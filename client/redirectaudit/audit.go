// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package redirectaudit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ory/hydra/v2/fosite"
)

// Report and pair statuses.
type (
	// ReportStatus describes whether the whole scan finished.
	ReportStatus string

	// PairStatus describes the verdict for one client pair.
	PairStatus string
)

const (
	// ReportComplete means every pair in the sealed snapshot was decided.
	ReportComplete ReportStatus = "complete"
	// ReportIncomplete means a budget was exhausted. The report must never
	// be interpreted as proving the absence of overlaps.
	ReportIncomplete ReportStatus = "incomplete"

	// PairStatusOverlap means a non-empty witness URI exists that both
	// clients' real matchers accept.
	PairStatusOverlap PairStatus = "overlap"
	// PairStatusUnsupported means the pair could not be decided under the
	// modeled rule set, typically because the deployed matcher behaved
	// outside the model. No overlap is claimed or denied.
	PairStatusUnsupported PairStatus = "unsupported"
)

// SecurityNote is attached to every report. An overlap is a configuration
// observation, not a vulnerability claim.
const SecurityNote = "An overlap means two distinct clients accept at least one common non-empty redirect_uri under the current fosite redirect matching rules. It is a configuration observation only, not a determination that an OAuth 2.0 vulnerability exists: exploitability depends on client authentication, enabled grant types, consent and PKCE policy, network exposure and other deployment controls. Clients relying on the empty redirect_uri single-registration fallback are listed separately and never imply a non-empty URI intersection."

// RegistrationSource identifies the exact registered entry of a client that
// makes an overlap possible.
type RegistrationSource struct {
	ClientID      string `json:"client_id"`
	EntryIndex    int    `json:"entry_index"`
	RegisteredURI string `json:"registered_uri"`
	Rule          string `json:"rule"`
}

// OverlapPair is one deterministically ordered client pair.
type OverlapPair struct {
	ClientA string `json:"client_a"`
	ClientB string `json:"client_b"`

	Status PairStatus `json:"status"`

	// WitnessURI is a non-empty URI accepted by both clients' real
	// matchers. Empty when status is unsupported.
	WitnessURI string `json:"witness_uri,omitempty"`

	// WitnessVerifiedByMatcher is true only after the witness has been
	// re-checked against fosite.MatchRedirectURIWithClientRedirectURIs for
	// both clients.
	WitnessVerifiedByMatcher bool `json:"witness_verified_by_matcher"`

	// Sources records every registered entry of either client that grants
	// a rule covering the witness.
	Sources []RegistrationSource `json:"sources"`

	// Reason is set for unsupported pairs and explains why no verdict is
	// given.
	Reason string `json:"reason,omitempty"`
}

// EmptyParameterFallback documents a client that accepts an empty
// redirect_uri request parameter thanks to its single valid registered URI.
type EmptyParameterFallback struct {
	ClientID      string `json:"client_id"`
	EntryIndex    int    `json:"entry_index"`
	RegisteredURI string `json:"registered_uri"`
}

// InertRegistration is a registered entry that provably accepts no URI under
// the modeled rule set.
type InertRegistration struct {
	ClientID      string `json:"client_id"`
	EntryIndex    int    `json:"entry_index"`
	RegisteredURI string `json:"registered_uri"`
	Reason        string `json:"reason"`
}

// AuditStats carries counters that make truncation and coverage explicit.
type AuditStats struct {
	ClientsAnalyzed       int  `json:"clients_analyzed"`
	TotalClientPairs      int  `json:"total_client_pairs"`
	ComparisonsUsed       int  `json:"comparisons_used"`
	ExactDomainBuckets    int  `json:"exact_domain_buckets"`
	LoopbackDomainBuckets int  `json:"loopback_domain_buckets"`
	MaxComparisons        int  `json:"max_comparisons,omitempty"`
	MaxFindings           int  `json:"max_findings,omitempty"`
	PairsTruncated        bool `json:"pairs_truncated"`
}

// Report is the sealed audit result.
//
// swagger:model clientRedirectOverlapAuditReport
type Report struct {
	RuleSet                 string                   `json:"rule_set"`
	NetworkID               string                   `json:"network_id"`
	SnapshotDigest          string                   `json:"snapshot_digest"`
	SnapshotClientCount     int                      `json:"snapshot_client_count"`
	GeneratedAt             time.Time                `json:"generated_at"`
	Status                  ReportStatus             `json:"status"`
	Overlaps                []OverlapPair            `json:"overlaps"`
	EmptyParameterFallbacks []EmptyParameterFallback `json:"empty_parameter_fallbacks"`
	InertRegistrations      []InertRegistration      `json:"inert_registrations"`
	Stats                   AuditStats               `json:"stats"`
	SecurityNote            string                   `json:"security_note"`
}

// Options bound the audit work. Zero values mean unlimited, except where
// noted.
type Options struct {
	// MaxComparisons limits the number of distinct client pairs that are
	// decided. Exhausting it yields an incomplete report.
	MaxComparisons int

	// MaxFindings limits the number of overlap/unsupported pair entries
	// emitted. Exhausting it yields an incomplete report.
	MaxFindings int
}

// redirectOracle decides acceptance using the deployed redirect matcher.
type redirectOracle interface {
	accepts(rawURI string, c SnapshotClient) bool
}

// fositeOracle is the production oracle: the real fosite matcher, no
// reimplementation or normalization.
type fositeOracle struct{}

func (fositeOracle) accepts(rawURI string, c SnapshotClient) bool {
	_, err := fosite.MatchRedirectURIWithClientRedirectURIs(rawURI, &fosite.DefaultClient{
		ID:           c.ID,
		RedirectURIs: c.RedirectURIs,
	})
	return err == nil
}

// Auditor runs ClientRedirectOverlapAudit against sealed snapshots.
type Auditor struct {
	modeler acceptanceModeler
	oracle  redirectOracle
	now     func() time.Time
}

// NewAuditor returns an Auditor backed by the real fosite matcher.
func NewAuditor() *Auditor {
	return &Auditor{
		modeler: fositeModeler{},
		oracle:  fositeOracle{},
		now:     time.Now,
	}
}

type pairKey struct{ a, b string }

func makePairKey(x, y string) pairKey {
	if x < y {
		return pairKey{x, y}
	}
	return pairKey{y, x}
}

type guardMismatch struct {
	clientID string
	probe    string
	reason   string
}

type auditIndexes struct {
	exact map[string]map[string][]registrationRule
	loop  map[loopbackKey]map[string][]registrationRule
}

// Run analyzes the sealed snapshot. It never mutates the snapshot or any
// registration data and returns an error instead of analyzing input whose
// integrity or rule-set binding cannot be established.
func (a *Auditor) Run(ctx context.Context, snap *SealedSnapshot, opts Options) (*Report, error) {
	if snap == nil {
		return nil, fmt.Errorf("redirect overlap audit: sealed snapshot is required")
	}
	if err := snap.VerifyDigest(); err != nil {
		return nil, fmt.Errorf("redirect overlap audit: %w", err)
	}
	if snap.RuleSet() != RuleSetVersion {
		return nil, fmt.Errorf("redirect overlap audit: snapshot sealed under rule set %q, auditor implements %q; reseal the snapshot", snap.RuleSet(), RuleSetVersion)
	}

	clients := snap.Clients()
	models := make(map[string]clientModel, len(clients))
	for _, c := range clients {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		models[c.ID] = a.modeler.modelClient(c)
	}

	// Empirical guard: every modeled prediction is checked against the real
	// matcher. Any disagreement means the deployed matcher behaves outside
	// the modeled rule set, and affected pairs are reported Unsupported
	// instead of being guessed.
	mismatches := a.runGuard(clients, models)
	unsupported := make(map[string][]guardMismatch)
	for _, mm := range mismatches {
		unsupported[mm.clientID] = append(unsupported[mm.clientID], mm)
	}

	idx := buildIndexes(models)
	pairRules, unsupportedPairs := collectPairs(clients, idx, unsupported)

	clientByID := make(map[string]SnapshotClient, len(clients))
	for _, c := range clients {
		clientByID[c.ID] = c
	}

	report := &Report{
		RuleSet:             snap.RuleSet(),
		NetworkID:           snap.NetworkID(),
		SnapshotDigest:      snap.Digest(),
		SnapshotClientCount: snap.ClientCount(),
		GeneratedAt:         a.now().UTC(),
		Status:              ReportComplete,
		Overlaps:            []OverlapPair{},
		InertRegistrations:  []InertRegistration{},
		SecurityNote:        SecurityNote,
		Stats: AuditStats{
			ClientsAnalyzed:       len(clients),
			TotalClientPairs:      len(clients) * (len(clients) - 1) / 2,
			ExactDomainBuckets:    len(idx.exact),
			LoopbackDomainBuckets: len(idx.loop),
			MaxComparisons:        opts.MaxComparisons,
			MaxFindings:           opts.MaxFindings,
		},
	}

	// Deterministic processing order.
	sortedPairs := make([]pairKey, 0, len(pairRules)+len(unsupportedPairs))
	seen := make(map[pairKey]struct{})
	for k := range pairRules {
		sortedPairs = append(sortedPairs, k)
		seen[k] = struct{}{}
	}
	for k := range unsupportedPairs {
		if _, ok := seen[k]; !ok {
			sortedPairs = append(sortedPairs, k)
		}
	}
	sort.Slice(sortedPairs, func(i, j int) bool {
		if sortedPairs[i].a != sortedPairs[j].a {
			return sortedPairs[i].a < sortedPairs[j].a
		}
		return sortedPairs[i].b < sortedPairs[j].b
	})

	for _, pk := range sortedPairs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if opts.MaxComparisons > 0 && report.Stats.ComparisonsUsed >= opts.MaxComparisons {
			report.Stats.PairsTruncated = true
			break
		}
		if opts.MaxFindings > 0 && len(report.Overlaps) >= opts.MaxFindings {
			report.Stats.PairsTruncated = true
			break
		}
		report.Stats.ComparisonsUsed++

		if reasons := unsupportedReasons(pk, unsupported); len(reasons) > 0 {
			report.Overlaps = append(report.Overlaps, OverlapPair{
				ClientA: pk.a,
				ClientB: pk.b,
				Status:  PairStatusUnsupported,
				Reason:  strings.Join(reasons, "; "),
			})
			continue
		}

		rules := pairRules[pk]
		witness, sources, ok := a.decideOverlap(pk, idx, rules, clientByID)
		if !ok {
			// Model predicted an intersection but the deployed matcher
			// rejected the witness: degrade to Unsupported.
			report.Overlaps = append(report.Overlaps, OverlapPair{
				ClientA: pk.a,
				ClientB: pk.b,
				Status:  PairStatusUnsupported,
				Reason:  "model predicted an overlap but no witness was accepted by the deployed matcher",
			})
			continue
		}

		report.Overlaps = append(report.Overlaps, OverlapPair{
			ClientA:                  pk.a,
			ClientB:                  pk.b,
			Status:                   PairStatusOverlap,
			WitnessURI:               witness,
			WitnessVerifiedByMatcher: true,
			Sources:                  sources,
		})
	}

	if report.Stats.PairsTruncated {
		report.Status = ReportIncomplete
	}

	// Empty-parameter fallbacks and inert entries are reported separately and
	// deterministically.
	for _, c := range clients {
		m := models[c.ID]
		if m.fallback != nil {
			report.EmptyParameterFallbacks = append(report.EmptyParameterFallbacks, EmptyParameterFallback{
				ClientID:      m.fallback.clientID,
				EntryIndex:    m.fallback.entryIndex,
				RegisteredURI: m.fallback.registeredURI,
			})
		}
		for _, e := range m.inert {
			report.InertRegistrations = append(report.InertRegistrations, InertRegistration{
				ClientID:      e.clientID,
				EntryIndex:    e.entryIndex,
				RegisteredURI: e.registered,
				Reason:        e.reason,
			})
		}
	}
	sort.Slice(report.EmptyParameterFallbacks, func(i, j int) bool {
		return report.EmptyParameterFallbacks[i].ClientID < report.EmptyParameterFallbacks[j].ClientID
	})
	sort.Slice(report.InertRegistrations, func(i, j int) bool {
		if report.InertRegistrations[i].ClientID != report.InertRegistrations[j].ClientID {
			return report.InertRegistrations[i].ClientID < report.InertRegistrations[j].ClientID
		}
		return report.InertRegistrations[i].EntryIndex < report.InertRegistrations[j].EntryIndex
	})

	return report, nil
}

// runGuard probes the real matcher for every modeled prediction.
func (a *Auditor) runGuard(clients []SnapshotClient, models map[string]clientModel) []guardMismatch {
	var mismatches []guardMismatch

	for _, c := range clients {
		m := models[c.ID]

		// Positive probes: exact entries and one canonical URI per loopback
		// domain must be accepted.
		exactProbes := make(map[string]struct{})
		loopProbes := make(map[loopbackKey]struct{})
		for _, r := range m.rules {
			switch r.kind {
			case kindExact:
				exactProbes[r.registered] = struct{}{}
			case kindLoopback:
				loopProbes[r.loop] = struct{}{}
			}
		}
		for raw := range exactProbes {
			if !a.oracle.accepts(raw, c) {
				mismatches = append(mismatches, guardMismatch{
					clientID: c.ID, probe: raw,
					reason: "modeled exact-string rule was rejected by the deployed matcher",
				})
			}
		}
		for key := range loopProbes {
			witness := key.canonicalURI()
			if !a.oracle.accepts(witness, c) {
				mismatches = append(mismatches, guardMismatch{
					clientID: c.ID, probe: witness,
					reason: "modeled rfc8252-loopback rule was rejected by the deployed matcher",
				})
			}

			// Negative probes: changing the path or the raw query must be
			// rejected under the modeled rules. If the deployed matcher
			// accepts them, its rule set is wider than the model.
			negPath := loopbackKey{hostname: key.hostname, path: key.path + "/__hydra_redirect_audit_guard__", rawQuery: key.rawQuery}.canonicalURI()
			if a.oracle.accepts(negPath, c) {
				mismatches = append(mismatches, guardMismatch{
					clientID: c.ID, probe: negPath,
					reason: "matcher accepted a loopback path the model predicts as rejected",
				})
			}
			negQueryKey := loopbackKey{
				hostname: key.hostname,
				path:     key.path,
				rawQuery: withGuardQuery(key.rawQuery),
			}
			if a.oracle.accepts(negQueryKey.canonicalURI(), c) {
				mismatches = append(mismatches, guardMismatch{
					clientID: c.ID, probe: negQueryKey.canonicalURI(),
					reason: "matcher accepted a loopback query the model predicts as rejected",
				})
			}
		}

		// Inert entries must be rejected when presented verbatim.
		for _, e := range m.inert {
			if e.registered == "" {
				continue
			}
			if a.oracle.accepts(e.registered, c) {
				mismatches = append(mismatches, guardMismatch{
					clientID: c.ID, probe: e.registered,
					reason: "matcher accepted a registration entry the model classifies as inert",
				})
			}
		}

		// Empty-parameter fallback prediction.
		expectedFallback := m.fallback != nil
		if a.oracle.accepts("", c) != expectedFallback {
			mismatches = append(mismatches, guardMismatch{
				clientID: c.ID, probe: "",
				reason: "empty redirect_uri fallback behavior diverges from the modeled rule set",
			})
		}
	}

	sort.Slice(mismatches, func(i, j int) bool {
		if mismatches[i].clientID != mismatches[j].clientID {
			return mismatches[i].clientID < mismatches[j].clientID
		}
		return mismatches[i].probe < mismatches[j].probe
	})
	return mismatches
}

func withGuardQuery(raw string) string {
	if raw == "" {
		return "__hydra_redirect_audit_guard__=1"
	}
	return raw + "&__hydra_redirect_audit_guard__=1"
}

// buildIndexes partitions rules into provably disjoint matching domains so
// only clients sharing a domain are ever compared.
func buildIndexes(models map[string]clientModel) auditIndexes {
	idx := auditIndexes{
		exact: make(map[string]map[string][]registrationRule),
		loop:  make(map[loopbackKey]map[string][]registrationRule),
	}
	addRule := func(bucket map[string]map[string][]registrationRule, key string, r registrationRule) {
		if bucket[key] == nil {
			bucket[key] = make(map[string][]registrationRule)
		}
		bucket[key][r.clientID] = append(bucket[key][r.clientID], r)
	}
	addLoop := func(key loopbackKey, r registrationRule) {
		if idx.loop[key] == nil {
			idx.loop[key] = make(map[string][]registrationRule)
		}
		idx.loop[key][r.clientID] = append(idx.loop[key][r.clientID], r)
	}

	for _, m := range models {
		for _, r := range m.rules {
			switch r.kind {
			case kindExact:
				addRule(idx.exact, r.registered, r)
				if key, ok := isLoopbackExact(r.registered); ok {
					// A valid http loopback exact URI is itself covered by
					// the loopback rule of any client sharing the domain.
					addLoop(key, r)
				}
			case kindLoopback:
				addLoop(r.loop, r)
			}
		}
	}
	return idx
}

// collectPairs returns, for every pair sharing a matching domain, the rules
// involved, and the set of pairs that cannot be decided because a client is
// in an unsupported state.
func collectPairs(clients []SnapshotClient, idx auditIndexes, unsupported map[string][]guardMismatch) (map[pairKey][]registrationRule, map[pairKey]struct{}) {
	pairRules := make(map[pairKey][]registrationRule)
	dedup := make(map[pairKey]map[string]struct{})

	addPair := func(x, y string, rules ...registrationRule) {
		pk := makePairKey(x, y)
		if dedup[pk] == nil {
			dedup[pk] = make(map[string]struct{})
		}
		for _, r := range rules {
			key := fmt.Sprintf("%s|%d|%s", r.clientID, r.entryIndex, r.kind)
			if _, ok := dedup[pk][key]; ok {
				continue
			}
			dedup[pk][key] = struct{}{}
			pairRules[pk] = append(pairRules[pk], r)
		}
	}

	combine := func(clientRules map[string][]registrationRule) {
		ids := make([]string, 0, len(clientRules))
		for id := range clientRules {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for i := 0; i < len(ids); i++ {
			for j := i + 1; j < len(ids); j++ {
				addPair(ids[i], ids[j], append(clientRules[ids[i]], clientRules[ids[j]]...)...)
			}
		}
	}

	for _, bucket := range idx.exact {
		combine(bucket)
	}
	for _, bucket := range idx.loop {
		combine(bucket)
	}

	unsupportedPairs := make(map[pairKey]struct{})
	if len(unsupported) > 0 {
		badIDs := make([]string, 0, len(unsupported))
		for id := range unsupported {
			badIDs = append(badIDs, id)
		}
		sort.Strings(badIDs)
		allIDs := make([]string, 0, len(clients))
		for _, c := range clients {
			allIDs = append(allIDs, c.ID)
		}
		sort.Strings(allIDs)
		for _, bad := range badIDs {
			for _, other := range allIDs {
				if other == bad {
					continue
				}
				unsupportedPairs[makePairKey(bad, other)] = struct{}{}
			}
		}
	}
	return pairRules, unsupportedPairs
}

func unsupportedReasons(pk pairKey, unsupported map[string][]guardMismatch) []string {
	var reasons []string
	for _, id := range []string{pk.a, pk.b} {
		for _, mm := range unsupported[id] {
			reasons = append(reasons, fmt.Sprintf("client %q: %s (probe %q)", mm.clientID, mm.reason, mm.probe))
		}
	}
	sort.Strings(reasons)
	return reasons
}

// decideOverlap selects a deterministic witness and verifies it against the
// real matcher for both clients. It returns ok=false when verification
// fails, which the caller treats as Unsupported.
func (a *Auditor) decideOverlap(
	pk pairKey,
	idx auditIndexes,
	rules []registrationRule,
	clientByID map[string]SnapshotClient,
) (string, []RegistrationSource, bool) {
	// Prefer an exact-string witness shared by both clients, then a loopback
	// canonical witness. Within each kind, choose the lexicographically
	// smallest candidate for deterministic output.
	var exactCandidates []string
	for raw, bucket := range idx.exact {
		if _, ok1 := bucket[pk.a]; ok1 {
			if _, ok2 := bucket[pk.b]; ok2 {
				exactCandidates = append(exactCandidates, raw)
			}
		}
	}
	var loopCandidates []loopbackKey
	for key, bucket := range idx.loop {
		if _, ok1 := bucket[pk.a]; ok1 {
			if _, ok2 := bucket[pk.b]; ok2 {
				loopCandidates = append(loopCandidates, key)
			}
		}
	}

	var witness string
	switch {
	case len(exactCandidates) > 0:
		sort.Strings(exactCandidates)
		witness = exactCandidates[0]
	case len(loopCandidates) > 0:
		sort.Slice(loopCandidates, func(i, j int) bool {
			return loopCandidates[i].String() < loopCandidates[j].String()
		})
		witness = loopCandidates[0].canonicalURI()
	default:
		return "", nil, false
	}

	if !a.oracle.accepts(witness, clientByID[pk.a]) || !a.oracle.accepts(witness, clientByID[pk.b]) {
		return "", nil, false
	}

	sources := make([]RegistrationSource, 0, len(rules))
	for _, r := range rules {
		if r.clientID != pk.a && r.clientID != pk.b {
			continue
		}
		sources = append(sources, r.source())
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].ClientID != sources[j].ClientID {
			return sources[i].ClientID < sources[j].ClientID
		}
		if sources[i].EntryIndex != sources[j].EntryIndex {
			return sources[i].EntryIndex < sources[j].EntryIndex
		}
		if sources[i].Rule != sources[j].Rule {
			return sources[i].Rule < sources[j].Rule
		}
		return sources[i].RegisteredURI < sources[j].RegisteredURI
	})
	sources = dedupeSources(sources)
	return witness, sources, true
}

func dedupeSources(in []RegistrationSource) []RegistrationSource {
	if len(in) <= 1 {
		return in
	}
	out := in[:1]
	for i := 1; i < len(in); i++ {
		last := out[len(out)-1]
		if last == in[i] {
			continue
		}
		out = append(out, in[i])
	}
	return out
}
