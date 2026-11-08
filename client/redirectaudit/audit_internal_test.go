// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package redirectaudit

import (
	"context"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/fosite"
)

func mustSeal(t *testing.T, clients ...SnapshotClient) *SealedSnapshot {
	t.Helper()
	snap, err := SealSnapshot("network-under-test", time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC), clients)
	require.NoError(t, err)
	require.NoError(t, snap.VerifyDigest())
	return snap
}

// findPair returns the reported pair for (a, b), regardless of slice order.
func findPair(t *testing.T, rep *Report, a, b string) OverlapPair {
	t.Helper()
	pk := makePairKey(a, b)
	for _, p := range rep.Overlaps {
		if p.ClientA == pk.a && p.ClientB == pk.b {
			return p
		}
	}
	t.Fatalf("pair %v not found in report: %+v", pk, rep.Overlaps)
	return OverlapPair{}
}

func assertNoPair(t *testing.T, rep *Report, a, b string) {
	t.Helper()
	pk := makePairKey(a, b)
	for _, p := range rep.Overlaps {
		if p.ClientA == pk.a && p.ClientB == pk.b {
			t.Fatalf("unexpected pair %v in report: %+v", pk, p)
		}
	}
}

// assertWitnessAcceptedByRealMatcher re-runs the real fosite matcher for
// every reported witness on both clients.
func assertWitnessAcceptedByRealMatcher(t *testing.T, snap *SealedSnapshot, rep *Report) {
	t.Helper()
	byID := map[string]SnapshotClient{}
	for _, c := range snap.Clients() {
		byID[c.ID] = c
	}
	for _, p := range rep.Overlaps {
		if p.Status != PairStatusOverlap {
			continue
		}
		require.NotEmpty(t, p.WitnessURI, "overlap pair %s/%s must carry a non-empty witness", p.ClientA, p.ClientB)
		for _, id := range []string{p.ClientA, p.ClientB} {
			_, err := fosite.MatchRedirectURIWithClientRedirectURIs(p.WitnessURI, &fosite.DefaultClient{
				ID: id, RedirectURIs: byID[id].RedirectURIs,
			})
			require.NoError(t, err, "witness %q must be accepted by real matcher for client %q", p.WitnessURI, id)
		}
		assert.True(t, p.WitnessVerifiedByMatcher)
	}
}

// TestCounterexamples covers the exact regression set demanded for the
// audit: port-only differences, IPv6 literals, duplicates, query order and
// case/percent-encoding sensitivity.
func TestCounterexamples(t *testing.T) {
	t.Run("loopback port-only difference overlaps and witness is verified", func(t *testing.T) {
		snap := mustSeal(t,
			SnapshotClient{ID: "a", RedirectURIs: []string{"http://127.0.0.1:8080/cb"}},
			SnapshotClient{ID: "b", RedirectURIs: []string{"http://127.0.0.1:9090/cb"}},
		)
		rep, err := NewAuditor().Run(context.Background(), snap, Options{})
		require.NoError(t, err)
		require.Equal(t, ReportComplete, rep.Status)
		require.Len(t, rep.Overlaps, 1)

		pair := rep.Overlaps[0]
		assert.Equal(t, PairStatusOverlap, pair.Status)
		assert.Equal(t, "a", pair.ClientA)
		assert.Equal(t, "b", pair.ClientB)
		// No-port canonical witness: accepted under the RFC 8252 port rule.
		assert.Equal(t, "http://127.0.0.1/cb", pair.WitnessURI)
		assertWitnessAcceptedByRealMatcher(t, snap, rep)

		rules := map[string][]string{}
		for _, s := range pair.Sources {
			rules[s.ClientID] = append(rules[s.ClientID], s.Rule)
		}
		// Valid http loopback registrations carry both an exact-string rule
		// and the RFC 8252 loopback rule; the overlap itself is proven by the
		// port-ignoring loopback rule.
		assert.ElementsMatch(t, []string{RuleExactString, RuleLoopback}, rules["a"])
		assert.ElementsMatch(t, []string{RuleExactString, RuleLoopback}, rules["b"])
	})

	t.Run("non-loopback port-only difference does not overlap", func(t *testing.T) {
		snap := mustSeal(t,
			SnapshotClient{ID: "a", RedirectURIs: []string{"https://app.example.com:8080/cb"}},
			SnapshotClient{ID: "b", RedirectURIs: []string{"https://app.example.com:9090/cb"}},
		)
		rep, err := NewAuditor().Run(context.Background(), snap, Options{})
		require.NoError(t, err)
		assert.Empty(t, rep.Overlaps)
	})

	t.Run("IPv6 literal forms are distinct matching domains", func(t *testing.T) {
		snap := mustSeal(t,
			SnapshotClient{ID: "v6-short", RedirectURIs: []string{"http://[::1]/cb"}},
			SnapshotClient{ID: "v6-long", RedirectURIs: []string{"http://[0:0:0:0:0:0:0:1]/cb"}},
			SnapshotClient{ID: "v6-short-2", RedirectURIs: []string{"http://[::1]:9999/cb"}},
		)
		rep, err := NewAuditor().Run(context.Background(), snap, Options{})
		require.NoError(t, err)

		// Same literal, different ports overlap through the loopback rule.
		p := findPair(t, rep, "v6-short", "v6-short-2")
		assert.Equal(t, PairStatusOverlap, p.Status)
		assert.Equal(t, "http://[::1]/cb", p.WitnessURI)
		// The two textual IPv6 forms parse to the same IP but never match
		// under the real string-based hostname comparison.
		assertNoPair(t, rep, "v6-short", "v6-long")
		assertNoPair(t, rep, "v6-short-2", "v6-long")
		assertWitnessAcceptedByRealMatcher(t, snap, rep)
	})

	t.Run("duplicate registered entries are deduplicated", func(t *testing.T) {
		snap := mustSeal(t,
			SnapshotClient{ID: "a", RedirectURIs: []string{
				"http://127.0.0.1/cb", "http://127.0.0.1/cb", "http://127.0.0.1/cb",
			}},
			SnapshotClient{ID: "b", RedirectURIs: []string{"http://127.0.0.1/cb"}},
		)
		rep, err := NewAuditor().Run(context.Background(), snap, Options{})
		require.NoError(t, err)
		require.Len(t, rep.Overlaps, 1)
		pair := rep.Overlaps[0]
		assert.Equal(t, "http://127.0.0.1/cb", pair.WitnessURI)

		// Sources preserve every registration index, but the same rule of
		// the same entry (exact rule also lands in the loopback bucket) is
		// reported only once.
		tuples := map[string]struct{}{}
		clientIndexCount := map[string]int{}
		for _, s := range pair.Sources {
			tuples[s.ClientID+"|"+s.Rule+"|"+string(rune('0'+s.EntryIndex))] = struct{}{}
			clientIndexCount[s.ClientID] = max(clientIndexCount[s.ClientID], s.EntryIndex+1)
		}
		require.Len(t, tuples, 8, "3+1 entries each with exact and loopback rules")
		assert.Equal(t, 3, clientIndexCount["a"])
		assert.Equal(t, 1, clientIndexCount["b"])
		assertWitnessAcceptedByRealMatcher(t, snap, rep)
	})

	t.Run("query order is not equivalent", func(t *testing.T) {
		snap := mustSeal(t,
			SnapshotClient{ID: "a", RedirectURIs: []string{"http://127.0.0.1:8080/cb?a=1&b=2"}},
			SnapshotClient{ID: "b", RedirectURIs: []string{"http://127.0.0.1:8080/cb?b=2&a=1"}},
		)
		rep, err := NewAuditor().Run(context.Background(), snap, Options{})
		require.NoError(t, err)
		assert.Empty(t, rep.Overlaps, "RawQuery string comparison must distinguish query order")
	})

	t.Run("case differences are not equivalent", func(t *testing.T) {
		snap := mustSeal(t,
			SnapshotClient{ID: "a", RedirectURIs: []string{"https://Example.com/Path"}},
			SnapshotClient{ID: "b", RedirectURIs: []string{"https://example.com/path"}},
			SnapshotClient{ID: "c", RedirectURIs: []string{"http://127.0.0.1/Cb"}},
			SnapshotClient{ID: "d", RedirectURIs: []string{"http://127.0.0.1/cb"}},
		)
		rep, err := NewAuditor().Run(context.Background(), snap, Options{})
		require.NoError(t, err)
		assertNoPair(t, rep, "a", "b")
		assertNoPair(t, rep, "c", "d")
	})

	t.Run("percent encoding is not normalized", func(t *testing.T) {
		snap := mustSeal(t,
			SnapshotClient{ID: "a", RedirectURIs: []string{"https://google.com/?foo=bar%20foo+baz"}},
			SnapshotClient{ID: "b", RedirectURIs: []string{"https://google.com/?foo=bar%20foo%2Bbaz"}},
			SnapshotClient{ID: "c", RedirectURIs: []string{"https://google.com/?foo=bar%20foo+baz"}},
		)
		rep, err := NewAuditor().Run(context.Background(), snap, Options{})
		require.NoError(t, err)
		assertNoPair(t, rep, "a", "b")
		p := findPair(t, rep, "a", "c")
		assert.Equal(t, PairStatusOverlap, p.Status)
		assert.Equal(t, "https://google.com/?foo=bar%20foo+baz", p.WitnessURI)
		assertWitnessAcceptedByRealMatcher(t, snap, rep)
	})

	t.Run("localhost, loopback IPs and custom schemes stay separate domains", func(t *testing.T) {
		snap := mustSeal(t,
			SnapshotClient{ID: "localhost", RedirectURIs: []string{"http://localhost:8080/cb"}},
			SnapshotClient{ID: "ipv4", RedirectURIs: []string{"http://127.0.0.1:8080/cb"}},
			SnapshotClient{ID: "custom", RedirectURIs: []string{"myapp://localhost:8080/cb"}},
			SnapshotClient{ID: "custom-loop", RedirectURIs: []string{"myapp://127.0.0.1/cb"}},
		)
		rep, err := NewAuditor().Run(context.Background(), snap, Options{})
		require.NoError(t, err)
		assertNoPair(t, rep, "localhost", "ipv4")
		assertNoPair(t, rep, "localhost", "custom")
		assertNoPair(t, rep, "ipv4", "custom")

		// Real-matcher quirk, modeled faithfully: a registered custom scheme
		// over a loopback IP literal still opens the http loopback family.
		p := findPair(t, rep, "ipv4", "custom-loop")
		assert.Equal(t, PairStatusOverlap, p.Status)
		assert.Equal(t, "http://127.0.0.1/cb", p.WitnessURI)
		assertWitnessAcceptedByRealMatcher(t, snap, rep)
	})

	t.Run("fragment registration keeps its loopback family but loses exact matching", func(t *testing.T) {
		snap := mustSeal(t,
			SnapshotClient{ID: "frag", RedirectURIs: []string{"http://127.0.0.1/cb#frag"}},
			SnapshotClient{ID: "clean", RedirectURIs: []string{"http://127.0.0.1:1234/cb"}},
		)
		rep, err := NewAuditor().Run(context.Background(), snap, Options{})
		require.NoError(t, err)
		p := findPair(t, rep, "frag", "clean")
		assert.Equal(t, PairStatusOverlap, p.Status)
		assertWitnessAcceptedByRealMatcher(t, snap, rep)

		// The fragment entry itself must be classified as non-exact.
		for _, s := range p.Sources {
			if s.ClientID == "frag" {
				assert.Equal(t, RuleLoopback, s.Rule)
			}
		}
		require.Len(t, rep.InertRegistrations, 0)
	})
}

// TestEmptyParameterFallbackReportedSeparately ensures the single-registered
// empty-redirect fallback never fabricates a non-empty intersection.
func TestEmptyParameterFallbackReportedSeparately(t *testing.T) {
	snap := mustSeal(t,
		SnapshotClient{ID: "one", RedirectURIs: []string{"https://a.example/cb"}},
		SnapshotClient{ID: "two", RedirectURIs: []string{"https://b.example/cb"}},
		SnapshotClient{ID: "multi", RedirectURIs: []string{"https://c.example/1", "https://c.example/2"}},
	)
	rep, err := NewAuditor().Run(context.Background(), snap, Options{})
	require.NoError(t, err)

	assert.Empty(t, rep.Overlaps, "different single URIs must not be turned into an overlap")
	require.Len(t, rep.EmptyParameterFallbacks, 2)
	assert.Equal(t, "one", rep.EmptyParameterFallbacks[0].ClientID)
	assert.Equal(t, "two", rep.EmptyParameterFallbacks[1].ClientID)

	// And the fallback really is accepted by the matcher for empty input.
	for _, fb := range rep.EmptyParameterFallbacks {
		_, err := fosite.MatchRedirectURIWithClientRedirectURIs("", &fosite.DefaultClient{
			RedirectURIs: []string{fb.RegisteredURI},
		})
		require.NoError(t, err)
	}
}

// TestInertRegistrations covers unparseable and otherwise dead entries.
func TestInertRegistrations(t *testing.T) {
	snap := mustSeal(t,
		SnapshotClient{ID: "dead", RedirectURIs: []string{":/not-a-url", "https://h.example/cb#fragment"}},
		SnapshotClient{ID: "alive", RedirectURIs: []string{"https://h.example/ok"}},
	)
	rep, err := NewAuditor().Run(context.Background(), snap, Options{})
	require.NoError(t, err)
	assert.Empty(t, rep.Overlaps)
	require.Len(t, rep.InertRegistrations, 2)
	reasons := map[string]string{}
	for _, in := range rep.InertRegistrations {
		reasons[in.RegisteredURI] = in.Reason
	}
	assert.Equal(t, inertUnparseable, reasons[":/not-a-url"])
	assert.Equal(t, inertInvalid, reasons["https://h.example/cb#fragment"])
}

// TestBudgetIncomplete verifies that exhausted budgets produce Incomplete
// instead of silently truncating and claiming no overlap.
func TestBudgetIncomplete(t *testing.T) {
	clients := []SnapshotClient{
		{ID: "shared", RedirectURIs: []string{"https://shared.example/cb"}},
	}
	for i := 0; i < 5; i++ {
		clients = append(clients, SnapshotClient{
			ID:           "c" + string(rune('0'+i)),
			RedirectURIs: []string{"https://shared.example/cb"},
		})
	}
	snap := mustSeal(t, clients...)

	rep, err := NewAuditor().Run(context.Background(), snap, Options{MaxComparisons: 2})
	require.NoError(t, err)
	assert.Equal(t, ReportIncomplete, rep.Status)
	assert.True(t, rep.Stats.PairsTruncated)
	assert.Equal(t, 2, rep.Stats.ComparisonsUsed)
	assert.LessOrEqual(t, len(rep.Overlaps), 2)

	// Unlimited run is complete and finds all C(6,2)=15 overlapping pairs.
	full, err := NewAuditor().Run(context.Background(), snap, Options{})
	require.NoError(t, err)
	assert.Equal(t, ReportComplete, full.Status)
	assert.Equal(t, 15, full.Stats.TotalClientPairs)
	assert.Len(t, full.Overlaps, 15)

	// Findings cap also truncates.
	capped, err := NewAuditor().Run(context.Background(), snap, Options{MaxFindings: 1})
	require.NoError(t, err)
	assert.Equal(t, ReportIncomplete, capped.Status)
	assert.Len(t, capped.Overlaps, 1)
}

// TestUnsupportedWhenModelDivergesFromMatcher injects a modeler whose
// predictions the real matcher cannot honor, and checks the audit degrades
// to Unsupported rather than inventing witnesses.
func TestUnsupportedWhenModelDivergesFromMatcher(t *testing.T) {
	snap := mustSeal(t,
		SnapshotClient{ID: "a", RedirectURIs: []string{"https://a.example/cb"}},
		SnapshotClient{ID: "b", RedirectURIs: []string{"https://b.example/cb"}},
	)
	auditor := NewAuditor()
	auditor.modeler = hallucinatingModeler{}

	rep, err := auditor.Run(context.Background(), snap, Options{})
	require.NoError(t, err)
	require.NotEmpty(t, rep.Overlaps)
	for _, p := range rep.Overlaps {
		assert.Equal(t, PairStatusUnsupported, p.Status)
		assert.Empty(t, p.WitnessURI)
		assert.NotEmpty(t, p.Reason)
	}
}

type hallucinatingModeler struct{}

func (hallucinatingModeler) modelClient(c SnapshotClient) clientModel {
	m := fositeModeler{}.modelClient(c)
	fake := loopbackKey{hostname: "127.0.0.1", path: "/this-domain-does-not-exist", rawQuery: ""}
	m.rules = append(m.rules, registrationRule{
		clientID: c.ID, entryIndex: len(c.RedirectURIs), registered: fake.canonicalURI(),
		kind: kindLoopback, loop: fake,
	})
	m.loopKeys = append(m.loopKeys, fake)
	return m
}

// TestSnapshotIntegrity ensures tampering is detected and analysis refuses
// to run on modified or cross-rule-set input.
func TestSnapshotIntegrity(t *testing.T) {
	snap := mustSeal(t,
		SnapshotClient{ID: "a", RedirectURIs: []string{"https://a.example/cb"}},
	)

	tampered := *snap
	tampered.clients[0].RedirectURIs = []string{"https://attacker.example/cb"}
	err := tampered.VerifyDigest()
	require.Error(t, err)

	_, err = NewAuditor().Run(context.Background(), &tampered, Options{})
	require.Error(t, err)

	wrongRuleSet := *snap
	wrongRuleSet.ruleSet = "future-matcher/v999"
	_, err = NewAuditor().Run(context.Background(), &wrongRuleSet, Options{})
	require.Error(t, err)

	_, err = SealSnapshot("n", time.Now(), []SnapshotClient{
		{ID: "x"}, {ID: "x"},
	})
	require.Error(t, err)
}

// TestDeterministicOrdering checks repeated runs produce identical ordering
// and witness selection.
func TestDeterministicOrdering(t *testing.T) {
	snap := mustSeal(t,
		SnapshotClient{ID: "zeta", RedirectURIs: []string{"https://shared.example/cb", "http://127.0.0.1/cb"}},
		SnapshotClient{ID: "alpha", RedirectURIs: []string{"https://shared.example/cb"}},
		SnapshotClient{ID: "mid", RedirectURIs: []string{"http://127.0.0.1:9/cb"}},
	)
	first, err := NewAuditor().Run(context.Background(), snap, Options{})
	require.NoError(t, err)
	second, err := NewAuditor().Run(context.Background(), snap, Options{})
	require.NoError(t, err)

	require.Equal(t, pairIDs(first), pairIDs(second))
	assert.Equal(t, "alpha", first.Overlaps[0].ClientA)
	for i := range first.Overlaps {
		assert.Equal(t, first.Overlaps[i], second.Overlaps[i])
	}
	assertWitnessAcceptedByRealMatcher(t, snap, first)
}

func pairIDs(rep *Report) [][2]string {
	out := make([][2]string, len(rep.Overlaps))
	for i, p := range rep.Overlaps {
		out[i] = [2]string{p.ClientA, p.ClientB}
	}
	return out
}

// TestExhaustiveReferenceComparison runs randomized small snapshots through
// both the bucketed engine and the brute-force reference and requires exact
// agreement on the set of overlapping pairs.
func TestExhaustiveReferenceComparison(t *testing.T) {
	templates := []string{
		"https://app.example.com/cb",
		"https://app.example.com/cb?x=1&y=2",
		"https://app.example.com/Cb",
		"https://other.example/path",
		"http://127.0.0.1/cb",
		"http://127.0.0.1:8080/cb",
		"http://127.0.0.1/cb?a=1&b=2",
		"http://127.0.0.1/cb?b=2&a=1",
		"http://127.0.0.1/Cb",
		"http://[::1]/cb",
		"http://[::1]:5000/cb?q=1",
		"http://[0:0:0:0:0:0:0:1]/cb",
		"http://localhost:8080/cb",
		"myapp://callback",
		"wta://auth",
		"myapp://127.0.0.1/cb",
		"https://google.com/?foo=bar%20foo+baz",
		"http://127.0.0.1/cb#frag",
		":/not-a-url",
	}

	for seed := int64(1); seed <= 25; seed++ {
		rng := rand.New(rand.NewSource(seed))
		n := 6 + rng.Intn(10)
		clients := make([]SnapshotClient, 0, n)
		for i := 0; i < n; i++ {
			k := 1 + rng.Intn(3)
			entries := make([]string, 0, k)
			for j := 0; j < k; j++ {
				entries = append(entries, templates[rng.Intn(len(templates))])
			}
			clients = append(clients, SnapshotClient{
				ID:           "client-" + padID(i),
				RedirectURIs: entries,
			})
		}

		snap, err := SealSnapshot("fuzz-network", time.Now(), clients)
		require.NoError(t, err, "seed %d", seed)

		report, err := NewAuditor().Run(context.Background(), snap, Options{})
		require.NoError(t, err, "seed %d", seed)
		require.Equal(t, ReportComplete, report.Status, "seed %d: unlimited budget must complete", seed)

		for _, p := range report.Overlaps {
			require.Equal(t, PairStatusOverlap, p.Status,
				"seed %d: real matcher must never disagree with the model: %s", seed, p.Reason)
		}
		assertWitnessAcceptedByRealMatcher(t, snap, report)

		reference, err := ExhaustiveReferenceOverlaps(snap)
		require.NoError(t, err, "seed %d", seed)

		enginePairs := map[pairKey]struct{}{}
		for _, p := range report.Overlaps {
			enginePairs[makePairKey(p.ClientA, p.ClientB)] = struct{}{}
		}
		referencePairs := map[pairKey]struct{}{}
		for pk := range reference {
			referencePairs[pk] = struct{}{}
		}
		assert.Equal(t, referencePairs, enginePairs, "seed %d: pair set mismatch", seed)

		// Every engine witness must be one of the reference witnesses.
		for _, p := range report.Overlaps {
			pk := makePairKey(p.ClientA, p.ClientB)
			witnesses := reference[pk]
			idx := sort.SearchStrings(witnesses, p.WitnessURI)
			require.True(t, idx < len(witnesses) && witnesses[idx] == p.WitnessURI,
				"seed %d: witness %q not in brute-force set %v", seed, p.WitnessURI, witnesses)
		}
	}
}

func padID(i int) string {
	if i < 10 {
		return "0" + string(rune('0'+i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

// TestNoSecretFieldsByConstruction documents the snapshot type's surface:
// it cannot carry secrets or tokens.
func TestNoSecretFieldsByConstruction(t *testing.T) {
	snap := mustSeal(t, SnapshotClient{ID: "a", RedirectURIs: []string{"https://a.example/cb"}})
	for _, c := range snap.Clients() {
		// Compile-time guarantee: only these two fields exist.
		assert.NotEmpty(t, c.ID)
		assert.NotNil(t, c.RedirectURIs)
	}
	assert.NotEmpty(t, snap.Digest())
	assert.Equal(t, "network-under-test", snap.NetworkID())
}
