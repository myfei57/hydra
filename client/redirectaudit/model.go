// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package redirectaudit

import (
	"net"
	"net/url"
	"strings"

	"github.com/ory/hydra/v2/fosite"
)

// Rule kinds recognized by the modeled matcher.
const (
	// RuleExactString is RFC 6749 §3.1.2.3 simple string comparison: the
	// requested redirect_uri must be byte-identical to a registered entry
	// that is itself a valid redirect URI. No case folding, percent-encoding
	// normalization, or query reordering is performed.
	RuleExactString = "exact-string"

	// RuleLoopback is RFC 8252 §7.3 loopback redirect matching as
	// implemented by fosite.isMatchingAsLoopback: the requested URI must use
	// the http scheme, its hostname must be an IP literal that
	// net.IP.IsLoopback accepts, the hostname literal, path and raw query
	// must equal the registered ones, and the port is ignored.
	RuleLoopback = "rfc8252-loopback"
)

// Inert registration entry reasons.
const (
	inertUnparseable = "registered-uri-unparseable"
	inertInvalid     = "registered-uri-invalid-without-loopback-rule"
	inertEmpty       = "registered-uri-empty"
)

// ruleKind is internal: JSON reports use the Rule* string constants.
type ruleKind string

const (
	kindExact    ruleKind = RuleExactString
	kindLoopback ruleKind = RuleLoopback
)

// loopbackKey is the provable matching domain of an RFC 8252 loopback rule.
// Two URIs can only be related through the loopback rule if they share the
// exact hostname literal (string equality, not parsed-IP equality), path and
// raw query. The free port component is deliberately not part of the key
// because the matcher ignores it.
type loopbackKey struct {
	hostname string
	path     string
	rawQuery string
}

// String renders the deterministic, colon-free textual key used in maps and
// diagnostics.
func (k loopbackKey) String() string {
	return "http|" + k.hostname + "|" + k.path + "|" + k.rawQuery
}

// canonicalURI builds one concrete, non-empty witness URI for the loopback
// domain by using no explicit port. Every produced witness is independently
// verified against the real matcher before being reported.
func (k loopbackKey) canonicalURI() string {
	host := k.hostname
	if strings.Contains(host, ":") {
		// IPv6 literals must be bracketed inside a URL host.
		host = "[" + host + "]"
	}
	u := &url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     k.path,
		RawQuery: k.rawQuery,
	}
	return u.String()
}

// registrationRule records which registered entry of which client grants a
// particular acceptance rule.
type registrationRule struct {
	clientID   string
	entryIndex int
	registered string
	kind       ruleKind
	loop       loopbackKey
}

// source renders the externally reported registration provenance.
func (r registrationRule) source() RegistrationSource {
	return RegistrationSource{
		ClientID:      r.clientID,
		EntryIndex:    r.entryIndex,
		RegisteredURI: r.registered,
		Rule:          string(r.kind),
	}
}

// inertEntry is a registered entry that provably contributes nothing to the
// client's non-empty acceptance set under the modeled rule set.
type inertEntry struct {
	clientID   string
	entryIndex int
	registered string
	reason     string
}

// emptyFallback documents a client for which an empty redirect_uri request
// parameter is accepted because exactly one valid URI is registered. It is
// reported separately and never turned into a fabricated non-empty overlap.
type emptyFallback struct {
	clientID      string
	entryIndex    int
	registeredURI string
}

// clientModel is the complete, rule-level description of one client's
// redirect_uri acceptance behavior.
type clientModel struct {
	id       string
	rules    []registrationRule
	loopKeys []loopbackKey
	inert    []inertEntry
	fallback *emptyFallback
}

// acceptanceModeler turns a sealed client into its rule model. The default
// implementation mirrors the current fosite matcher; tests may substitute a
// deliberately wrong modeler to exercise the empirical Unsupported guard.
type acceptanceModeler interface {
	modelClient(c SnapshotClient) clientModel
}

// fositeModeler is the production modeler, kept as a named type so the
// rule-set versioning is explicit.
type fositeModeler struct{}

func (fositeModeler) modelClient(c SnapshotClient) clientModel {
	m := clientModel{id: c.ID}

	for i, raw := range c.RedirectURIs {
		if raw == "" {
			m.inert = append(m.inert, inertEntry{
				clientID: c.ID, entryIndex: i, registered: raw, reason: inertEmpty,
			})
			continue
		}

		parsed, err := url.Parse(raw)
		if err != nil {
			m.inert = append(m.inert, inertEntry{
				clientID: c.ID, entryIndex: i, registered: raw, reason: inertUnparseable,
			})
			continue
		}

		// Exact-string rule only exists when the registered entry itself is
		// valid: MatchRedirectURIWithClientRedirectURIs re-validates the
		// matched registered string before accepting it.
		if fosite.IsValidRedirectURI(parsed) {
			m.rules = append(m.rules, registrationRule{
				clientID: c.ID, entryIndex: i, registered: raw, kind: kindExact,
			})
		}

		// The loopback rule keys off the requested URI but requires the
		// registered hostname literal to equal it, so the registered
		// hostname must itself be a loopback IP literal. Note that the
		// real matcher neither checks the registered scheme nor the
		// registered entry's validity here, so neither do we.
		if ip := net.ParseIP(parsed.Hostname()); ip != nil && ip.IsLoopback() {
			key := loopbackKey{
				hostname: parsed.Hostname(),
				path:     parsed.Path,
				rawQuery: parsed.RawQuery,
			}
			m.rules = append(m.rules, registrationRule{
				clientID: c.ID, entryIndex: i, registered: raw, kind: kindLoopback, loop: key,
			})
			m.loopKeys = append(m.loopKeys, key)
		} else if !fosite.IsValidRedirectURI(parsed) {
			m.inert = append(m.inert, inertEntry{
				clientID: c.ID, entryIndex: i, registered: raw, reason: inertInvalid,
			})
		}
	}

	// Single valid registered entry: the empty-parameter fallback of the
	// real matcher. Modeled separately from the non-empty acceptance set.
	if len(c.RedirectURIs) == 1 {
		if u, err := url.Parse(c.RedirectURIs[0]); err == nil && fosite.IsValidRedirectURI(u) {
			m.fallback = &emptyFallback{
				clientID:      c.ID,
				entryIndex:    0,
				registeredURI: c.RedirectURIs[0],
			}
		}
	}

	m.loopKeys = uniqueLoopbackKeys(m.loopKeys)
	return m
}

func uniqueLoopbackKeys(keys []loopbackKey) []loopbackKey {
	seen := make(map[loopbackKey]struct{}, len(keys))
	out := make([]loopbackKey, 0, len(keys))
	for _, k := range keys {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// isLoopbackExact reports whether an exact rule also belongs to a loopback
// matching domain: a valid http URI whose hostname is a loopback IP literal
// is itself accepted through the loopback rule of other clients.
func isLoopbackExact(raw string) (loopbackKey, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" {
		return loopbackKey{}, false
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return loopbackKey{}, false
	}
	return loopbackKey{
		hostname: parsed.Hostname(),
		path:     parsed.Path,
		rawQuery: parsed.RawQuery,
	}, true
}
