// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package redirectaudit

import (
	"net/url"
	"sort"
)

// ExhaustiveReferenceOverlaps is an intentionally simple brute-force oracle
// used to validate the bucketed engine on small snapshots.
//
// It builds a finite candidate universe from the sealed input itself -
// every registered string plus canonical witnesses (two port shapes) for
// every modeled loopback domain - and asks the real fosite matcher about
// every candidate for every unordered client pair. No empty redirect_uri is
// ever considered: the empty-parameter fallback is out of scope for overlap
// analysis and reported separately.
//
// The result maps each overlapping pair to the sorted list of all
// candidate witnesses accepted by both clients.
func ExhaustiveReferenceOverlaps(snap *SealedSnapshot) (map[pairKey][]string, error) {
	if err := snap.VerifyDigest(); err != nil {
		return nil, err
	}

	clients := snap.Clients()
	modeler := fositeModeler{}
	oracle := fositeOracle{}

	// Build the candidate universe deterministically.
	universeSet := make(map[string]struct{})
	for _, c := range clients {
		m := modeler.modelClient(c)
		for _, raw := range c.RedirectURIs {
			if raw != "" {
				universeSet[raw] = struct{}{}
			}
		}
		for _, key := range m.loopKeys {
			universeSet[key.canonicalURI()] = struct{}{}
			universeSet[withPort(key, "8080")] = struct{}{}
		}
	}
	universe := make([]string, 0, len(universeSet))
	for u := range universeSet {
		universe = append(universe, u)
	}
	sort.Strings(universe)

	result := make(map[pairKey][]string)
	for i := 0; i < len(clients); i++ {
		for j := i + 1; j < len(clients); j++ {
			pk := makePairKey(clients[i].ID, clients[j].ID)
			for _, candidate := range universe {
				if oracle.accepts(candidate, clients[i]) && oracle.accepts(candidate, clients[j]) {
					result[pk] = append(result[pk], candidate)
				}
			}
			if witnesses := result[pk]; len(witnesses) > 0 {
				sort.Strings(witnesses)
				result[pk] = witnesses
			}
		}
	}

	return result, nil
}

// withPort renders a loopback domain witness with an explicit port, covering
// the dynamic-port shape of RFC 8252.
func withPort(key loopbackKey, port string) string {
	host := key.hostname
	if containsColon(host) {
		host = "[" + host + "]"
	}
	host = host + ":" + port
	u := &url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     key.path,
		RawQuery: key.rawQuery,
	}
	return u.String()
}

func containsColon(s string) bool {
	for _, r := range s {
		if r == ':' {
			return true
		}
	}
	return false
}
