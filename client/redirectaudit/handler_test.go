// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package redirectaudit_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/negroni"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/client/redirectaudit"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/x/httprouterx"
)

func newAdminServer(t *testing.T, reg redirectaudit.InternalRegistry) *httptest.Server {
	t.Helper()
	n := negroni.New()
	n.UseFunc(httprouterx.TrimTrailingSlashNegroni)
	n.UseFunc(httprouterx.NoCacheNegroni)
	n.UseFunc(httprouterx.AddAdminPrefixIfNotPresentNegroni)

	router := httprouterx.NewRouterAdminWithPrefix()
	redirectaudit.NewHandler(reg).SetAdminRoutes(router)
	n.UseHandler(router)

	ts := httptest.NewServer(n)
	t.Cleanup(ts.Close)
	return ts
}

func TestAdminHandlerAudit(t *testing.T) {
	ctx := context.Background()
	reg := testhelpers.NewRegistryMemory(t)

	const secretValue = "secret-value-that-must-never-leak-12345"
	seed := []*client.Client{
		{ID: "client-a", Secret: secretValue, RedirectURIs: []string{"https://shared.example/cb"}},
		{ID: "client-b", Secret: secretValue, RedirectURIs: []string{"https://shared.example/cb", "https://b.example/other"}},
		{ID: "client-c", Secret: secretValue, RedirectURIs: []string{"http://127.0.0.1:8080/cb"}},
		{ID: "client-d", Secret: secretValue, RedirectURIs: []string{"http://127.0.0.1:9090/cb"}},
		{ID: "client-e", Secret: secretValue, RedirectURIs: []string{"https://isolated.example/x"}},
	}
	for _, c := range seed {
		require.NoError(t, reg.ClientManager().CreateClient(ctx, c))
	}

	ts := newAdminServer(t, reg)

	t.Run("happy path", func(t *testing.T) {
		res, err := ts.Client().Get(ts.URL + "/admin/clients/redirect-overlap-audit")
		require.NoError(t, err)
		defer res.Body.Close()
		require.Equal(t, http.StatusOK, res.StatusCode)

		var report redirectaudit.Report
		require.NoError(t, json.NewDecoder(res.Body).Decode(&report))

		assert.Equal(t, redirectaudit.ReportComplete, report.Status)
		assert.Equal(t, redirectaudit.RuleSetVersion, report.RuleSet)
		assert.Equal(t, 5, report.SnapshotClientCount)
		assert.NotEmpty(t, report.SnapshotDigest)
		assert.Equal(t, 10, report.Stats.TotalClientPairs)
		assert.NotEmpty(t, report.SecurityNote)

		// Two overlapping pairs: shared exact URI and the loopback family.
		require.Len(t, report.Overlaps, 2)
		assert.Equal(t, "client-a", report.Overlaps[0].ClientA)
		assert.Equal(t, "client-b", report.Overlaps[0].ClientB)
		assert.Equal(t, "https://shared.example/cb", report.Overlaps[0].WitnessURI)
		assert.True(t, report.Overlaps[0].WitnessVerifiedByMatcher)

		assert.Equal(t, "client-c", report.Overlaps[1].ClientA)
		assert.Equal(t, "client-d", report.Overlaps[1].ClientB)
		assert.Equal(t, "http://127.0.0.1/cb", report.Overlaps[1].WitnessURI)
	})

	t.Run("response never contains secrets or tokens", func(t *testing.T) {
		res, err := ts.Client().Get(ts.URL + "/admin/clients/redirect-overlap-audit")
		require.NoError(t, err)
		defer res.Body.Close()

		raw, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		body := string(raw)

		assert.NotContains(t, body, secretValue)
		assert.NotContains(t, body, "client_secret")
		assert.NotContains(t, body, "registration_access_token")
		assert.NotContains(t, body, "hashed_secret")
	})

	t.Run("budget query parameters produce incomplete reports", func(t *testing.T) {
		res, err := ts.Client().Get(ts.URL + "/admin/clients/redirect-overlap-audit?max_comparisons=1")
		require.NoError(t, err)
		defer res.Body.Close()
		require.Equal(t, http.StatusOK, res.StatusCode)

		var report redirectaudit.Report
		require.NoError(t, json.NewDecoder(res.Body).Decode(&report))
		assert.Equal(t, redirectaudit.ReportIncomplete, report.Status)
		assert.True(t, report.Stats.PairsTruncated)
		require.Len(t, report.Overlaps, 1)
	})

	t.Run("invalid query parameters are rejected", func(t *testing.T) {
		res, err := ts.Client().Get(ts.URL + "/admin/clients/redirect-overlap-audit?max_comparisons=-3")
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)

		res, err = ts.Client().Get(ts.URL + "/admin/clients/redirect-overlap-audit?max_findings=not-a-number")
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("route is absent from the public router", func(t *testing.T) {
		public := negroni.New()
		public.UseHandler(httprouterx.NewRouterPublic())
		publicTS := httptest.NewServer(public)
		t.Cleanup(publicTS.Close)

		res, err := publicTS.Client().Get(publicTS.URL + "/clients/redirect-overlap-audit")
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, http.StatusNotFound, res.StatusCode)
	})
}

func TestSealFromManagerIsCompleteAndPaginated(t *testing.T) {
	ctx := context.Background()
	reg := testhelpers.NewRegistryMemory(t)

	const total = 7
	for i := 0; i < total; i++ {
		require.NoError(t, reg.ClientManager().CreateClient(ctx, &client.Client{
			ID:           "paged-" + string(rune('0'+i)),
			Secret:       "irrelevant-secret",
			RedirectURIs: []string{"https://paged.example/cb"},
		}))
	}

	// Page size one forces the snapshotter to walk every keyset page inside
	// one transaction; no client may be lost.
	snap, err := redirectaudit.SealFromManager(ctx, reg.Persister(), redirectaudit.WithSealPageSize(1))
	require.NoError(t, err)
	require.Len(t, snap.Clients(), total)
	require.NoError(t, snap.VerifyDigest())
	assert.Equal(t, reg.Networker().NetworkID(ctx).String(), snap.NetworkID())
	assert.Equal(t, redirectaudit.RuleSetVersion, snap.RuleSet())

	// Snapshot content is sorted and contains no other fields by construction.
	for i := 1; i < len(snap.Clients()); i++ {
		assert.Less(t, snap.Clients()[i-1].ID, snap.Clients()[i].ID)
	}

	report, err := redirectaudit.NewAuditor().Run(ctx, snap, redirectaudit.Options{})
	require.NoError(t, err)
	assert.Equal(t, redirectaudit.ReportComplete, report.Status)
	// Every pair shares the exact URI.
	assert.Len(t, report.Overlaps, total*(total-1)/2)
}

func TestSealFromManagerScopesToNetwork(t *testing.T) {
	ctx := context.Background()
	reg := testhelpers.NewRegistryMemory(t)

	require.NoError(t, reg.ClientManager().CreateClient(ctx, &client.Client{
		ID: "only-client", Secret: "s", RedirectURIs: []string{"https://n.example/cb"},
	}))

	snap, err := redirectaudit.SealFromManager(ctx, reg.Persister())
	require.NoError(t, err)
	assert.Len(t, snap.Clients(), 1)
	assert.Equal(t, "only-client", snap.Clients()[0].ID)
}
