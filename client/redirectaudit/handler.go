// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package redirectaudit

import (
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/ory/herodot"
	"github.com/ory/hydra/v2/persistence"
	"github.com/ory/x/httprouterx"
	"github.com/ory/x/httpx"
)

// RedirectOverlapAuditHandlerPath is the admin-only route of the
// ClientRedirectOverlapAudit. It is never registered on the public router.
const RedirectOverlapAuditHandlerPath = "/clients/redirect-overlap-audit"

// InternalRegistry is the storage surface required by the handler.
type InternalRegistry interface {
	httpx.WriterProvider
	persistence.Provider
}

// Handler exposes ClientRedirectOverlapAudit on the administrative API.
type Handler struct {
	r InternalRegistry
}

// NewHandler constructs the administrative audit handler.
func NewHandler(r InternalRegistry) *Handler {
	return &Handler{r: r}
}

// SetAdminRoutes registers the audit endpoint on the administrative router
// only. Administrative routers are bound to the administrative listener, so
// this endpoint cannot be reached from the public OAuth 2.0 surface.
func (h *Handler) SetAdminRoutes(admin *httprouterx.RouterAdmin) {
	admin.GET(RedirectOverlapAuditHandlerPath, h.runClientRedirectOverlapAudit)
}

// Client Redirect Overlap Audit query parameters
//
// swagger:parameters runClientRedirectOverlapAudit
type _ struct {
	// Maximum number of distinct client pairs to decide before the report is
	// marked incomplete. Omit or set to 0 for no limit.
	//
	// in: query
	// required: false
	MaxComparisons int `json:"max_comparisons"`

	// Maximum number of overlap/unsupported pair entries to emit before the
	// report is marked incomplete. Omit or set to 0 for no limit.
	//
	// in: query
	// required: false
	MaxFindings int `json:"max_findings"`
}

// swagger:route GET /admin/clients/redirect-overlap-audit oAuth2 runClientRedirectOverlapAudit
//
// # Run Client Redirect URI Overlap Audit
//
// Seals a complete, transactionally consistent snapshot of every OAuth 2.0
// client in the current authorization network and analyzes whether the
// non-empty redirect_uri acceptance sets of distinct clients intersect,
// using the same fosite matching rules as the authorization endpoint
// (simple string comparison plus the RFC 8252 loopback port rule). Every
// reported witness is re-validated against the real matcher.
//
// The endpoint is administrative only and never returns client secrets,
// registration access tokens, or data from another authorization network.
// It is read-only and does not modify any client registration. An overlap is
// a configuration observation and is not reported as a vulnerability by
// itself. When a budget is exhausted the response status is "incomplete";
// an incomplete response must not be interpreted as proving the absence of
// overlaps.
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
//	Schemes: http, https
//
//	Responses:
//	  200: clientRedirectOverlapAuditReport
//	  400: genericError
//	  default: genericError
//
//	Extensions:
//	  x-ory-ratelimit-bucket: hydra-admin-low
func (h *Handler) runClientRedirectOverlapAudit(w http.ResponseWriter, r *http.Request) {
	opts, err := parseAuditOptions(r)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	// Collection and sealing happen inside one storage transaction, so
	// concurrent registration changes cannot remove clients mid-scan.
	snapshot, err := SealFromManager(r.Context(), h.r.Persister())
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	report, err := NewAuditor().Run(r.Context(), snapshot, opts)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().Write(w, r, report)
}

func parseAuditOptions(r *http.Request) (Options, error) {
	var opts Options
	for _, name := range []string{"max_comparisons", "max_findings"} {
		raw := r.URL.Query().Get(name)
		if raw == "" {
			continue
		}
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return Options{}, errors.WithStack(herodot.ErrBadRequest().WithReasonf(
				"Query parameter %q must be a non-negative integer but got %q.", name, raw))
		}
		if name == "max_comparisons" {
			opts.MaxComparisons = value
		} else {
			opts.MaxFindings = value
		}
	}
	return opts, nil
}
