// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package redirectaudit implements ClientRedirectOverlapAudit: an
// administrator-only analysis of whether the non-empty redirect_uri
// acceptance sets of two different OAuth 2.0 clients intersect, modeled
// strictly after fosite.MatchRedirectURIWithClientRedirectURIs.
//
// The audit only ever operates on a sealed, integrity-protected client
// snapshot. It never reads client secrets, tokens, or any registration
// fields other than the client id and the registered redirect_uris, and it
// never modifies registration data.
package redirectaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/ory/pop/v6"

	"github.com/ory/hydra/v2/client"
	keysetpagination "github.com/ory/x/pagination/keysetpagination_v2"

	"github.com/gofrs/uuid"
)

// RuleSetVersion identifies the exact matcher rule set the audit models.
// Bump it if fosite.MatchRedirectURIWithClientRedirectURIs ever gains new
// matching rules; unknown behavior is then surfaced as Unsupported instead
// of being guessed.
const RuleSetVersion = "fosite.MatchRedirectURIWithClientRedirectURIs/v1"

// SnapshotClient is the only client data the audit is allowed to observe.
// Deliberately it carries no secret, token, owner, or any other network or
// registration field.
type SnapshotClient struct {
	// ID is the OAuth 2.0 client identifier.
	ID string `json:"client_id"`

	// RedirectURIs are the raw registered redirect URI strings. They are
	// kept byte-for-byte because the real matcher compares strings without
	// normalization.
	RedirectURIs []string `json:"redirect_uris"`
}

// SealedSnapshot is an immutable, integrity-protected view of every client
// in one authorization network at a single point in time.
//
// The digest is computed over a canonical JSON encoding of the whole
// snapshot. Any tampering with the sealed bytes is detected by
// VerifyDigest before analysis, so the audit can never run on input that
// changed after sealing.
type SealedSnapshot struct {
	ruleSet   string
	networkID string
	takenAt   time.Time
	clients   []SnapshotClient
	digest    string
}

// RuleSet returns the matcher rule set version the snapshot was sealed for.
func (s *SealedSnapshot) RuleSet() string { return s.ruleSet }

// NetworkID returns the authorization network (Hydra NID) the snapshot was
// taken from. The audit never crosses network boundaries.
func (s *SealedSnapshot) NetworkID() string { return s.networkID }

// TakenAt returns the UTC time at which the snapshot was sealed.
func (s *SealedSnapshot) TakenAt() time.Time { return s.takenAt }

// Clients returns the sealed, id-sorted client entries. The returned slice
// must not be modified.
func (s *SealedSnapshot) Clients() []SnapshotClient { return s.clients }

// Digest returns the hex-encoded SHA-256 integrity proof of the snapshot.
func (s *SealedSnapshot) Digest() string { return s.digest }

// ClientCount returns the number of clients contained in the snapshot.
func (s *SealedSnapshot) ClientCount() int { return len(s.clients) }

type digestEnvelope struct {
	RuleSet   string           `json:"rule_set"`
	NetworkID string           `json:"network_id"`
	TakenAt   string           `json:"taken_at_utc"`
	Clients   []SnapshotClient `json:"clients"`
}

// SealSnapshot freezes the given client entries into an immutable
// SealedSnapshot and computes its integrity digest.
//
// Entries are copied and sorted by client id. Duplicate client ids are
// rejected because a complete, identity-unique snapshot is a precondition
// for exhaustive pair analysis.
func SealSnapshot(networkID string, takenAt time.Time, clients []SnapshotClient) (*SealedSnapshot, error) {
	sealed := make([]SnapshotClient, len(clients))
	for i, c := range clients {
		sealed[i] = SnapshotClient{
			ID:           c.ID,
			RedirectURIs: append([]string(nil), c.RedirectURIs...),
		}
	}

	slices.SortFunc(sealed, func(a, b SnapshotClient) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})

	for i := 1; i < len(sealed); i++ {
		if sealed[i-1].ID == sealed[i].ID {
			return nil, fmt.Errorf("seal snapshot: duplicate client_id %q violates snapshot uniqueness", sealed[i].ID)
		}
	}

	s := &SealedSnapshot{
		ruleSet:   RuleSetVersion,
		networkID: networkID,
		takenAt:   takenAt.UTC(),
		clients:   sealed,
	}

	digest, err := s.computeDigest()
	if err != nil {
		return nil, err
	}
	s.digest = digest
	return s, nil
}

func (s *SealedSnapshot) computeDigest() (string, error) {
	payload := digestEnvelope{
		RuleSet:   s.ruleSet,
		NetworkID: s.networkID,
		TakenAt:   s.takenAt.UTC().Format(time.RFC3339Nano),
		Clients:   s.clients,
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("seal snapshot: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyDigest recomputes the integrity proof and fails closed if the sealed
// input does not match the digest computed at sealing time.
func (s *SealedSnapshot) VerifyDigest() error {
	actual, err := s.computeDigest()
	if err != nil {
		return err
	}
	if actual != s.digest {
		return fmt.Errorf("snapshot integrity proof mismatch: expected digest %s, got %s", s.digest, actual)
	}
	return nil
}

// TransactionalClientManager is the storage surface required to take a
// consistent snapshot. persistence.Persister satisfies it.
type TransactionalClientManager interface {
	client.Manager
	Transaction(ctx context.Context, fn func(ctx context.Context, c *pop.Connection) error) error
}

// networkIDProvider is implemented by the SQL persister through its embedded
// BasePersister. It is optional: snapshot inputs without network identity
// (for example synthetic sealed snapshots) simply report an empty network id.
type networkIDProvider interface {
	NetworkID(ctx context.Context) uuid.UUID
}

type sealOptions struct {
	pageSize int
	now      func() time.Time
}

// SealOption customizes snapshot collection.
type SealOption func(*sealOptions)

// WithSealPageSize overrides the keyset page size used while collecting the
// snapshot. It exists primarily for testing; production callers should use
// the default maximum page size.
func WithSealPageSize(pageSize int) SealOption {
	return func(o *sealOptions) {
		o.pageSize = pageSize
	}
}

// SealFromManager collects every client visible to the manager inside a
// single database transaction and seals the result.
//
// Paging happens against one transactional read view: concurrent creates,
// updates, and deletes cannot remove clients from the middle of the scan,
// which is what makes the snapshot complete rather than a racy,
// page-by-page approximation. Only client id and redirect_uris are copied;
// no secret, token, or other registration/network field ever leaves the
// storage layer. The manager is used read-only.
func SealFromManager(ctx context.Context, m TransactionalClientManager, opts ...SealOption) (*SealedSnapshot, error) {
	cfg := sealOptions{
		pageSize: keysetpagination.DefaultMaxSize,
		now:      time.Now,
	}
	for _, o := range opts {
		o(&cfg)
	}

	var (
		collected []SnapshotClient
		networkID string
	)

	err := m.Transaction(ctx, func(ctx context.Context, _ *pop.Connection) error {
		if n, ok := m.(networkIDProvider); ok {
			networkID = n.NetworkID(ctx).String()
		}

		var pageOpts []keysetpagination.Option
		for {
			page, nextPage, err := m.GetClients(ctx, client.Filter{
				PageOpts: append(pageOpts, keysetpagination.WithSize(cfg.pageSize)),
			})
			if err != nil {
				return err
			}

			for i := range page {
				collected = append(collected, SnapshotClient{
					ID:           page[i].GetID(),
					RedirectURIs: append([]string(nil), page[i].GetRedirectURIs()...),
				})
			}

			if nextPage.IsLast() {
				return nil
			}
			pageOpts = nextPage.ToOptions()
		}
	})
	if err != nil {
		return nil, fmt.Errorf("collect client redirect snapshot: %w", err)
	}

	return SealSnapshot(networkID, cfg.now(), collected)
}
