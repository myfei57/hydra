// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk

import (
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/josex"
	"github.com/ory/x/otelx"
)

// Backend identifies one of the two key managers a CompositeManager combines.
type Backend string

const (
	// BackendHardware is the Hardware Security Module backed manager.
	BackendHardware Backend = "hardware"
	// BackendSoftware is the software (SQL) backed manager.
	BackendSoftware Backend = "software"
)

// ConsistencyMode selects how the two backends are read when a composite view
// is built.
type ConsistencyMode string

const (
	// ConsistencyEventual reads each backend with an independent GetKeySet
	// call. The two reads are not, and must not be claimed to be, a single
	// point-in-time observation. A genuine x.ErrNotFound on a backend means
	// the backend currently holds no key for the set; any other error fails
	// the build. This is the default and matches the historic ManagerStrategy
	// fallback semantics.
	ConsistencyEventual ConsistencyMode = "eventual"

	// ConsistencyStrict requires both backends to implement SnapshotManager.
	// Each backend is read through a revision-pinned snapshot, so the merged
	// view refers to fixed revisions of both backends instead of two
	// independent, untimestamped GetKeySet calls. A backend that cannot serve
	// snapshots makes the build fail with ErrSnapshotUnsupported.
	ConsistencyStrict ConsistencyMode = "strict"
)

// Sentinel errors for composite view operations. They are RFC6749 errors so
// errors.Is keeps working through errors.WithStack / WithWrap, exactly as for
// x.ErrNotFound.
var (
	// ErrCompositeKeyConflict is returned when two backends serve the same
	// kid with different key identity (public material, alg, or use). The
	// entire candidate view is rejected: no partial generation is published
	// and the previously published generation stays in service.
	ErrCompositeKeyConflict = &fosite.RFC6749Error{
		CodeField:        http.StatusConflict,
		ErrorField:       http.StatusText(http.StatusConflict),
		DescriptionField: "The same key ID is served by multiple key backends with different key material or parameters",
	}

	// ErrSnapshotUnsupported is returned in strict consistency mode when a
	// backend does not provide the revision-pinned snapshot protocol. Hydra
	// never presents two independent GetKeySet reads as a strict snapshot.
	ErrSnapshotUnsupported = &fosite.RFC6749Error{
		CodeField:        http.StatusNotImplemented,
		ErrorField:       http.StatusText(http.StatusNotImplemented),
		DescriptionField: "Strict composite key consistency requires a revision-pinned snapshot protocol, which the configured key backend does not support",
	}

	// ErrCompositeManagerClosed is returned when a CompositeManager is used
	// after Close.
	ErrCompositeManagerClosed = &fosite.RFC6749Error{
		CodeField:        http.StatusServiceUnavailable,
		ErrorField:       http.StatusText(http.StatusServiceUnavailable),
		DescriptionField: "The composite key manager has been closed",
	}
)

// KeySetRevision is an opaque, backend-scoped revision token. Two snapshots
// with the same revision value from the same backend describe the same key set
// state. The value is never interpreted across backends.
type KeySetRevision struct {
	// Backend that issued the revision.
	Backend Backend
	// Value is the backend-specific, opaque revision identifier.
	Value string
}

// KeySetSnapshot is a revision-pinned, immutable read of one backend's key
// set. The KeySet content must remain stable for the lifetime of the snapshot,
// even if the backend is mutated afterwards.
type KeySetSnapshot struct {
	// Revision pins the backend state this snapshot was taken from.
	Revision KeySetRevision
	// KeySet is the key set content as it existed at Revision.
	KeySet *jose.JSONWebKeySet
}

// SnapshotManager is the optional protocol a backend Manager implements to
// participate in ConsistencyStrict composite reads. A backend without this
// protocol can still be used in ConsistencyEventual mode.
type SnapshotManager interface {
	Manager

	// SnapshotKeySet returns a revision-pinned snapshot of the named key set.
	// A genuine absence must be reported as x.ErrNotFound, the same way
	// GetKeySet does, so that "not found" stays distinguishable from a
	// backend failure.
	SnapshotKeySet(ctx context.Context, set string) (KeySetSnapshot, error)
}

// viewKeySigner resolves the signing material for one key of a published view.
// Every implementation is bound to exactly one (backend, kid) pair and must
// never silently resolve a different kid or fall back to another backend:
// when the bound owner cannot produce the pinned material, it returns an
// error and signing fails.
type viewKeySigner interface {
	// signingKey returns a JSONWebKey usable for signing. The returned key is
	// transient and must not be retained in the published view. For
	// non-exportable hardware material it wraps an opaque signer handle; for
	// exportable software material it is fetched from the owning manager on
	// demand and validated against the pinned public identity.
	signingKey(ctx context.Context) (*jose.JSONWebKey, error)
}

// opaqueKeySigner keeps the non-exportable signer handle returned by an HSM.
// The handle exposes Public/Algs/SignPayload only, never the private bytes,
// so caching it does not export a private key.
type opaqueKeySigner struct {
	handle jose.OpaqueSigner
	kid    string
	alg    string
	use    string
}

func (s *opaqueKeySigner) signingKey(_ context.Context) (*jose.JSONWebKey, error) {
	return &jose.JSONWebKey{
		Key:       s.handle,
		KeyID:     s.kid,
		Algorithm: s.alg,
		Use:       s.use,
	}, nil
}

// managedKeySigner re-fetches an exportable private key from the owning
// manager at signing time. The view never caches the private key material; it
// only pins the public thumbprint and refuses to sign if the backend now
// serves different material for the same kid.
type managedKeySigner struct {
	manager    Manager
	owner      Backend
	set        string
	kid        string
	thumbprint string
}

func (s *managedKeySigner) signingKey(ctx context.Context) (*jose.JSONWebKey, error) {
	keySet, err := s.manager.GetKey(ctx, s.set, s.kid)
	if err != nil {
		// The owning backend is unavailable or no longer holds the key. Fail
		// outright rather than reaching for another backend's material.
		return nil, err
	}

	for i := range keySet.Keys {
		key := &keySet.Keys[i]
		if key.KeyID != s.kid {
			continue
		}

		public := josex.ToPublicKey(key)
		thumbprint, err := public.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if got := hex.EncodeToString(thumbprint); got != s.thumbprint {
			return nil, errors.WithStack(ErrCompositeKeyConflict.
				WithHintf("Key backend %q now serves different material for key ID %q than the published composite view (thumbprint %q, expected %q)",
					s.owner, s.kid, got, s.thumbprint))
		}
		return key, nil
	}

	return nil, errors.WithStack(x.ErrNotFound.
		WithHintf("Key backend %q no longer holds key ID %q", s.owner, s.kid))
}

// ViewKey is one entry of a CompositeKeyView. It is immutable after the view
// is published.
type ViewKey struct {
	// public is a public-only JWK. It never wraps an OpaqueSigner or private
	// key material and is safe to marshal into a public JWKS response.
	public jose.JSONWebKey
	// owner is the backend that performs real signatures with this key.
	owner Backend
	// thumbprint is the hex encoded RFC 7638 SHA-256 JWK thumbprint of the
	// public material.
	thumbprint string
	// signer resolves the signing material without ever changing owner.
	signer viewKeySigner
}

// KID returns the key ID.
func (k ViewKey) KID() string { return k.public.KeyID }

// Owner returns the backend that owns signatures produced with this key.
func (k ViewKey) Owner() Backend { return k.owner }

// Thumbprint returns the hex encoded SHA-256 JWK thumbprint.
func (k ViewKey) Thumbprint() string { return k.thumbprint }

// Public returns a copy of the public JWK. The copy contains no private or
// opaque material.
func (k ViewKey) Public() jose.JSONWebKey {
	out := k.public
	return out
}

// CompositeKeyView is an immutable, published combination of the hardware and
// software managers for one key set. A view is built completely off the read
// path and only then atomically published, so readers can never observe a
// half-constructed view. All signatures and public JWKS answers derived from a
// view bind to the same per-key owner and material recorded in it.
type CompositeKeyView struct {
	set        string
	generation uint64
	digest     string
	keys       []ViewKey // sorted by KID and immutable after publish
	selected   string
	revisions  []KeySetRevision // empty in eventual mode
	createdAt  time.Time

	// active counts signing operations that still reference this view. A
	// superseded view is only retired after all active operations complete.
	active sync.WaitGroup
	// retired is closed once the view has been superseded or the manager was
	// closed and no active signing operation remains.
	retired    chan struct{}
	retireOnce sync.Once
}

// Set returns the key set name this view was built for.
func (v *CompositeKeyView) Set() string { return v.set }

// Generation returns the stable, monotonic generation number.
func (v *CompositeKeyView) Generation() uint64 { return v.generation }

// Digest returns the deterministic content digest over all key identities and
// owners. Two views of the same set with the same content have the same digest
// and do not create a new generation.
func (v *CompositeKeyView) Digest() string { return v.digest }

// CreatedAt returns the publication time.
func (v *CompositeKeyView) CreatedAt() time.Time { return v.createdAt }

// Revisions returns the pinned backend revisions this view was built from. It
// is empty in eventual consistency mode.
func (v *CompositeKeyView) Revisions() []KeySetRevision {
	out := make([]KeySetRevision, len(v.revisions))
	copy(out, v.revisions)
	return out
}

// Retired is closed after the view is superseded (or its manager closed) and
// every signing operation that started before retirement has completed.
func (v *CompositeKeyView) Retired() <-chan struct{} { return v.retired }

// Key returns the view entry for a kid.
func (v *CompositeKeyView) Key(kid string) (ViewKey, bool) {
	// keys are sorted by kid, but sets are small; a linear scan keeps the
	// code free of index state that could drift across publications.
	for i := range v.keys {
		if v.keys[i].KID() == kid {
			return v.keys[i], true
		}
	}
	return ViewKey{}, false
}

// Keys returns a copy of the immutable view entries.
func (v *CompositeKeyView) Keys() []ViewKey {
	out := make([]ViewKey, len(v.keys))
	copy(out, v.keys)
	return out
}

// SelectedKID returns the kid of the key that new signatures bind to.
func (v *CompositeKeyView) SelectedKID() string { return v.selected }

// SelectedKey returns the key that new signatures bind to. It is the first key
// in stable kid order, which makes selection deterministic across replicas.
func (v *CompositeKeyView) SelectedKey() ViewKey {
	entry, _ := v.Key(v.selected)
	return entry
}

// PublicKeySet returns a JSONWebKeySet containing exclusively public JWKs.
// Non-exportable private keys are represented by their public material only;
// no opaque signer handle, private exponent, or credential is ever included.
func (v *CompositeKeyView) PublicKeySet() *jose.JSONWebKeySet {
	out := &jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(v.keys))}
	for i := range v.keys {
		out.Keys = append(out.Keys, v.keys[i].Public())
	}
	return out
}

func (v *CompositeKeyView) acquire() { v.active.Add(1) }

func (v *CompositeKeyView) release() { v.active.Done() }

// retire marks the view as superseded and closes Retired once all in-flight
// signing operations have finished. It is safe to call multiple times.
func (v *CompositeKeyView) retire() {
	v.retireOnce.Do(func() {
		go func() {
			v.active.Wait()
			close(v.retired)
		}()
	})
}

// CompositeManager combines a hardware and a software Manager into immutable
// CompositeKeyViews while implementing the Manager interface itself. Write
// routing mirrors ManagerStrategy exactly (generation goes to hardware,
// software keys go to the software manager, deletes fall back on genuine
// NotFound), so enabling the composite is behavior compatible.
type CompositeManager struct {
	hardware Manager
	software Manager
	mode     ConsistencyMode

	// build serializes view construction per set so concurrent first reads
	// publish a single generation instead of racing each other.
	build singleflight.Group

	mu         sync.RWMutex
	views      map[string]*CompositeKeyView
	stale      map[string]bool
	staleSeq   map[string]uint64
	generation map[string]uint64
	lastDigest map[string]string
	closed     bool

	closeOnce sync.Once
}

// maxBuildRetries bounds rebuilds triggered by invalidations landing while a
// candidate view is being constructed.
const maxBuildRetries = 5

// CompositeOption customizes a CompositeManager.
type CompositeOption func(*CompositeManager)

// WithStrictConsistency enables revision-pinned snapshot reads. Both backends
// must implement SnapshotManager or every view build fails with
// ErrSnapshotUnsupported.
func WithStrictConsistency() CompositeOption {
	return func(m *CompositeManager) { m.mode = ConsistencyStrict }
}

// NewCompositeManager combines the two backends. It does not take ownership of
// their lifecycle: Close retires composite views but never closes a manager
// supplied by the caller.
func NewCompositeManager(hardwareKeyManager, softwareKeyManager Manager, opts ...CompositeOption) *CompositeManager {
	m := &CompositeManager{
		hardware:   hardwareKeyManager,
		software:   softwareKeyManager,
		mode:       ConsistencyEventual,
		views:      map[string]*CompositeKeyView{},
		stale:      map[string]bool{},
		staleSeq:   map[string]uint64{},
		generation: map[string]uint64{},
		lastDigest: map[string]string{},
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Mode reports the configured consistency mode.
func (m *CompositeManager) Mode() ConsistencyMode { return m.mode }

// CurrentView returns the currently published view for a set without building
// one. The second return value is false when no view has been published yet.
func (m *CompositeManager) CurrentView(set string) (*CompositeKeyView, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.views[set]
	return v, ok
}

// useView acquires a reference on v for the duration of fn. The reference is
// acquired under the manager read lock, which every retire() call waits on via
// the write lock, so WaitGroup.Add can never race WaitGroup.Wait. The view
// stays usable even if another goroutine publishes a successor while fn runs;
// it is retired only after fn returns.
func (m *CompositeManager) useView(v *CompositeKeyView, fn func() error) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return errors.WithStack(ErrCompositeManagerClosed)
	}
	v.acquire()
	m.mu.RUnlock()

	defer v.release()
	return fn()
}

// EnsureView returns the current view for set, building and publishing a new
// generation when none exists or the backend content has changed. Backend
// failures and identity conflicts reject the candidate and leave the previous
// generation in service.
func (m *CompositeManager) EnsureView(ctx context.Context, set string) (_ *CompositeKeyView, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "jwk.CompositeEnsureView",
		trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, errors.WithStack(ErrCompositeManagerClosed)
	}
	if v, ok := m.views[set]; ok && !m.stale[set] {
		m.mu.RUnlock()
		return v, nil
	}
	m.mu.RUnlock()

	v, err, _ := m.build.Do(set, func() (any, error) {
		return m.buildAndPublish(ctx, set)
	})
	if err != nil {
		return nil, err
	}
	return v.(*CompositeKeyView), nil
}

type backendRead struct {
	backend   Backend
	keys      []jose.JSONWebKey
	revision  KeySetRevision
	available bool
}

// readBackend reads one backend, distinguishing a genuine NotFound (the
// backend holds no key for this set) from an actual failure (which aborts the
// whole build). In strict mode it requires and uses the snapshot protocol.
func (m *CompositeManager) readBackend(ctx context.Context, set string, backend Backend, manager Manager) (*backendRead, error) {
	if m.mode == ConsistencyStrict {
		snapshotManager, ok := manager.(SnapshotManager)
		if !ok {
			return nil, errors.WithStack(ErrSnapshotUnsupported.
				WithHintf("Key backend %q does not implement the revision-pinned snapshot protocol", backend))
		}

		snapshot, err := snapshotManager.SnapshotKeySet(ctx, set)
		if errors.Is(err, x.ErrNotFound) {
			return &backendRead{backend: backend, available: false}, nil
		}
		if err != nil {
			return nil, err
		}
		if snapshot.KeySet == nil {
			return &backendRead{backend: backend, available: false, revision: snapshot.Revision}, nil
		}
		return &backendRead{
			backend:   backend,
			keys:      snapshot.KeySet.Keys,
			revision:  snapshot.Revision,
			available: true,
		}, nil
	}

	keySet, err := manager.GetKeySet(ctx, set)
	if errors.Is(err, x.ErrNotFound) {
		return &backendRead{backend: backend, available: false}, nil
	}
	if err != nil {
		// A real backend error must never be mistaken for an empty backend:
		// returning here aborts the build and no new generation is published.
		return nil, err
	}
	return &backendRead{backend: backend, keys: keySet.Keys, available: true}, nil
}

type keyIdentity struct {
	thumbprint string
	alg        string
	use        string
}

func (i keyIdentity) equals(other keyIdentity) bool {
	return i.thumbprint == other.thumbprint && i.alg == other.alg && i.use == other.use
}

func (m *CompositeManager) buildAndPublish(ctx context.Context, set string) (*CompositeKeyView, error) {
	return m.buildAndPublishAttempt(ctx, set, 0)
}

func (m *CompositeManager) buildAndPublishAttempt(ctx context.Context, set string, attempt int) (*CompositeKeyView, error) {
	// Another goroutine may have published while this build was waiting on
	// the singleflight entry.
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, errors.WithStack(ErrCompositeManagerClosed)
	}
	if v, ok := m.views[set]; ok && !m.stale[set] {
		m.mu.RUnlock()
		return v, nil
	}
	// Pin the invalidation sequence this build is based on. An invalidation
	// landing while the backends are being read invalidates the candidate and
	// forces a rebuild instead of publishing a generation that missed it.
	sequence := m.staleSeq[set]
	m.mu.RUnlock()

	hardwareRead, err := m.readBackend(ctx, set, BackendHardware, m.hardware)
	if err != nil {
		return nil, err
	}
	softwareRead, err := m.readBackend(ctx, set, BackendSoftware, m.software)
	if err != nil {
		return nil, err
	}

	if !hardwareRead.available && !softwareRead.available {
		return nil, errors.WithStack(x.ErrNotFound)
	}

	entries := map[string]*ViewKey{}
	add := func(read *backendRead) error {
		ownerManager := m.hardware
		if read.backend == BackendSoftware {
			ownerManager = m.software
		}

		for _, key := range read.keys {
			public := josex.ToPublicKey(&key)
			if public.Key == nil {
				return errors.Errorf("key %q from backend %q has no resolvable public material", key.KeyID, read.backend)
			}
			rawThumbprint, err := public.Thumbprint(crypto.SHA256)
			if err != nil {
				return errors.WithStack(err)
			}
			identity := keyIdentity{
				thumbprint: hex.EncodeToString(rawThumbprint),
				alg:        key.Algorithm,
				use:        key.Use,
			}

			if existing, ok := entries[key.KeyID]; ok {
				if !identity.equals(keyIdentity{
					thumbprint: existing.thumbprint,
					alg:        existing.public.Algorithm,
					use:        existing.public.Use,
				}) {
					// Reject the whole candidate view rather than silently
					// picking one backend by order or publishing both
					// materials under the same kid.
					return errors.WithStack(ErrCompositeKeyConflict.
						WithHintf("Key ID %q is served by backends %q and %q with different public key material, alg, or use",
							key.KeyID, existing.owner, read.backend))
				}

				// Identical material under the same kid: safe to deduplicate.
				// Hardware precedence is explicit and harmless because either
				// backend produces signatures verifiable by the same public
				// key. Software-only keys keep their software owner.
				if read.backend == BackendHardware {
					existing.owner = BackendHardware
					existing.signer = newViewKeySigner(key, ownerManager, read.backend, set, identity)
				}
				continue
			}

			entries[key.KeyID] = &ViewKey{
				public:     public,
				owner:      read.backend,
				thumbprint: identity.thumbprint,
				signer:     newViewKeySigner(key, ownerManager, read.backend, set, identity),
			}
		}
		return nil
	}

	if err := add(hardwareRead); err != nil {
		return nil, err
	}
	if err := add(softwareRead); err != nil {
		return nil, err
	}

	kids := make([]string, 0, len(entries))
	for kid := range entries {
		kids = append(kids, kid)
	}
	sort.Strings(kids)

	keys := make([]ViewKey, 0, len(kids))
	for _, kid := range kids {
		keys = append(keys, *entries[kid])
	}

	digest, err := computeViewDigest(set, keys)
	if err != nil {
		return nil, err
	}

	var revisions []KeySetRevision
	if m.mode == ConsistencyStrict {
		if hardwareRead.available {
			revisions = append(revisions, hardwareRead.revision)
		}
		if softwareRead.available {
			revisions = append(revisions, softwareRead.revision)
		}
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.WithStack(ErrCompositeManagerClosed)
	}

	// A write invalidated the set while the backends were being read: discard
	// this candidate and rebuild, so a published generation cannot miss a
	// committed change. The previous generation remains in service meanwhile.
	if m.staleSeq[set] != sequence {
		m.mu.Unlock()
		if attempt >= maxBuildRetries {
			return nil, errors.Errorf("composite view for set %q could not converge after %d concurrent invalidations", set, maxBuildRetries)
		}
		return m.buildAndPublishAttempt(ctx, set, attempt+1)
	}

	// Unchanged content never creates a new generation, even after the cached
	// view was marked stale by a write. The existing view stays in service.
	if previous, ok := m.views[set]; ok && previous.digest == digest {
		delete(m.stale, set)
		m.mu.Unlock()
		return previous, nil
	}

	generation := m.generation[set]
	if m.lastDigest[set] != digest {
		generation++
		m.generation[set] = generation
		m.lastDigest[set] = digest
	}

	view := &CompositeKeyView{
		set:        set,
		generation: generation,
		digest:     digest,
		keys:       keys,
		selected:   keys[0].KID(),
		revisions:  revisions,
		createdAt:  time.Now().UTC(),
		retired:    make(chan struct{}),
	}

	previous := m.views[set]
	m.views[set] = view
	delete(m.stale, set)
	m.mu.Unlock()

	if previous != nil && previous != view {
		previous.retire()
	}
	return view, nil
}

// newViewKeySigner chooses the signer handle for one key. Non-exportable
// opaque signers (HSM) are retained as handles; everything else is resolved on
// demand from the owning manager so private bytes never enter the view cache.
func newViewKeySigner(key jose.JSONWebKey, ownerManager Manager, owner Backend, set string, identity keyIdentity) viewKeySigner {
	if opaque, ok := key.Key.(jose.OpaqueSigner); ok {
		return &opaqueKeySigner{handle: opaque, kid: key.KeyID, alg: key.Algorithm, use: key.Use}
	}
	return &managedKeySigner{
		manager:    ownerManager,
		owner:      owner,
		set:        set,
		kid:        key.KeyID,
		thumbprint: identity.thumbprint,
	}
}

type digestEntry struct {
	KID        string  `json:"kid"`
	Thumbprint string  `json:"thumbprint"`
	Alg        string  `json:"alg"`
	Use        string  `json:"use"`
	Owner      Backend `json:"owner"`
}

// computeViewDigest hashes the canonical, sorted list of key identities and
// owners. Only public identity contributes: no private material, opaque
// handle pointer, or timestamp can influence the digest.
func computeViewDigest(set string, keys []ViewKey) (string, error) {
	entries := make([]digestEntry, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, digestEntry{
			KID:        key.KID(),
			Thumbprint: key.thumbprint,
			Alg:        key.public.Algorithm,
			Use:        key.public.Use,
			Owner:      key.owner,
		})
	}

	canonical, err := json.Marshal(struct {
		Set string        `json:"set"`
		Key []digestEntry `json:"keys"`
	}{Set: set, Key: entries})
	if err != nil {
		return "", errors.WithStack(err)
	}

	hasher := crypto.SHA256.New()
	if _, err := hasher.Write(canonical); err != nil {
		return "", errors.WithStack(err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Invalidate marks the cached view for a set as stale so the next read
// rebuilds it from the backends. It is used when a backend changed outside of
// this manager (for example an HSM-side reconfiguration). The previously
// published view remains the last-known-good generation until a successor is
// built and published; a failed rebuild leaves it in service and retries on
// the next read.
func (m *CompositeManager) Invalidate(set string) {
	m.invalidate(set)
}

// invalidate marks a set's view stale after a successful write. The view is
// not retired eagerly: it stays the published generation until a successor
// exists, at which point buildAndPublish retires it. The monotonic sequence
// lets an in-flight build detect that it missed this change and rebuild.
func (m *CompositeManager) invalidate(set string) {
	m.mu.Lock()
	m.stale[set] = true
	m.staleSeq[set]++
	m.mu.Unlock()
}

// GenerateAndPersistKeySet routes to the hardware manager, matching
// ManagerStrategy.
func (m *CompositeManager) GenerateAndPersistKeySet(ctx context.Context, set, kid, alg, use string) (_ *jose.JSONWebKeySet, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "jwk.CompositeGenerateAndPersistKeySet",
		trace.WithAttributes(
			attribute.String("set", set),
			attribute.String("kid", kid),
			attribute.String("alg", alg),
			attribute.String("use", use)))
	defer otelx.End(span, &err)

	keySet, err := m.hardware.GenerateAndPersistKeySet(ctx, set, kid, alg, use)
	if err != nil {
		return nil, err
	}
	m.invalidate(set)
	return keySet, nil
}

// AddKey routes to the software manager, matching ManagerStrategy.
func (m *CompositeManager) AddKey(ctx context.Context, set string, key *jose.JSONWebKey) (err error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "jwk.CompositeAddKey", trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	if err := m.software.AddKey(ctx, set, key); err != nil {
		return err
	}
	m.invalidate(set)
	return nil
}

// AddKeySet routes to the software manager, matching ManagerStrategy.
func (m *CompositeManager) AddKeySet(ctx context.Context, set string, keys *jose.JSONWebKeySet) (err error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "jwk.CompositeAddKeySet", trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	if err := m.software.AddKeySet(ctx, set, keys); err != nil {
		return err
	}
	m.invalidate(set)
	return nil
}

// UpdateKey routes to the software manager, matching ManagerStrategy.
func (m *CompositeManager) UpdateKey(ctx context.Context, set string, key *jose.JSONWebKey) (err error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "jwk.CompositeUpdateKey", trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	if err := m.software.UpdateKey(ctx, set, key); err != nil {
		return err
	}
	m.invalidate(set)
	return nil
}

// UpdateKeySet routes to the software manager, matching ManagerStrategy.
func (m *CompositeManager) UpdateKeySet(ctx context.Context, set string, keys *jose.JSONWebKeySet) (err error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "jwk.CompositeUpdateKeySet", trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	if err := m.software.UpdateKeySet(ctx, set, keys); err != nil {
		return err
	}
	m.invalidate(set)
	return nil
}

// GetKey returns the key for kid from the current published view. The signing
// material is assembled transiently through the pinned owner; a failure of
// that owner is returned, never papered over with another backend's key.
func (m *CompositeManager) GetKey(ctx context.Context, set, kid string) (_ *jose.JSONWebKeySet, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "jwk.CompositeGetKey",
		trace.WithAttributes(attribute.String("set", set), attribute.String("kid", kid)))
	defer otelx.End(span, &err)

	view, err := m.EnsureView(ctx, set)
	if err != nil {
		return nil, err
	}

	entry, ok := view.Key(kid)
	if !ok {
		return nil, errors.WithStack(x.ErrNotFound)
	}

	var key *jose.JSONWebKey
	err = m.useView(view, func() error {
		key, err = entry.signer.signingKey(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*key}}, nil
}

// GetKeySet returns the merged key set of the current published view. Opaque
// hardware handles and on-demand software private keys are assembled for this
// call only; the view cache itself retains public JWKs and opaque handles, but
// never exported private key material.
func (m *CompositeManager) GetKeySet(ctx context.Context, set string) (_ *jose.JSONWebKeySet, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "jwk.CompositeGetKeySet", trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	view, err := m.EnsureView(ctx, set)
	if err != nil {
		return nil, err
	}

	keySet := &jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(view.keys))}
	err = m.useView(view, func() error {
		for _, entry := range view.keys {
			key, signErr := entry.signer.signingKey(ctx)
			if signErr != nil {
				return signErr
			}
			keySet.Keys = append(keySet.Keys, *key)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return keySet, nil
}

// DeleteKey mirrors ManagerStrategy: the hardware manager is tried first and
// the software manager is only consulted on a genuine NotFound.
func (m *CompositeManager) DeleteKey(ctx context.Context, set, kid string) (err error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "jwk.CompositeDeleteKey",
		trace.WithAttributes(attribute.String("set", set), attribute.String("kid", kid)))
	defer otelx.End(span, &err)

	err = m.hardware.DeleteKey(ctx, set, kid)
	switch {
	case err == nil:
		m.invalidate(set)
		return nil
	case errors.Is(err, x.ErrNotFound):
		if err := m.software.DeleteKey(ctx, set, kid); err != nil {
			return err
		}
		m.invalidate(set)
		return nil
	default:
		return err
	}
}

// DeleteKeySet mirrors ManagerStrategy: the hardware manager is tried first
// and the software manager is only consulted on a genuine NotFound.
func (m *CompositeManager) DeleteKeySet(ctx context.Context, set string) (err error) {
	ctx, span := otel.GetTracerProvider().Tracer(tracingComponent).Start(ctx, "jwk.CompositeDeleteKeySet", trace.WithAttributes(attribute.String("set", set)))
	defer otelx.End(span, &err)

	err = m.hardware.DeleteKeySet(ctx, set)
	switch {
	case err == nil:
		m.invalidate(set)
		return nil
	case errors.Is(err, x.ErrNotFound):
		if err := m.software.DeleteKeySet(ctx, set); err != nil {
			return err
		}
		m.invalidate(set)
		return nil
	default:
		return err
	}
}

// Close retires all published views once their active signing operations
// complete. It must not, and does not, close or delete anything on the
// caller-provided backend managers: their lifecycle belongs to the registry.
func (m *CompositeManager) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		views := make([]*CompositeKeyView, 0, len(m.views))
		for _, view := range m.views {
			views = append(views, view)
		}
		m.views = map[string]*CompositeKeyView{}
		m.stale = map[string]bool{}
		m.staleSeq = map[string]uint64{}
		m.mu.Unlock()

		for _, view := range views {
			view.retire()
		}
	})
	return nil
}

var (
	_ Manager = (*CompositeManager)(nil)
)
