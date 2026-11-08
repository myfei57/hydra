// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/cryptosigner"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/fosite/token/jwt"
	"github.com/ory/hydra/v2/jwk"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/josex"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeBackend is an in-memory key Manager that can play either role. Hardware
// keys are stored through cryptosigner.Opaque, exactly like the HSM manager
// does, so the composite only ever sees an opaque signer for them. It also
// implements the optional snapshot protocol.
type fakeBackend struct {
	backend jwk.Backend

	mu       sync.RWMutex
	sets     map[string][]jose.JSONWebKey
	revision uint64

	getKeySetErr error
	getKeyErr    error
	deleteErr    error
	// getKeyBlock, when non-nil, makes every GetKey call wait until the
	// channel is closed. Tests use it to hold a signing operation mid-flight.
	getKeyBlock chan struct{}
	// getKeySetBlock does the same for GetKeySet / SnapshotKeySet reads,
	// allowing a build to be held mid-flight.
	getKeySetBlock chan struct{}

	getKeySetCalls int
	getKeyCalls    int

	generated int
	added     int
	updated   int
	deleted   int
	closed    bool
}

func newFakeBackend(backend jwk.Backend) *fakeBackend {
	return &fakeBackend{backend: backend, sets: map[string][]jose.JSONWebKey{}}
}

func (b *fakeBackend) bump() {
	b.revision++
}

func (b *fakeBackend) put(set string, keys ...jose.JSONWebKey) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sets[set] = append(b.sets[set], keys...)
	b.bump()
}

func (b *fakeBackend) replace(set string, keys ...jose.JSONWebKey) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sets[set] = keys
	b.bump()
}

func (b *fakeBackend) remove(set, kid string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	existing := b.sets[set]
	kept := existing[:0]
	for _, key := range existing {
		if key.KeyID != kid {
			kept = append(kept, key)
		}
	}
	b.sets[set] = kept
	b.bump()
}

func (b *fakeBackend) snapshotKeysLocked(set string) ([]jose.JSONWebKey, bool) {
	keys, ok := b.sets[set]
	if !ok || len(keys) == 0 {
		return nil, false
	}
	// Struct copies decouple the snapshot from later slice mutations. The
	// inner key pointers are treated as immutable; replacements create new
	// structs.
	out := make([]jose.JSONWebKey, len(keys))
	copy(out, keys)
	return out, true
}

func (b *fakeBackend) GenerateAndPersistKeySet(_ context.Context, set, kid, alg, use string) (*jose.JSONWebKeySet, error) {
	key, err := newSoftwareKey(alg, kid, use)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.generated++
	b.sets[set] = append(b.sets[set], *key)
	b.bump()
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*key}}, nil
}

func (b *fakeBackend) AddKey(_ context.Context, set string, key *jose.JSONWebKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.added++
	b.sets[set] = append(b.sets[set], *key)
	b.bump()
	return nil
}

func (b *fakeBackend) AddKeySet(_ context.Context, set string, keys *jose.JSONWebKeySet) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.added++
	b.sets[set] = append(b.sets[set], keys.Keys...)
	b.bump()
	return nil
}

func (b *fakeBackend) UpdateKey(_ context.Context, set string, key *jose.JSONWebKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.updated++
	existing := b.sets[set]
	for i := range existing {
		if existing[i].KeyID == key.KeyID {
			existing[i] = *key
			b.bump()
			return nil
		}
	}
	b.sets[set] = append(existing, *key)
	b.bump()
	return nil
}

func (b *fakeBackend) UpdateKeySet(_ context.Context, set string, keys *jose.JSONWebKeySet) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.updated++
	b.sets[set] = append([]jose.JSONWebKey(nil), keys.Keys...)
	b.bump()
	return nil
}

func (b *fakeBackend) GetKey(_ context.Context, set, kid string) (*jose.JSONWebKeySet, error) {
	// Count the attempt before blocking so tests can wait for an in-flight
	// sign to reach the backend.
	b.mu.Lock()
	b.getKeyCalls++
	b.mu.Unlock()

	if b.getKeyBlock != nil {
		<-b.getKeyBlock
	}

	b.mu.Lock()
	err := b.getKeyErr
	keys, ok := b.snapshotKeysLocked(set)
	b.mu.Unlock()

	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errorsWithNotFound()
	}
	for _, key := range keys {
		if key.KeyID == kid {
			return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}, nil
		}
	}
	return nil, errorsWithNotFound()
}

func (b *fakeBackend) GetKeySet(ctx context.Context, set string) (*jose.JSONWebKeySet, error) {
	b.mu.Lock()
	b.getKeySetCalls++
	block := b.getKeySetBlock
	b.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	b.mu.Lock()
	err := b.getKeySetErr
	keys, ok := b.snapshotKeysLocked(set)
	b.mu.Unlock()

	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errorsWithNotFound()
	}
	return &jose.JSONWebKeySet{Keys: keys}, nil
}

func (b *fakeBackend) DeleteKey(_ context.Context, set, kid string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.deleteErr != nil {
		return b.deleteErr
	}
	b.deleted++
	if _, ok := b.sets[set]; !ok {
		return errorsWithNotFound()
	}
	kept := b.sets[set][:0]
	found := false
	for _, key := range b.sets[set] {
		if key.KeyID == kid {
			found = true
			continue
		}
		kept = append(kept, key)
	}
	if !found {
		return errorsWithNotFound()
	}
	b.sets[set] = kept
	b.bump()
	return nil
}

func (b *fakeBackend) DeleteKeySet(_ context.Context, set string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deleted++
	if _, ok := b.sets[set]; !ok {
		return errorsWithNotFound()
	}
	delete(b.sets, set)
	b.bump()
	return nil
}

// SnapshotKeySet implements jwk.SnapshotManager.
func (b *fakeBackend) SnapshotKeySet(_ context.Context, set string) (jwk.KeySetSnapshot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	keys, ok := b.snapshotKeysLocked(set)
	if !ok {
		return jwk.KeySetSnapshot{}, errorsWithNotFound()
	}
	return jwk.KeySetSnapshot{
		Revision: jwk.KeySetRevision{Backend: b.backend, Value: hex.EncodeToString([]byte{byte(b.revision)})},
		KeySet:   &jose.JSONWebKeySet{Keys: keys},
	}, nil
}

// Close exists to prove the composite manager never closes caller-owned
// backends. It is not part of jwk.Manager.
func (b *fakeBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

func (b *fakeBackend) isClosed() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.closed
}

func (b *fakeBackend) revisionValue() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.revision
}

// plainManager exposes only the Manager methods, hiding the snapshot
// protocol even though the embedded fake implements it.
type plainManager struct {
	jwk.Manager
}

// failingOpaqueSigner behaves like an HSM handle whose signing operation
// fails. It never exposes private bytes.
type failingOpaqueSigner struct {
	public  *jose.JSONWebKey
	signErr error
}

func (f *failingOpaqueSigner) Public() *jose.JSONWebKey { return f.public }
func (f *failingOpaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}
func (f *failingOpaqueSigner) SignPayload(_ []byte, _ jose.SignatureAlgorithm) ([]byte, error) {
	return nil, f.signErr
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

func newSoftwareKey(alg, kid, use string) (*jose.JSONWebKey, error) {
	var key crypto.Signer
	switch alg {
	case "RS256":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		key = priv
	case "ES256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		key = priv
	default:
		return nil, fmt.Errorf("unsupported test alg %q", alg)
	}
	return &jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: alg, Use: use}, nil
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func mustECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func mustSoftwareJWK(t *testing.T, alg, kid, use string) *jose.JSONWebKey {
	t.Helper()
	var key crypto.Signer
	switch alg {
	case "RS256":
		key = mustRSAKey(t)
	case "ES256":
		key = mustECKey(t)
	default:
		t.Fatalf("unsupported test alg %q", alg)
	}
	return &jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: alg, Use: use}
}

func opaqueJWK(t *testing.T, signer crypto.Signer, alg, kid, use string) jose.JSONWebKey {
	t.Helper()
	return jose.JSONWebKey{
		Key:       cryptosigner.Opaque(signer),
		KeyID:     kid,
		Algorithm: alg,
		Use:       use,
	}
}

func thumbprintOf(t *testing.T, key *jose.JSONWebKey) string {
	t.Helper()
	pub := josex.ToPublicKey(key)
	raw, err := pub.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	return hex.EncodeToString(raw)
}

func errorsWithNotFound() error {
	// Wrapping mirrors production call sites (errors.WithStack) while keeping
	// errors.Is(err, x.ErrNotFound) working through the Unwrap chain.
	return fmt.Errorf("fake backend: %w", x.ErrNotFound)
}

func assertRetired(t *testing.T, view *jwk.CompositeKeyView, timeout time.Duration) {
	t.Helper()
	select {
	case <-view.Retired():
	case <-time.After(timeout):
		t.Fatalf("view generation %d was not retired within %s", view.Generation(), timeout)
	}
}

func assertNotRetired(t *testing.T, view *jwk.CompositeKeyView) {
	t.Helper()
	select {
	case <-view.Retired():
		t.Fatalf("view generation %d was retired while still active", view.Generation())
	default:
	}
}

// assertPublicOnlyJWKS marshals the public view and proves that no private or
// symmetric key field, and no opaque handle, can reach a public reader.
func assertPublicOnlyJWKS(t *testing.T, view *jwk.CompositeKeyView) {
	t.Helper()

	for _, entry := range view.Keys() {
		switch entry.Public().Key.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
		default:
			t.Fatalf("view key %q exposes non-public key type %T", entry.KID(), entry.Public().Key)
		}
	}

	raw, err := json.Marshal(view.PublicKeySet())
	require.NoError(t, err)

	var decoded struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.NotEmpty(t, decoded.Keys)

	privateFields := []string{"d", "p", "q", "dp", "dq", "qi", "k"}
	for _, key := range decoded.Keys {
		for _, field := range privateFields {
			if _, ok := key[field]; ok {
				t.Fatalf("public JWKS contains private field %q: %s", field, string(raw))
			}
		}
	}
}

func signAndParse(t *testing.T, signer *jwk.CompositeJWTSigner, kid string) string {
	t.Helper()
	headers := jwt.NewHeaders()
	headers.Add("kid", kid)
	raw, _, err := signer.Generate(context.Background(), jwt.MapClaims{"foo": "bar"}, headers)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	return raw
}

func assertVerifies(t *testing.T, raw string, public jose.JSONWebKey) {
	t.Helper()
	parsed, err := josejwt.ParseSigned(raw)
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, parsed.Claims(public.Key, &claims))
	assert.Equal(t, "bar", claims["foo"])
}

func assertRejects(t *testing.T, raw string, public jose.JSONWebKey) {
	t.Helper()
	parsed, err := josejwt.ParseSigned(raw)
	require.NoError(t, err)
	var claims map[string]any
	err = parsed.Claims(public.Key, &claims)
	assert.Error(t, err, "token must not verify against foreign generation key")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCompositeManager_MixedHardwareAndSoftwareKeys(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)

	ecKey := mustECKey(t)
	hw.put("set-1", opaqueJWK(t, ecKey, "ES256", "hw-key", "sig"))
	rsaKey := mustRSAKey(t)
	sw.put("set-1", *mustSoftwareJWKWith(t, rsaKey, "RS256", "sw-key", "sig"))

	view, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), view.Generation())
	assert.Len(t, view.Digest(), 64)
	require.Len(t, view.Keys(), 2)

	hwEntry, ok := view.Key("hw-key")
	require.True(t, ok)
	assert.Equal(t, jwk.BackendHardware, hwEntry.Owner())
	swEntry, ok := view.Key("sw-key")
	require.True(t, ok)
	assert.Equal(t, jwk.BackendSoftware, swEntry.Owner())

	// Thumbprints match the underlying public material directly.
	hwPublic := josex.ToPublicKey(&hw.sets["set-1"][0])
	hwTP, err := hwPublic.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(hwTP), hwEntry.Thumbprint())

	// The public view never carries private or opaque material.
	assertPublicOnlyJWKS(t, view)

	// Repeated reads return the same immutable view and never rotate.
	again, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assert.Same(t, view, again)
	assert.Equal(t, view.Digest(), again.Digest())

	// The Manager interface still yields signing material: opaque for the
	// hardware key, the exportable private key transiently for software.
	merged, err := m.GetKeySet(context.Background(), "set-1")
	require.NoError(t, err)
	privateKey, err := jwk.FindPrivateKey(merged)
	require.NoError(t, err)
	assert.False(t, privateKey.IsPublic())

	hwOnly, err := m.GetKey(context.Background(), "set-1", "hw-key")
	require.NoError(t, err)
	require.Len(t, hwOnly.Keys, 1)
	_, isOpaque := hwOnly.Keys[0].Key.(jose.OpaqueSigner)
	assert.True(t, isOpaque)

	_, err = m.GetKey(context.Background(), "set-1", "missing")
	assert.ErrorIs(t, err, x.ErrNotFound)
}

func mustSoftwareJWKWith(t *testing.T, key crypto.Signer, alg, kid, use string) *jose.JSONWebKey {
	t.Helper()
	return &jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: alg, Use: use}
}

func TestCompositeManager_SameKidIdenticalMaterialIsDeduplicated(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)

	rsaKey := mustRSAKey(t)
	sw.put("set-1", jose.JSONWebKey{Key: rsaKey, KeyID: "shared", Algorithm: "RS256", Use: "sig"})
	hw.put("set-1", opaqueJWK(t, rsaKey, "RS256", "shared", "sig"))

	view, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	require.Len(t, view.Keys(), 1, "identical kid and material must deduplicate")
	entry := view.Keys()[0]
	assert.Equal(t, jwk.BackendHardware, entry.Owner(), "hardware has explicit precedence for identical material")

	// The resolved signing key stays the opaque hardware handle.
	resolved, err := m.GetKey(context.Background(), "set-1", "shared")
	require.NoError(t, err)
	_, isOpaque := resolved.Keys[0].Key.(jose.OpaqueSigner)
	assert.True(t, isOpaque)

	// Stable rebuild does not create a new generation.
	m.Invalidate("set-1")
	rebuilt, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), rebuilt.Generation())
	assert.Equal(t, view.Digest(), rebuilt.Digest())
}

func TestCompositeManager_SameKidConflictingMaterialRejectsView(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)

	// Publish a healthy first generation.
	sw.put("set-1", *mustSoftwareJWK(t, "ES256", "stable", "sig"))
	view1, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	require.Equal(t, uint64(1), view1.Generation())

	// Now both backends serve "dup" with different material.
	hw.put("set-1", opaqueJWK(t, mustECKey(t), "ES256", "dup", "sig"))
	sw.put("set-1", *mustSoftwareJWK(t, "ES256", "dup", "sig"))
	m.Invalidate("set-1")

	_, err = m.EnsureView(context.Background(), "set-1")
	assert.ErrorIs(t, err, jwk.ErrCompositeKeyConflict)

	// The old generation remains the only published, readable view; readers
	// never see a half-merged candidate containing both "dup" materials.
	current, ok := m.CurrentView("set-1")
	require.True(t, ok)
	assert.Same(t, view1, current)
	_, present := current.Key("dup")
	assert.False(t, present)

	// Same conflict, but with no previous generation: nothing is published.
	hw2, sw2 := newFakeBackend(jwk.BackendHardware), newFakeBackend(jwk.BackendSoftware)
	m2 := jwk.NewCompositeManager(hw2, sw2)
	hw2.put("set-2", opaqueJWK(t, mustECKey(t), "ES256", "dup", "sig"))
	sw2.put("set-2", *mustSoftwareJWK(t, "ES256", "dup", "sig"))
	_, err = m2.EnsureView(context.Background(), "set-2")
	assert.ErrorIs(t, err, jwk.ErrCompositeKeyConflict)
	_, ok = m2.CurrentView("set-2")
	assert.False(t, ok)
}

func TestCompositeManager_AlgOrUseMismatchAlsoConflicts(t *testing.T) {
	t.Parallel()
	rsaKey := mustRSAKey(t)

	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)
	hw.put("set-1", opaqueJWK(t, rsaKey, "RS256", "shared", "sig"))
	sw.put("set-1", jose.JSONWebKey{Key: rsaKey, KeyID: "shared", Algorithm: "RS512", Use: "sig"})

	_, err := m.EnsureView(context.Background(), "set-1")
	assert.ErrorIs(t, err, jwk.ErrCompositeKeyConflict)
}

func TestCompositeManager_BackendErrorIsNotNotFound(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)

	// A real hardware failure must surface as an error, never as an empty or
	// software-only view.
	hw.getKeySetErr = errors.New("hsm unreachable")
	_, err := m.EnsureView(context.Background(), "set-1")
	require.Error(t, err)
	assert.NotErrorIs(t, err, x.ErrNotFound)
	assert.Contains(t, err.Error(), "hsm unreachable")
	_, ok := m.CurrentView("set-1")
	assert.False(t, ok)
	hw.getKeySetErr = nil

	// Software failure is handled the same way.
	hw.put("set-1", opaqueJWK(t, mustECKey(t), "ES256", "hw-key", "sig"))
	sw.getKeySetErr = errors.New("database down")
	_, err = m.EnsureView(context.Background(), "set-1")
	require.Error(t, err)
	assert.NotErrorIs(t, err, x.ErrNotFound)
	assert.Contains(t, err.Error(), "database down")
	sw.getKeySetErr = nil

	// Genuine hardware NotFound falls through to the software backend.
	view, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	entry, ok := view.Key("hw-key")
	require.True(t, ok)
	assert.Equal(t, jwk.BackendHardware, entry.Owner())

	// Both backends genuinely missing -> NotFound.
	_, err = m.EnsureView(context.Background(), "does-not-exist")
	assert.ErrorIs(t, err, x.ErrNotFound)
}

func TestCompositeManager_EventualModeWorksWithoutSnapshotProtocol(t *testing.T) {
	t.Parallel()
	hwFake, swFake := newFakeBackend(jwk.BackendHardware), newFakeBackend(jwk.BackendSoftware)
	hw := &plainManager{Manager: hwFake}
	sw := &plainManager{Manager: swFake}
	m := jwk.NewCompositeManager(hw, sw) // default: eventual

	swFake.put("set-1", *mustSoftwareJWK(t, "RS256", "sw-key", "sig"))
	view, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assert.Empty(t, view.Revisions(), "eventual reads must not claim pinned revisions")
}

func TestCompositeManager_StrictModeRequiresSnapshotProtocol(t *testing.T) {
	t.Parallel()
	hw := &plainManager{Manager: newFakeBackend(jwk.BackendHardware)}
	sw := &plainManager{Manager: newFakeBackend(jwk.BackendSoftware)}
	m := jwk.NewCompositeManager(hw, sw, jwk.WithStrictConsistency())

	_, err := m.EnsureView(context.Background(), "set-1")
	assert.ErrorIs(t, err, jwk.ErrSnapshotUnsupported)
}

func TestCompositeManager_StrictModePinsRevisions(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw, jwk.WithStrictConsistency())

	hw.put("set-1", opaqueJWK(t, mustECKey(t), "ES256", "hw-key", "sig"))
	sw.put("set-1", *mustSoftwareJWK(t, "RS256", "sw-key", "sig"))

	view, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	revisions := view.Revisions()
	require.Len(t, revisions, 2)
	owners := map[jwk.Backend]string{}
	for _, revision := range revisions {
		owners[revision.Backend] = revision.Value
		require.NotEmpty(t, revision.Value)
	}
	assert.Contains(t, owners, jwk.BackendHardware)
	assert.Contains(t, owners, jwk.BackendSoftware)

	// A snapshot stays pinned even when the backend mutates afterwards.
	snapshot, err := hw.SnapshotKeySet(context.Background(), "set-1")
	require.NoError(t, err)
	require.Len(t, snapshot.KeySet.Keys, 1)
	revisionBefore := hw.revisionValue()
	hw.put("set-1", opaqueJWK(t, mustECKey(t), "ES256", "hw-key-2", "sig"))
	require.Len(t, snapshot.KeySet.Keys, 1, "pinned snapshot must not observe later mutations")
	assert.Greater(t, hw.revisionValue(), revisionBefore, "mutation must advance the backend revision")

	// The published view is immutable and still shows the original content.
	assert.Len(t, view.Keys(), 2)
}

func TestCompositeManager_ConfigChangePublishesNewGeneration(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)

	sw.put("set-1", *mustSoftwareJWK(t, "RS256", "key-a", "sig"))
	view1, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), view1.Generation())

	// Backend reconfiguration adds a key: a new generation with a new digest
	// is published, and the old one is retired after references drain.
	sw.put("set-1", *mustSoftwareJWK(t, "ES256", "key-b", "sig"))
	m.Invalidate("set-1")
	view2, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assert.Equal(t, uint64(2), view2.Generation())
	assert.NotEqual(t, view1.Digest(), view2.Digest())
	assert.Len(t, view2.Keys(), 2)
	assertRetired(t, view1, time.Second)

	// Unchanged rebuild keeps the generation and digest.
	m.Invalidate("set-1")
	again, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assert.Same(t, view2, again)

	// Removing material creates another generation.
	sw.remove("set-1", "key-b")
	m.Invalidate("set-1")
	view3, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assert.Equal(t, uint64(3), view3.Generation())
	assert.Len(t, view3.Keys(), 1)
	assertRetired(t, view2, time.Second)
}

func TestCompositeManager_InvalidationDuringBuildRebuildsCandidate(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)

	sw.put("set-1", *mustSoftwareJWK(t, "RS256", "key-a", "sig"))
	view1, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	require.Len(t, view1.Keys(), 1)

	m.Invalidate("set-1")
	block := make(chan struct{})
	sw.getKeySetBlock = block

	type buildResult struct {
		view *jwk.CompositeKeyView
		err  error
	}
	done := make(chan buildResult, 1)
	go func() {
		v, err := m.EnsureView(context.Background(), "set-1")
		done <- buildResult{view: v, err: err}
	}()

	require.Eventually(t, func() bool {
		sw.mu.RLock()
		defer sw.mu.RUnlock()
		return sw.getKeySetCalls >= 1
	}, time.Second, 5*time.Millisecond)

	// Commit another change while the candidate build is blocked on the
	// software backend, then invalidate again.
	sw.put("set-1", *mustSoftwareJWK(t, "ES256", "key-b", "sig"))
	m.Invalidate("set-1")
	close(block)

	select {
	case res := <-done:
		require.NoError(t, res.err)
		assert.Len(t, res.view.Keys(), 2, "the published generation must not miss the change committed during the build")
		_, hasA := res.view.Key("key-a")
		_, hasB := res.view.Key("key-b")
		assert.True(t, hasA)
		assert.True(t, hasB)
		assert.Equal(t, uint64(2), res.view.Generation())
	case <-time.After(5 * time.Second):
		t.Fatal("rebuild after in-flight invalidation did not complete")
	}

	sw.mu.RLock()
	assert.GreaterOrEqual(t, sw.getKeySetCalls, 2, "the stale candidate must have triggered a rebuild")
	sw.mu.RUnlock()
}

func TestCompositeJWTSigner_BindsGenerationAndVerifiesWithJose(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)

	ecKey := mustECKey(t)
	hw.put("set-1", opaqueJWK(t, ecKey, "ES256", "hw-sign", "sig"))
	sw.put("set-1", *mustSoftwareJWK(t, "RS256", "sw-sign", "sig"))

	signer := jwk.NewCompositeJWTSigner(m, "set-1")
	view1, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assert.Equal(t, "hw-sign", view1.SelectedKey().KID())

	kid, err := signer.GetPublicKeyID(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "hw-sign", kid)

	pub, err := signer.GetPublicKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "hw-sign", pub.KeyID)
	assert.Equal(t, view1.SelectedKey().Thumbprint(), thumbprintOf(t, &pub))

	raw1 := signAndParse(t, signer, kid)

	// The JWT header kid is bound to the same selected key.
	parsed, err := josejwt.ParseSigned(raw1)
	require.NoError(t, err)
	require.Len(t, parsed.Headers, 1)
	assert.Equal(t, "hw-sign", parsed.Headers[0].KeyID)

	// The token verifies only with the public key of the same generation.
	hwPublic1 := view1.PublicKeySet().Keys[0]
	swPublic := view1.PublicKeySet().Keys[1]
	assertVerifies(t, raw1, hwPublic1)
	assertRejects(t, raw1, swPublic)

	// Rotate the hardware material behind the same kid and publish a new
	// generation. The old generation stays usable for tokens already issued.
	newEC := mustECKey(t)
	hw.replace("set-1", opaqueJWK(t, newEC, "ES256", "hw-sign", "sig"))
	m.Invalidate("set-1")
	view2, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assert.Equal(t, uint64(2), view2.Generation())

	kid2, err := signer.GetPublicKeyID(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "hw-sign", kid2)
	raw2 := signAndParse(t, signer, kid2)

	hwPublic2, ok := view2.Key("hw-sign")
	require.True(t, ok)
	assertVerifies(t, raw2, hwPublic2.Public())
	assertRejects(t, raw2, hwPublic1)
	assertRejects(t, raw1, hwPublic2.Public())
	// The old token still verifies against the retained old generation.
	assertVerifies(t, raw1, hwPublic1)

	assertPublicOnlyJWKS(t, view2)
}

func TestCompositeJWTSigner_NeverFallsBackAfterOwnerFailure(t *testing.T) {
	t.Parallel()

	t.Run("software owner failure does not reach hardware", func(t *testing.T) {
		hw := newFakeBackend(jwk.BackendHardware)
		sw := newFakeBackend(jwk.BackendSoftware)
		m := jwk.NewCompositeManager(hw, sw)
		sw.put("set-1", *mustSoftwareJWK(t, "RS256", "sw-only", "sig"))

		signer := jwk.NewCompositeJWTSigner(m, "set-1")
		_, err := m.EnsureView(context.Background(), "set-1")
		require.NoError(t, err)

		hw.getKeySetCalls = 0
		hw.getKeyCalls = 0
		sw.getKeyErr = errors.New("database unavailable")

		_, _, err = signer.Generate(context.Background(), jwt.MapClaims{}, jwt.NewHeaders())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database unavailable")
		assert.Zero(t, hw.getKeySetCalls)
		assert.Zero(t, hw.getKeyCalls, "hardware backend must not be used as a signing fallback")
	})

	t.Run("opaque HSM handle failure does not use software material", func(t *testing.T) {
		hw := newFakeBackend(jwk.BackendHardware)
		sw := newFakeBackend(jwk.BackendSoftware)
		m := jwk.NewCompositeManager(hw, sw)

		ecKey := mustECKey(t)
		failing := &failingOpaqueSigner{
			public:  &jose.JSONWebKey{Key: &ecKey.PublicKey},
			signErr: errors.New("pkcs11 device error"),
		}
		hw.put("set-1", jose.JSONWebKey{Key: failing, KeyID: "hw-only", Algorithm: "ES256", Use: "sig"})
		sw.put("set-1", *mustSoftwareJWK(t, "RS256", "sw-other", "sig"))

		signer := jwk.NewCompositeJWTSigner(m, "set-1")
		_, err := m.EnsureView(context.Background(), "set-1")
		require.NoError(t, err)

		sw.getKeySetCalls = 0
		sw.getKeyCalls = 0
		_, _, err = signer.Generate(context.Background(), jwt.MapClaims{}, jwt.NewHeaders())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pkcs11 device error")
		assert.Zero(t, sw.getKeyCalls, "software backend must never replace a failing HSM signer")
	})

	t.Run("backend material swap is detected instead of signed", func(t *testing.T) {
		hw := newFakeBackend(jwk.BackendHardware)
		sw := newFakeBackend(jwk.BackendSoftware)
		m := jwk.NewCompositeManager(hw, sw)
		original := mustSoftwareJWK(t, "RS256", "sw-key", "sig")
		sw.put("set-1", *original)

		signer := jwk.NewCompositeJWTSigner(m, "set-1")
		view, err := m.EnsureView(context.Background(), "set-1")
		require.NoError(t, err)

		// The backend now serves different private material under the same kid
		// without a new published generation. The pinned thumbprint guard must
		// reject it.
		swrapped := *mustSoftwareJWK(t, "RS256", "sw-key", "sig")
		sw.replace("set-1", swrapped)

		_, _, err = signer.Generate(context.Background(), jwt.MapClaims{}, jwt.NewHeaders())
		require.Error(t, err)
		assert.ErrorIs(t, err, jwk.ErrCompositeKeyConflict)
		assert.Same(t, view, mustCurrent(t, m, "set-1"))
	})
}

func mustCurrent(t *testing.T, m *jwk.CompositeManager, set string) *jwk.CompositeKeyView {
	t.Helper()
	v, ok := m.CurrentView(set)
	require.True(t, ok)
	return v
}

func TestCompositeManager_PublishDuringSigningKeepsOldGenerationAlive(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)

	sw.put("set-1", *mustSoftwareJWK(t, "RS256", "k1", "sig"))
	signer := jwk.NewCompositeJWTSigner(m, "set-1")
	view1, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)

	block := make(chan struct{})
	sw.getKeyBlock = block

	type result struct {
		raw string
		err error
	}
	done := make(chan result, 1)
	go func() {
		raw, _, err := signer.Generate(context.Background(), jwt.MapClaims{"foo": "bar"}, jwt.NewHeaders())
		done <- result{raw: raw, err: err}
	}()

	require.Eventually(t, func() bool {
		sw.mu.RLock()
		defer sw.mu.RUnlock()
		return sw.getKeyCalls == 1
	}, time.Second, 5*time.Millisecond)
	assertNotRetired(t, view1)

	// Reconfigure while the signature is in flight: the new selection is k0.
	sw.put("set-1", *mustSoftwareJWK(t, "ES256", "k0", "sig"))
	m.Invalidate("set-1")
	view2, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assert.NotSame(t, view1, view2)
	assert.Equal(t, "k0", view2.SelectedKey().KID())
	assertNotRetired(t, view1)

	close(block)
	select {
	case res := <-done:
		require.NoError(t, res.err)
		parsed, err := josejwt.ParseSigned(res.raw)
		require.NoError(t, err)
		assert.Equal(t, "k1", parsed.Headers[0].KeyID, "the in-flight signature binds to the old generation key")
		oldPublic, ok := view1.Key("k1")
		require.True(t, ok)
		assertVerifies(t, res.raw, oldPublic.Public())
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight signature did not complete")
	}
	assertRetired(t, view1, time.Second)

	// Subsequent signatures use the new generation.
	raw := signAndParse(t, signer, "k0")
	parsed, err := josejwt.ParseSigned(raw)
	require.NoError(t, err)
	assert.Equal(t, "k0", parsed.Headers[0].KeyID)
	newPublic, ok := view2.Key("k0")
	require.True(t, ok)
	assertVerifies(t, raw, newPublic.Public())
}

func TestCompositeManager_CloseDoesNotCloseCallerManagers(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)
	hw.put("set-1", opaqueJWK(t, mustECKey(t), "ES256", "hw-key", "sig"))
	view, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)

	require.NoError(t, m.Close())
	assert.False(t, hw.isClosed())
	assert.False(t, sw.isClosed())
	assertRetired(t, view, time.Second)

	_, err = m.GetKeySet(context.Background(), "set-1")
	assert.ErrorIs(t, err, jwk.ErrCompositeManagerClosed)
	_, err = m.EnsureView(context.Background(), "set-1")
	assert.ErrorIs(t, err, jwk.ErrCompositeManagerClosed)
}

func TestCompositeManager_WriteRoutingMatchesManagerStrategy(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)
	ctx := context.Background()

	// Generation always goes to hardware.
	_, err := m.GenerateAndPersistKeySet(ctx, "set-1", "kid", "RS256", "sig")
	require.NoError(t, err)
	assert.Equal(t, 1, hw.generated)
	assert.Zero(t, sw.generated)

	// Software writes go to software.
	require.NoError(t, m.AddKey(ctx, "set-1", mustSoftwareJWK(t, "RS256", "a", "sig")))
	require.NoError(t, m.AddKeySet(ctx, "set-1", &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*mustSoftwareJWK(t, "ES256", "b", "sig")}}))
	require.NoError(t, m.UpdateKey(ctx, "set-1", mustSoftwareJWK(t, "RS256", "a", "sig")))
	require.NoError(t, m.UpdateKeySet(ctx, "set-1", &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*mustSoftwareJWK(t, "ES256", "c", "sig")}}))
	assert.Equal(t, 4, sw.added+sw.updated)
	assert.Zero(t, hw.added+hw.updated)

	// Delete: hardware success stops there.
	require.NoError(t, m.DeleteKeySet(ctx, "set-1"))
	assert.Equal(t, 1, hw.deleted)
	sw.deleted = 0

	// Delete: genuine hardware NotFound falls through to software. The
	// software set still holds "c" after the UpdateKeySet call above.
	require.NoError(t, m.DeleteKey(ctx, "set-1", "c"))
	assert.Equal(t, 1, sw.deleted)

	// Delete: hardware error is returned, software is not touched.
	hwDeletedBefore := hw.deleted
	hw.deleteErr = errors.New("hsm delete failed")
	err = m.DeleteKey(ctx, "set-1", "kid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hsm delete failed")
	assert.Equal(t, hwDeletedBefore, hw.deleted)
	assert.Equal(t, 1, sw.deleted, "software must not be consulted on a hardware error")
	hw.deleteErr = nil
}

func TestCompositeManager_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)
	signer := jwk.NewCompositeJWTSigner(m, "set-1")
	ctx := context.Background()

	sw.put("set-1", *mustSoftwareJWK(t, "RS256", "initial", "sig"))

	const workers = 8
	const rounds = 20
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for round := 0; round < rounds; round++ {
				view, err := m.EnsureView(ctx, "set-1")
				if !assert.NoError(t, err) {
					return
				}
				if _, err := m.GetKeySet(ctx, "set-1"); !assert.NoError(t, err) {
					return
				}
				raw, _, err := signer.Generate(ctx, jwt.MapClaims{"round": round}, jwt.NewHeaders())
				if !assert.NoError(t, err) {
					return
				}
				public := view.SelectedKey().Public()
				parsed, err := josejwt.ParseSigned(raw)
				if !assert.NoError(t, err) {
					return
				}
				var claims map[string]any
				if !assert.NoError(t, parsed.Claims(public.Key, &claims)) {
					return
				}
				if round%5 == 0 && worker == 0 {
					// Unique kids keep rotations conflict-free; the composite
					// still republishes a new generation for each change.
					sw.put("set-1", *mustSoftwareJWK(t, "ES256", fmt.Sprintf("rotated-%d", round), "sig"))
					m.Invalidate("set-1")
				}
			}
		}(worker)
	}
	wg.Wait()

	view, err := m.EnsureView(ctx, "set-1")
	require.NoError(t, err)
	assertPublicOnlyJWKS(t, view)
}

// Guard against accidentally drifting the opaque signer interface expectations.
func TestOpaqueHandleRemainsNonExportable(t *testing.T) {
	t.Parallel()
	ecKey := mustECKey(t)
	handle := cryptosigner.Opaque(ecKey)
	pub := handle.Public()
	require.NotNil(t, pub)
	assert.IsType(t, &ecdsa.PublicKey{}, pub.Key)

	// The handle itself cannot be marshaled as a private JWK field: build a
	// view and confirm only public material is serialized.
	hw := newFakeBackend(jwk.BackendHardware)
	sw := newFakeBackend(jwk.BackendSoftware)
	m := jwk.NewCompositeManager(hw, sw)
	hw.put("set-1", jose.JSONWebKey{Key: handle, KeyID: "k", Algorithm: "ES256", Use: "sig"})
	view, err := m.EnsureView(context.Background(), "set-1")
	require.NoError(t, err)
	assertPublicOnlyJWKS(t, view)

	// Signing still works through the opaque handle, using real jose.
	signer := jwk.NewCompositeJWTSigner(m, "set-1")
	raw := signAndParse(t, signer, "k")
	entry, ok := view.Key("k")
	require.True(t, ok)
	assertVerifies(t, raw, entry.Public())
}
