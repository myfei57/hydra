// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk

import (
	"context"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite/token/jwt"
)

// CompositeJWTSigner signs JWTs through a CompositeManager. Every token binds
// to one published CompositeKeyView generation: the kid reported by
// GetPublicKeyID, the kid placed in the JWT header, the key that performs the
// actual signature, and the public JWKS entry all describe the same selected
// key and its owning backend. If that owner cannot produce the pinned material
// at signing time, signing fails; the signer never retries with another
// backend or another generation's material.
type CompositeJWTSigner struct {
	*jwt.DefaultSigner
	m     *CompositeManager
	setID string
}

// NewCompositeJWTSigner creates a signer bound to setID on the given
// composite manager.
func NewCompositeJWTSigner(m *CompositeManager, setID string) *CompositeJWTSigner {
	s := &CompositeJWTSigner{m: m, setID: setID, DefaultSigner: &jwt.DefaultSigner{}}
	s.DefaultSigner.GetPrivateKey = s.getPrivateKey
	return s
}

// SetID returns the key set this signer is bound to.
func (s *CompositeJWTSigner) SetID() string { return s.setID }

func (s *CompositeJWTSigner) currentView(ctx context.Context) (*CompositeKeyView, error) {
	return s.m.EnsureView(ctx, s.setID)
}

// GetPublicKeyID returns the kid of the selected key in the current
// generation. It is the same kid that the next signature puts in its JWT
// header.
func (s *CompositeJWTSigner) GetPublicKeyID(ctx context.Context) (string, error) {
	view, err := s.currentView(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return view.SelectedKey().KID(), nil
}

// GetPublicKey returns the public JWK of the selected key in the current
// generation. It contains public material only.
func (s *CompositeJWTSigner) GetPublicKey(ctx context.Context) (jose.JSONWebKey, error) {
	view, err := s.currentView(ctx)
	if err != nil {
		return jose.JSONWebKey{}, errors.WithStack(err)
	}
	return view.SelectedKey().Public(), nil
}

// getPrivateKey resolves the signing material through the selected key's
// pinned owner while holding a reference on the view generation. A new
// generation published concurrently cannot retire this view until the
// signature completes, and an owner failure is propagated instead of falling
// back to a different key.
func (s *CompositeJWTSigner) getPrivateKey(ctx context.Context) (any, error) {
	view, err := s.currentView(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	entry := view.SelectedKey()
	var key *jose.JSONWebKey
	if err := s.m.useView(view, func() error {
		var signErr error
		key, signErr = entry.signer.signingKey(ctx)
		return signErr
	}); err != nil {
		return nil, errors.WithStack(err)
	}
	return key, nil
}

var _ JWTSigner = (*CompositeJWTSigner)(nil)
