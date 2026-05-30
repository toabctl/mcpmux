// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// fakeClock is a manually-advanced clock for deterministic expiry tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

// newTestSource builds an ExecTokenSource whose runner and clock are injected.
func newTestSource(clock *fakeClock, run runnerFunc) *ExecTokenSource {
	s := NewExecTokenSource(context.Background(), []string{"helper"}, time.Minute)
	s.runner = run
	s.now = clock.now
	return s
}

func TestExecTokenSource_CachesUntilExpiry(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	calls := 0
	s := newTestSource(clock, func(context.Context, []string) ([]byte, error) {
		calls++
		return []byte("opaque-token\n"), nil // not a JWT -> uses ttl (1m)
	})

	tok, err := s.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken != "opaque-token" {
		t.Errorf("AccessToken = %q, want trimmed %q", tok.AccessToken, "opaque-token")
	}

	// Within ttl-leeway: served from cache.
	clock.add(20 * time.Second)
	if _, err := s.Token(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 exec while cached, got %d", calls)
	}

	// Past expiry-leeway (1m ttl, 30s leeway): re-runs.
	clock.add(40 * time.Second)
	if _, err := s.Token(); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected re-exec after expiry, got %d calls", calls)
	}
}

func TestExecTokenSource_JWTExpiryWins(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	exp := clock.t.Add(2 * time.Hour).Unix()
	s := newTestSource(clock, func(context.Context, []string) ([]byte, error) {
		return []byte(makeJWT(exp)), nil
	})

	tok, err := s.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got := tok.Expiry.Unix(); got != exp {
		t.Errorf("Expiry = %d, want JWT exp %d", got, exp)
	}
}

func TestExecTokenSource_Invalidate(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	calls := 0
	s := newTestSource(clock, func(context.Context, []string) ([]byte, error) {
		calls++
		return []byte(makeJWT(clock.t.Add(time.Hour).Unix())), nil
	})

	if _, err := s.Token(); err != nil {
		t.Fatal(err)
	}
	s.Invalidate()
	if _, err := s.Token(); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("Invalidate should force re-exec; got %d calls", calls)
	}
}

func TestExecTokenSource_Errors(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}

	failing := newTestSource(clock, func(context.Context, []string) ([]byte, error) {
		return nil, errors.New("boom")
	})
	if _, err := failing.Token(); err == nil {
		t.Error("expected error when command fails")
	}

	empty := newTestSource(clock, func(context.Context, []string) ([]byte, error) {
		return []byte("   \n"), nil
	})
	if _, err := empty.Token(); err == nil {
		t.Error("expected error on empty output")
	}
}

func TestExecHandler_AuthorizeRefreshes(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	calls := 0
	s := newTestSource(clock, func(context.Context, []string) ([]byte, error) {
		calls++
		return []byte(fmt.Sprintf("token-%d", calls)), nil
	})
	h := NewExecHandler(s)

	if _, err := s.Token(); err != nil {
		t.Fatal(err)
	}
	// Authorize (simulating a 401) must invalidate and re-mint.
	if err := h.Authorize(context.Background(), nil, nil); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	tok, _ := s.Token()
	if tok.AccessToken != "token-2" {
		t.Errorf("after Authorize, token = %q, want token-2", tok.AccessToken)
	}
}

// makeJWT builds an unsigned JWT-shaped string with the given exp claim.
func makeJWT(exp int64) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	body, _ := json.Marshal(struct {
		Exp int64 `json:"exp"`
	}{Exp: exp})
	return hdr + "." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}
