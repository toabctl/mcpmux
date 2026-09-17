// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

func testStore(t *testing.T) *RuntimeStore {
	t.Helper()
	st, err := newStoreAt(filepath.Join(t.TempDir(), "mcpmux"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRuntimeStoreRoundTrip covers the absent, saved and overwritten cases, and
// that the file holding the tokens is not readable by anyone else.
func TestRuntimeStoreRoundTrip(t *testing.T) {
	st := testStore(t)

	got, err := st.Load("linear")
	if err != nil {
		t.Fatalf("Load on empty store: %v", err)
	}
	if got != nil {
		t.Errorf("Load on empty store = %v, want nil", got)
	}

	want := &Credential{
		ClientID:     "cid",
		ClientSecret: "secret",
		TokenURL:     "https://as.example/token",
		AuthStyle:    int(oauth2.AuthStyleInParams),
		Scopes:       []string{"read", "offline_access"},
		AccessToken:  "at",
		RefreshToken: "rt",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour).UTC().Truncate(time.Second),
	}
	if err := st.Save("linear", want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// A second backend must not displace the first.
	if err := st.Save("slack", &Credential{ClientID: "other", AccessToken: "x"}); err != nil {
		t.Fatalf("Save second: %v", err)
	}

	got, err = st.Load("linear")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned nil after Save")
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken ||
		got.ClientID != want.ClientID || got.TokenURL != want.TokenURL ||
		got.AuthStyle != want.AuthStyle || !got.Expiry.Equal(want.Expiry) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	if other, err := st.Load("slack"); err != nil || other == nil || other.ClientID != "other" {
		t.Errorf("second backend = %+v, %v", other, err)
	}

	fi, err := os.Stat(st.path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("token file mode = %o, want 600", perm)
	}
}

// TestRuntimeStoreCorruptFile verifies a damaged store does not wedge a fresh
// authorization: Save starts over rather than propagating the parse error.
func TestRuntimeStoreCorruptFile(t *testing.T) {
	st := testStore(t)
	if err := os.WriteFile(st.path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load("linear"); err == nil {
		t.Error("Load on corrupt store = nil error, want a parse error")
	}
	if err := st.Save("linear", &Credential{AccessToken: "at"}); err != nil {
		t.Fatalf("Save over corrupt store: %v", err)
	}
	got, err := st.Load("linear")
	if err != nil || got == nil || got.AccessToken != "at" {
		t.Errorf("after recovery: %+v, %v", got, err)
	}
}

func TestNewRuntimeStoreNeedsRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	if _, err := NewRuntimeStore(); err == nil {
		t.Error("want an error without XDG_RUNTIME_DIR")
	}
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	if _, err := NewRuntimeStore(); err != nil {
		t.Errorf("NewRuntimeStore: %v", err)
	}
}

// fakeSource hands out a scripted sequence of tokens.
type fakeSource struct {
	toks []*oauth2.Token
	n    int
	err  error
}

func (f *fakeSource) Token() (*oauth2.Token, error) {
	if f.err != nil {
		return nil, f.err
	}
	tok := f.toks[min(f.n, len(f.toks)-1)]
	f.n++
	return tok, nil
}

// TestPersistSource verifies a token is written once per change, so a rotated
// refresh token is stored but an unchanged one costs no writes.
func TestPersistSource(t *testing.T) {
	first := &oauth2.Token{AccessToken: "at1", RefreshToken: "rt1"}
	rotated := &oauth2.Token{AccessToken: "at2", RefreshToken: "rt2"}
	inner := &fakeSource{toks: []*oauth2.Token{first, first, rotated, rotated}}

	var saved []string
	p := &persistSource{inner: inner, save: func(tok *oauth2.Token) {
		saved = append(saved, tok.AccessToken+"/"+tok.RefreshToken)
	}}

	for range 4 {
		if _, err := p.Token(); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	want := []string{"at1/rt1", "at2/rt2"}
	if len(saved) != len(want) || saved[0] != want[0] || saved[1] != want[1] {
		t.Errorf("saved = %v, want %v", saved, want)
	}
}

func TestPersistSourceErrorNotSaved(t *testing.T) {
	p := &persistSource{
		inner: &fakeSource{err: errors.New("refresh failed")},
		save:  func(*oauth2.Token) { t.Error("save called for a failed refresh") },
	}
	if _, err := p.Token(); err == nil {
		t.Error("want the inner error to propagate")
	}
}

// TestBindStoreRestores checks that a usable stored credential is injected as
// the initial token source, which is what suppresses the browser consent.
func TestBindStoreRestores(t *testing.T) {
	st := testStore(t)
	if err := st.Save("linear", &Credential{
		ClientID: "cid", TokenURL: "https://as.example/token",
		AccessToken: "at", RefreshToken: "rt",
		Expiry: time.Now().Add(-time.Hour), // expired, but refreshable
	}); err != nil {
		t.Fatal(err)
	}

	cfg := &sdkauth.AuthorizationCodeHandlerConfig{}
	bindStore(cfg, st, "linear", quietLogger())

	if cfg.InitialTokenSource == nil {
		t.Error("InitialTokenSource = nil, want the stored credential injected")
	}
	if cfg.NewTokenSource == nil {
		t.Error("NewTokenSource = nil, want new tokens to be captured")
	}
}

// TestBindStoreSkipsUnusable covers the credentials that cannot avoid a
// consent: none stored, and an expired access token with no refresh token.
func TestBindStoreSkipsUnusable(t *testing.T) {
	tests := []struct {
		name string
		cred *Credential
	}{
		{"absent", nil},
		{"expired without refresh token", &Credential{
			ClientID: "cid", AccessToken: "at", Expiry: time.Now().Add(-time.Hour),
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := testStore(t)
			if tc.cred != nil {
				if err := st.Save("linear", tc.cred); err != nil {
					t.Fatal(err)
				}
			}
			cfg := &sdkauth.AuthorizationCodeHandlerConfig{}
			bindStore(cfg, st, "linear", quietLogger())
			if cfg.InitialTokenSource != nil {
				t.Error("InitialTokenSource is set, want a fresh consent instead")
			}
			if cfg.NewTokenSource == nil {
				t.Error("NewTokenSource = nil, want new tokens to still be captured")
			}
		})
	}
}

// TestBindStoreCapturesNewToken verifies the capture hook writes the token that
// a completed authorization produced, including the client registration needed
// to refresh it later.
func TestBindStoreCapturesNewToken(t *testing.T) {
	st := testStore(t)
	cfg := &sdkauth.AuthorizationCodeHandlerConfig{}
	bindStore(cfg, st, "linear", quietLogger())

	oc := &oauth2.Config{
		ClientID:     "cid",
		ClientSecret: "secret",
		Endpoint:     oauth2.Endpoint{TokenURL: "https://as.example/token"},
		Scopes:       []string{"read"},
	}
	tok := &oauth2.Token{AccessToken: "at", RefreshToken: "rt", TokenType: "Bearer"}
	if _, err := cfg.NewTokenSource(t.Context(), oc, tok); err != nil {
		t.Fatalf("NewTokenSource: %v", err)
	}

	got, err := st.Load("linear")
	if err != nil || got == nil {
		t.Fatalf("Load after capture: %+v, %v", got, err)
	}
	if got.AccessToken != "at" || got.RefreshToken != "rt" ||
		got.ClientID != "cid" || got.ClientSecret != "secret" ||
		got.TokenURL != "https://as.example/token" {
		t.Errorf("captured credential = %+v", got)
	}
}
