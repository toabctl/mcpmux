// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// Credential is the persisted result of an interactive OAuth authorization.
// The client registration and token endpoint are stored alongside the token
// because the client is registered dynamically per run, and a refresh needs
// both.
type Credential struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty"`
	TokenURL     string    `json:"token_url"`
	AuthStyle    int       `json:"auth_style"`
	Scopes       []string  `json:"scopes,omitempty"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Expiry       time.Time `json:"expiry,omitzero"`
}

// Store persists credentials between runs, keyed by backend label.
type Store interface {
	// Load returns the stored credential, or nil when there is none.
	Load(label string) (*Credential, error)
	Save(label string, c *Credential) error
}

// RuntimeStore keeps credentials in a 0600 file under $XDG_RUNTIME_DIR. That
// is a tmpfs, so tokens survive a service restart -- the case that otherwise
// costs every interactive consent -- without ever reaching persistent storage.
// They are gone after logout or reboot, which re-consents once.
type RuntimeStore struct {
	path string
	mu   sync.Mutex
}

// NewRuntimeStore returns a store under $XDG_RUNTIME_DIR/mcpmux, erroring when
// that is unset because there is then no tmpfs to keep tokens out of the disk.
func NewRuntimeStore() (*RuntimeStore, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return nil, errors.New("XDG_RUNTIME_DIR is unset")
	}
	return newStoreAt(filepath.Join(dir, "mcpmux"))
}

func newStoreAt(dir string) (*RuntimeStore, error) {
	//nolint:gosec // G703: dir comes from XDG_RUNTIME_DIR, not from external input.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create token store dir: %w", err)
	}
	return &RuntimeStore{path: filepath.Join(dir, "tokens.json")}, nil
}

// Load returns the stored credential for label, or nil when there is none.
func (s *RuntimeStore) Load(label string) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.readAll()
	if err != nil {
		return nil, err
	}
	return all[label], nil
}

// Save writes the credential for label, replacing any previous one.
func (s *RuntimeStore) Save(label string, c *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.readAll()
	if err != nil {
		// A corrupt store must not block a fresh authorization; start over.
		all = map[string]*Credential{}
	}
	all[label] = c
	// G117: serializing the secrets is the point; the file is 0600 on a tmpfs.
	//nolint:gosec
	buf, err := json.Marshal(all)
	if err != nil {
		return err
	}
	// Write a sibling temp file and rename, so a crash mid-write cannot leave a
	// truncated store, and the secrets are never briefly world-readable.
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".tokens-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func (s *RuntimeStore) readAll() (map[string]*Credential, error) {
	//nolint:gosec // G304: the path is built from XDG_RUNTIME_DIR, not user input.
	buf, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]*Credential{}, nil
	}
	if err != nil {
		return nil, err
	}
	all := map[string]*Credential{}
	if err := json.Unmarshal(buf, &all); err != nil {
		return nil, fmt.Errorf("parse token store: %w", err)
	}
	return all, nil
}

// credentialFrom flattens an oauth2 config and token into a storable record.
func credentialFrom(cfg *oauth2.Config, tok *oauth2.Token) *Credential {
	return &Credential{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     cfg.Endpoint.TokenURL,
		AuthStyle:    int(cfg.Endpoint.AuthStyle),
		Scopes:       cfg.Scopes,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		Expiry:       tok.Expiry,
	}
}

// oauth2Config rebuilds the config needed to refresh a stored credential. Only
// the token endpoint is restored: the authorization endpoint is reached solely
// through a browser consent, which a restored token exists to avoid.
func (c *Credential) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       c.Scopes,
		Endpoint: oauth2.Endpoint{
			TokenURL:  c.TokenURL,
			AuthStyle: oauth2.AuthStyle(c.AuthStyle),
		},
	}
}

func (c *Credential) token() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  c.AccessToken,
		RefreshToken: c.RefreshToken,
		TokenType:    c.TokenType,
		Expiry:       c.Expiry,
	}
}

// persistSource saves the token whenever the underlying source hands back a new
// one, so a rotated refresh token replaces the stored one instead of going
// stale.
type persistSource struct {
	inner oauth2.TokenSource
	save  func(*oauth2.Token)

	mu   sync.Mutex
	last string
}

func (p *persistSource) Token() (*oauth2.Token, error) {
	tok, err := p.inner.Token()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if key := tok.AccessToken + "\x00" + tok.RefreshToken; key != p.last {
		p.last = key
		p.save(tok)
	}
	return tok, nil
}
