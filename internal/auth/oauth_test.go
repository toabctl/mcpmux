// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
)

// drives fetch and the loopback callback, returning fetch's result. It retries
// the callback GET until fetch has registered its waiter (avoiding a race on
// startup), or fails the test on timeout.
func driveCallback(t *testing.T, query string) (*sdkauth.AuthorizationResult, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a, err := newBrowserAuthorizer(ctx, "test", 0, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newBrowserAuthorizer: %v", err)
	}

	type result struct {
		r *sdkauth.AuthorizationResult
		e error
	}
	done := make(chan result, 1)
	go func() {
		r, e := a.fetch(ctx, &sdkauth.AuthorizationArgs{URL: "http://example.test/authorize"})
		done <- result{r, e}
	}()

	for i := 0; i < 200; i++ {
		if resp, err := http.Get(a.redirect + "?" + query); err == nil {
			_ = resp.Body.Close()
		}
		select {
		case res := <-done:
			return res.r, res.e
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("fetch did not complete")
	return nil, nil
}

func TestBrowserAuthorizer_Success(t *testing.T) {
	r, err := driveCallback(t, "code=the-code&state=the-state")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if r.Code != "the-code" || r.State != "the-state" {
		t.Errorf("got code=%q state=%q", r.Code, r.State)
	}
}

func TestBrowserAuthorizer_ErrorParam(t *testing.T) {
	r, err := driveCallback(t, "error=access_denied")
	if err == nil {
		t.Fatalf("expected error, got result %+v", r)
	}
}
