// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package cmd

import (
	"context"
	"log/slog"

	"github.com/toabctl/mcpmux/internal/mux"
)

// retryOnSignal is a no-op on platforms without SIGUSR1; pending backends are
// still retried on their own schedule.
func retryOnSignal(context.Context, *mux.Mux, *slog.Logger) {}
