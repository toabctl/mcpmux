BINARY := mcpmux
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

PREFIX ?= $(HOME)/.local
UNITDIR ?= $(HOME)/.config/systemd/user

.DEFAULT_GOAL := all
.PHONY: all build test vet tidy run install restart uninstall clean

# Default: rebuild, install, and restart the running service to pick up changes.
all: install restart

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy

run: build
	./$(BINARY) serve -c mcpmux.yaml

install: build
	install -Dm755 $(BINARY) $(PREFIX)/bin/$(BINARY)
	install -Dm644 dist/mcpmux.service $(UNITDIR)/mcpmux.service
	install -Dm644 dist/mcpmux.socket $(UNITDIR)/mcpmux.socket
	systemctl --user daemon-reload

# Restart the service to load the new binary. The socket stays up across the
# restart, so queued client connections are not dropped. Starts the service if
# it is not already running (which also pulls in mcpmux.socket).
restart:
	systemctl --user restart mcpmux.service
	@systemctl --user --no-pager --lines=0 status mcpmux.service | head -3 || true

uninstall:
	systemctl --user disable --now mcpmux.service mcpmux.socket 2>/dev/null || true
	rm -f $(PREFIX)/bin/$(BINARY) $(UNITDIR)/mcpmux.service $(UNITDIR)/mcpmux.socket

clean:
	rm -f $(BINARY)
