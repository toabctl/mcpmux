# mcpmux

## Releasing

- Cut releases from `main`; versions are `vX.Y.Z` (the `v` prefix is required for Go modules).
- Create the GitHub release — it creates the tag automatically, so don't tag by hand:
  ```sh
  gh release create vX.Y.Z --target main --generate-notes
  ```
- Never move or re-tag a published version (the Go module proxy caches it). Bump to a new version instead.
