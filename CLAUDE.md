# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GitHub Action (`kebechet/setup-apple-certificate`) that manages Apple Distribution certificates and provisioning profiles via the App Store Connect API. It persists and reuses existing valid certificates, only creating new ones when necessary (no valid match or approaching expiry).

## Architecture

Single composite GitHub Action — entry point is `action.yml` which invokes `scripts/ensure-certificate.sh`.

**`scripts/ensure-certificate.sh`** is the entire runtime. It orchestrates:
1. **JWT generation** — inline Python using `PyJWT[crypto]` to authenticate with App Store Connect API
2. **Certificate lifecycle** — lists existing certs, matches by RSA public key modulus, checks expiry, creates new cert via CSR only when needed
3. **Provisioning profile management** — finds/creates/reuses profiles bound to the active certificate, cleans stale ones
4. **P12 packaging** — converts DER cert to PEM, packages with private key into P12, base64-encodes for output
5. **Output writing** — sets GitHub Action outputs and masks secrets

Key helper functions: `api_get()`, `api_post()`, `api_delete()` wrap curl calls with JWT auth headers.

Certificate comparison is done by matching RSA public key modulus between the persistent private key and certificates returned from the API.

Profile naming convention: `"PIPE: {BUNDLE_IDENTIFIER} {suffix}"` — only profiles with the `PIPE: ` prefix are managed/cleaned. The suffix is per `profileType` (`AppStore` for IOS_APP_STORE — kept for backward compatibility — `tvOS AppStore`, `macOS AppStore`, …), so one profile is ensured per requested type via the `PROFILE_TYPES` env (default `IOS_APP_STORE`). `PROFILE_TYPES` values are validated against the known enum, de-duplicated, and an empty list is an error. Cleanup is scoped per type (the list call filters by `profileType`), so profiles of other types are never touched.

App ID resolution is per profile type and platform-aware: the same identifier string can exist as separate App ID resources per platform, so `profile_platform()` maps each `profileType` to the required `bundleIds` platform (`MAC_*` → `MAC_OS`, everything else including tvOS and Mac Catalyst → `IOS`; `UNIVERSAL` satisfies either) and the resolver prefers an exact platform match over `UNIVERSAL`.

## Cross-Platform Considerations

The script runs on macOS GitHub runners. macOS uses BSD variants of CLI tools which differ from GNU/Linux:
- `base64`: use `-i`/`-o` flags for file I/O (no positional filename args), no `-w` flag (use `tr -d '\n'` instead)
- `base64 -d` works on both platforms for decoding
- Python's `cryptography` library deprecates naïve datetime properties — use `*_utc` variants

## Dependencies

Auto-installed at runtime:
- `python3` with `PyJWT[crypto]==2.11.0`, `cryptography>=43.0.0,<45.0.0`
- System tools: `openssl`, `curl`, `base64`

## Build / Test / Lint

No build system, test framework, or linter is configured. The action is a pure bash script with embedded Python heredocs. To test changes, push to a branch and run the action in a workflow.
