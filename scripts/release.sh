#!/bin/sh
# Build every architecture and publish a signed release on GitHub.
#   GITHUB_TOKEN=... scripts/release.sh [notes.md]
# The signing key lives outside the repository (default ~/.config/wharf/release-ed25519.key).
set -e
cd "$(dirname "$0")/.."
VER="$(sed -n 's/^const Version = "\(.*\)"/\1/p' internal/version/version.go)"
KEY="${WHARF_SIGNING_KEY:-$HOME/.config/wharf/release-ed25519.key}"
REPO="${WHARF_REPO:-wangsirco/wharf}"
[ -n "$GITHUB_TOKEN" ] || { echo "GITHUB_TOKEN is not set"; exit 1; }
[ -f "$KEY" ] || { echo "signing key $KEY not found"; exit 1; }
(cd web && npm run build >/dev/null)
CORE_HASH="$(go run ./cmd/wharf-release corehash)"; export CORE_HASH
for a in x86_64 aarch64 arm; do SKIP_WEB=1 sh scripts/build-ipk.sh "$a"; done
NOTES="${1:-}"
[ -z "$NOTES" ] && [ -f "docs/release-notes/v$VER.md" ] && NOTES="docs/release-notes/v$VER.md"
go run ./cmd/wharf-release publish -repo "$REPO" -version "$VER" -key "$KEY" ${NOTES:+-notes "$NOTES"} ${DRAFT:+-draft}
