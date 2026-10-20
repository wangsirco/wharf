#!/bin/sh
# Build luci-app-wharf_<version>_<arch>.ipk without the OpenWrt SDK.
# (Internal names — owp-agent, owp-panel, /etc/config/owp*, owp_* chains — are kept on purpose.)
#   scripts/build-ipk.sh [x86_64|aarch64|arm|mips|mipsel]   (default x86_64)
set -e
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(sed -n 's/^const Version = "\(.*\)"/\1/p' internal/version/version.go)-1}"
ARCH="${1:-x86_64}"

case "$ARCH" in
	x86_64)  GOARCH=amd64;  PKGARCH=x86_64 ;;
	aarch64) GOARCH=arm64;  PKGARCH=aarch64_generic ;;
	arm)     GOARCH=arm GOARM=7; PKGARCH=arm_cortex-a7_neon-vfpv4 ;;
	mips)    GOARCH=mips GOMIPS=softfloat;   PKGARCH=mips_24kc ;;
	mipsel)  GOARCH=mipsle GOMIPS=softfloat; PKGARCH=mipsel_24kc ;;
	*) echo "unknown arch $ARCH"; exit 1 ;;
esac
export GOARCH GOARM GOMIPS

[ "${SKIP_WEB:-0}" = 1 ] || (cd web && npm run build >/dev/null)

OUT=dist/ipk-$ARCH
rm -rf "$OUT" && mkdir -p "$OUT/data/usr/bin" "$OUT/control"
cp -R package/luci-app-wharf/root/. "$OUT/data/"
CORE_HASH="${CORE_HASH:-$(GOOS= GOARCH= go run ./cmd/wharf-release corehash)}"
LDFLAGS="-s -w -X github.com/wangsirco/wharf/internal/version.CoreHash=$CORE_HASH"
[ "$GOARCH" = arm ] && LDFLAGS="$LDFLAGS -X github.com/wangsirco/wharf/internal/agent.goarm=$GOARM"
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="$LDFLAGS" -o "$OUT/data/usr/bin/owp-agent" ./cmd/owp-agent
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="$LDFLAGS" -o "$OUT/data/usr/bin/owp-panel" ./cmd/owp-panel

SIZE=$(du -sk "$OUT/data" | awk '{print $1*1024}')
cat > "$OUT/control/control" <<CTRL
Package: luci-app-wharf
Version: $VERSION
Replaces: luci-app-owp
Conflicts: luci-app-owp
Provides: luci-app-owp
Depends: libc, rpcd, luci-base
Source: https://github.com/wangsirco/wharf
License: MIT
Section: luci
Architecture: $PKGARCH
Installed-Size: $SIZE
Description: Wharf - multi-admin OpenWrt control panel (agent + web panel + LuCI page)
CTRL
printf "/etc/config/owp\n/etc/config/owpfwd\n/etc/config/owpdev\n" > "$OUT/control/conffiles"
cp package/luci-app-wharf/control/postinst package/luci-app-wharf/control/prerm package/luci-app-wharf/control/postrm "$OUT/control/"
echo "2.0" > "$OUT/debian-binary"

TAR="tar --format ustar --uid 0 --gid 0 --uname root --gname root --no-mac-metadata"
export COPYFILE_DISABLE=1
(cd "$OUT/data" && $TAR -czf ../data.tar.gz .)
(cd "$OUT/control" && $TAR -czf ../control.tar.gz .)
PKG="dist/luci-app-wharf_${VERSION}_${PKGARCH}.ipk"
(cd "$OUT" && $TAR -czf "../$(basename "$PKG")" ./debian-binary ./control.tar.gz ./data.tar.gz)
ls -lh "$PKG"
