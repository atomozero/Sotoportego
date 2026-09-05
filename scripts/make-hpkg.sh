#!/bin/sh
#
# Build a Haiku .hpkg for Sotoportego.
#
# Layout inside the package: apps/Sotoportego/{Sotoportego, sotoportego_server,
# sotoportego_cli}. Installs to /boot/system (or ~/config) via `pkgman install`
# or by dropping the file into a packages/ directory.
#
set -e

# Repository root (this script lives in scripts/).
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

VERSION=0.2.3-1

# Derive the build architecture from the machine we're building on (x86_64, x86,
# ...) instead of hard-coding it, so the same script produces a correct package
# whether run on a 64-bit or a 32-bit (secondary-gcc) Haiku.
ARCH=$(getarch)
OUT="$ROOT/dist/sotoportego-$VERSION-$ARCH.hpkg"

# Build everything first.
make

# Locate the release object directory per binary rather than fixing the gcc
# version (objects.<arch>-cc<ver>-release): the compiler major can differ
# between Haiku images. Pick the newest matching dir if several exist.
find_binary() {
	# $1 = source subdir, $2 = binary name
	local dir
	dir=$(ls -dt "src/$1"/objects."$ARCH"-*-release 2>/dev/null | head -n 1)
	echo "$dir/$2"
}

GUI=$(find_binary gui Sotoportego)
SERVER=$(find_binary server sotoportego_server)
CLI=$(find_binary cli sotoportego_cli)

for f in "$GUI" "$SERVER" "$CLI"; do
	if [ ! -f "$f" ]; then
		echo "error: missing binary $f (build failed?)" >&2
		exit 1
	fi
done

# Stage the package tree.
STAGE=$(mktemp -d /tmp/sotoportego-pkg.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/apps/Sotoportego"
cp "$GUI"    "$STAGE/apps/Sotoportego/Sotoportego"
cp "$SERVER" "$STAGE/apps/Sotoportego/sotoportego_server"
cp "$CLI"    "$STAGE/apps/Sotoportego/sotoportego_cli"
# The checked-in PackageInfo carries an @ARCH@ placeholder so it stays
# arch-agnostic; fill it in with the arch we actually built for.
sed "s/@ARCH@/$ARCH/" packaging/sotoportego.PackageInfo > "$STAGE/.PackageInfo"

mkdir -p "$ROOT/dist"
rm -f "$OUT"
package create -C "$STAGE" "$OUT"

echo "Created $OUT"
