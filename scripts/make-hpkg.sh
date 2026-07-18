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

VERSION=0.1.2-1
ARCH=x86_64
OBJ=objects.$ARCH-cc13-release
OUT="$ROOT/dist/sotoportego-$VERSION-$ARCH.hpkg"

GUI="src/gui/$OBJ/Sotoportego"
SERVER="src/server/$OBJ/sotoportego_server"
CLI="src/cli/$OBJ/sotoportego_cli"

# Build everything first.
make

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
cp packaging/sotoportego.PackageInfo "$STAGE/.PackageInfo"

mkdir -p "$ROOT/dist"
rm -f "$OUT"
package create -C "$STAGE" "$OUT"

echo "Created $OUT"
