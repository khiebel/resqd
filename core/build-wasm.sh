#!/usr/bin/env bash
#
# Build the RESQD core WASM module, apply the env.now shim for browsers,
# and copy the output into the web frontend's public assets.
#
# Why the shim exists: chrono's wasmbind feature emits an unresolved
# `import * as import1 from "env"` in the generated glue JS. Browsers
# cannot resolve a bare "env" specifier, so we patch it to a literal
# object that exposes Date.now(). See reference_gemini_image.md and
# project_resqd.md for context.
#
# Usage:  ./build-wasm.sh
# Output: core/pkg/                        (wasm-pack canonical output)
#         web/public/resqd-wasm/           (copied, frontend-facing)

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
WEB_PUBLIC="$REPO_ROOT/web/public/resqd-wasm"
PKG_DIR="$HERE/pkg"
GLUE_JS="$PKG_DIR/resqd_core.js"

echo "── 1/4  wasm-pack build --target web --features wasm"
cd "$HERE"
wasm-pack build --target web --features wasm

if [[ ! -f "$GLUE_JS" ]]; then
  echo "error: $GLUE_JS not produced by wasm-pack" >&2
  exit 1
fi

echo "── 2/4  apply env.now shim to $GLUE_JS"
# Use a portable sed: macOS BSD sed needs an empty string after -i.
if grep -q 'import \* as import1 from "env"' "$GLUE_JS"; then
  sed -i '' -e 's|import \* as import1 from "env"|// Shim: chrono'"'"'s wasmbind bridge imports env.now for Date.now().\
// Bare "env" is not a valid ES module specifier in the browser.\
const import1 = { now: () => Date.now() };|' "$GLUE_JS"
  echo "     shim applied"
elif grep -q "const import1 = { now: () => Date.now() }" "$GLUE_JS"; then
  echo "     shim already present (rebuild idempotent)"
else
  echo "     warning: neither the env.now import nor the shim was found" >&2
  echo "     chrono may have changed its wasmbind bridge — inspect $GLUE_JS" >&2
fi

echo "── 3/4  copy pkg/ → $WEB_PUBLIC"
mkdir -p "$WEB_PUBLIC"
cp "$PKG_DIR/resqd_core.js"            "$WEB_PUBLIC/"
cp "$PKG_DIR/resqd_core.d.ts"          "$WEB_PUBLIC/"
cp "$PKG_DIR/resqd_core_bg.wasm"       "$WEB_PUBLIC/"
cp "$PKG_DIR/resqd_core_bg.wasm.d.ts"  "$WEB_PUBLIC/"

echo "── 4/4  verify streaming bindings exist"
if grep -q "WasmStreamEncryptor" "$WEB_PUBLIC/resqd_core.d.ts"; then
  echo "     WasmStreamEncryptor ✓"
else
  echo "     error: WasmStreamEncryptor missing from .d.ts" >&2
  exit 1
fi
if grep -q "WasmStreamDecryptor" "$WEB_PUBLIC/resqd_core.d.ts"; then
  echo "     WasmStreamDecryptor ✓"
else
  echo "     error: WasmStreamDecryptor missing from .d.ts" >&2
  exit 1
fi

WASM_SIZE=$(stat -f%z "$WEB_PUBLIC/resqd_core_bg.wasm" 2>/dev/null || stat -c%s "$WEB_PUBLIC/resqd_core_bg.wasm")
echo ""
echo "done. wasm = $WASM_SIZE bytes at $WEB_PUBLIC/resqd_core_bg.wasm"
