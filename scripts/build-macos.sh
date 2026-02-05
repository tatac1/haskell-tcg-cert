#!/bin/bash
# Build macOS Universal Binary (x86_64 + arm64)
#
# Usage:
#   ./scripts/build-macos.sh              # Build Universal Binary
#   ./scripts/build-macos.sh v1.0.0       # Build with version

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION="${1:-dev}"
BINARY_NAME="tcg-platform-cert-util"

echo "=== Building $BINARY_NAME for macOS ==="
echo "Version: $VERSION"
echo ""

# Check we're on macOS
if [[ "$(uname)" != "Darwin" ]]; then
  echo "Error: This script must be run on macOS"
  exit 1
fi

# Create output directory
mkdir -p "$PROJECT_ROOT/dist"

cd "$PROJECT_ROOT"

# Determine current architecture
CURRENT_ARCH="$(uname -m)"
echo "Current architecture: $CURRENT_ARCH"

# Build for current architecture
echo ""
echo "=== Building for $CURRENT_ARCH ==="
cabal build tcg-platform-cert-util

# Get the binary path
BINARY_PATH=$(cabal list-bin tcg-platform-cert-util 2>/dev/null | grep -v "^Up to date" | tail -1)
echo "Built binary: $BINARY_PATH"

# Copy to dist
OUTPUT_NAME="${BINARY_NAME}-${VERSION}-macos-${CURRENT_ARCH}"
cp "$BINARY_PATH" "$PROJECT_ROOT/dist/$OUTPUT_NAME"
chmod +x "$PROJECT_ROOT/dist/$OUTPUT_NAME"

echo ""
echo "=== Build complete ==="
echo "Output: dist/$OUTPUT_NAME"
echo ""

# Show binary info
file "$PROJECT_ROOT/dist/$OUTPUT_NAME"
ls -lh "$PROJECT_ROOT/dist/$OUTPUT_NAME"

echo ""
echo "=== Dynamic library dependencies ==="
otool -L "$PROJECT_ROOT/dist/$OUTPUT_NAME"

# Check if we can create a Universal Binary (requires both architectures)
if [[ "$CURRENT_ARCH" == "arm64" ]]; then
  OTHER_ARCH="x86_64"
else
  OTHER_ARCH="arm64"
fi

OTHER_BINARY="$PROJECT_ROOT/dist/${BINARY_NAME}-${VERSION}-macos-${OTHER_ARCH}"
if [[ -f "$OTHER_BINARY" ]]; then
  echo ""
  echo "=== Creating Universal Binary ==="
  UNIVERSAL_NAME="${BINARY_NAME}-${VERSION}-macos-universal"
  lipo -create \
    "$PROJECT_ROOT/dist/$OUTPUT_NAME" \
    "$OTHER_BINARY" \
    -output "$PROJECT_ROOT/dist/$UNIVERSAL_NAME"
  chmod +x "$PROJECT_ROOT/dist/$UNIVERSAL_NAME"
  echo "Created: dist/$UNIVERSAL_NAME"
  file "$PROJECT_ROOT/dist/$UNIVERSAL_NAME"
  ls -lh "$PROJECT_ROOT/dist/$UNIVERSAL_NAME"
else
  echo ""
  echo "Note: To create a Universal Binary, also build on $OTHER_ARCH and run:"
  echo "  lipo -create dist/$OUTPUT_NAME dist/${BINARY_NAME}-${VERSION}-macos-${OTHER_ARCH} -output dist/${BINARY_NAME}-${VERSION}-macos-universal"
fi
