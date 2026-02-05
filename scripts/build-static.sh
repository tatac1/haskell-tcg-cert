#!/bin/bash
# Build statically-linked Linux binary using Podman + Alpine musl
#
# Usage:
#   ./scripts/build-static.sh                    # Build for current architecture
#   ./scripts/build-static.sh x86_64             # Build for x86_64
#   ./scripts/build-static.sh aarch64 v1.0.0     # Build for aarch64 with version

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ARCH="${1:-$(uname -m)}"
VERSION="${2:-dev}"

# Normalize architecture names
case "$ARCH" in
  x86_64|amd64)
    PLATFORM="linux/amd64"
    ARCH_NAME="x86_64"
    ;;
  aarch64|arm64)
    PLATFORM="linux/arm64"
    ARCH_NAME="aarch64"
    ;;
  *)
    echo "Error: Unsupported architecture: $ARCH"
    echo "Supported: x86_64, aarch64"
    exit 1
    ;;
esac

echo "=== Building tcg-platform-cert-util ==="
echo "Architecture: $ARCH_NAME"
echo "Platform: $PLATFORM"
echo "Version: $VERSION"
echo ""

# Create output directory
mkdir -p "$PROJECT_ROOT/dist"

# Build using Podman
cd "$PROJECT_ROOT"

IMAGE_NAME="tcg-platform-cert-util-builder:${ARCH_NAME}"
CONTAINER_NAME="tcg-extract-${ARCH_NAME}-$$"
OUTPUT_NAME="tcg-platform-cert-util-${VERSION}-linux-${ARCH_NAME}"

echo "Starting Podman build..."
podman build \
  --platform="$PLATFORM" \
  -t "$IMAGE_NAME" \
  -f Containerfile.static \
  .

echo "Extracting binary..."
# Create a temporary container to extract the binary
# The artifact stage has the binary at /tcg-platform-cert-util
podman create --name "$CONTAINER_NAME" "$IMAGE_NAME" /tcg-platform-cert-util
podman cp "$CONTAINER_NAME:/tcg-platform-cert-util" "$PROJECT_ROOT/dist/$OUTPUT_NAME"
podman rm "$CONTAINER_NAME"

# Make executable
chmod +x "$PROJECT_ROOT/dist/$OUTPUT_NAME"

echo ""
echo "=== Build complete ==="
echo "Output: dist/$OUTPUT_NAME"

# Show file info
file "$PROJECT_ROOT/dist/$OUTPUT_NAME"
ls -lh "$PROJECT_ROOT/dist/$OUTPUT_NAME"
