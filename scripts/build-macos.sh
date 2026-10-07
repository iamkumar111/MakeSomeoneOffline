#!/bin/sh
# Run from any directory on macOS; creates Apple Silicon and Intel binaries.
set -eu
cd "$(dirname "$0")/.."
command -v go >/dev/null
command -v npm >/dev/null
npm --prefix web ci
npm --prefix web run build
mkdir -p bin
for arch in arm64 amd64; do
    GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 go build -o "bin/open-netcut-macos-$arch" ./cmd/control-plane
    GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 go build -o "bin/netcut-cli-macos-$arch" ./cmd/netcut-cli
    GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 go build -o "bin/mac-tool-$arch" ./cmd/mac-tool
done
echo 'Built in bin/. Start from the repository root so web/dist is found.'
