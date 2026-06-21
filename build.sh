#!/usr/bin/env bash
# 交叉编译到 dist/ 下的全平台静态单二进制。
set -e
cd "$(dirname "$0")"
mkdir -p dist
VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do
  GOOS=${target%/*}; GOARCH=${target#*/}
  ext=""; [ "$GOOS" = "windows" ] && ext=".exe"
  CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "dist/ncmdump-$GOOS-$GOARCH$ext" .
  echo "built dist/ncmdump-$GOOS-$GOARCH$ext"
done
