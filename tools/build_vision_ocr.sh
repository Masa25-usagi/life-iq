#!/bin/sh
# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

set -eu

tool_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build_dir="$tool_dir/.build"
mkdir -p "$build_dir"
exec swiftc \
  -framework Vision \
  -framework ImageIO \
  -framework CoreGraphics \
  "$tool_dir/vision_ocr.swift" \
  -o "$build_dir/vision_ocr"
