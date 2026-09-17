#!/usr/bin/env bash
# Render an animation to GIF.
#
#   scripts/render-gif.sh <elf-file> morph|steps [out.gif]
#
# Frames come from `elfa` as SVG and are rasterised by Chromium. ImageMagick is used only
# to assemble the GIF — its own SVG renderer draws .bss as a black box (see
# docs/RENDERING.md), so it never touches an SVG here.
set -euo pipefail

BIN=${1:?usage: render-gif.sh <elf-file> <morph|steps> [out.gif]}
MODE=${2:-morph}
OUT=${3:-docs/$MODE.gif}
ELFA=${ELFA:-./target/release/elfa}
WIDTH=${WIDTH:-960}
HOLD=${HOLD:-8}

command -v chromium >/dev/null || { echo "chromium is required" >&2; exit 1; }
command -v magick >/dev/null || { echo "imagemagick is required" >&2; exit 1; }
[ -x "$ELFA" ] || { echo "build first: cargo build --release" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

case "$MODE" in
  morph)
    FRAMES=${FRAMES:-36}
    "$ELFA" morph "$BIN" --frames "$FRAMES" -o "$WORK" >/dev/null
    ;;
  steps)
    # Read the whole listing rather than head-ing it: closing the pipe early is legal,
    # but there is no reason to make the tool handle it here.
    TOTAL=$("$ELFA" steps "$BIN" | awk 'NR == 1 { print $2 }')
    for ((n = 0; n < TOTAL; n++)); do
      "$ELFA" morph "$BIN" --step "$n" -o "$(printf '%s/frame_%03d.svg' "$WORK" "$n")"
    done
    ;;
  *) echo "mode must be morph or steps" >&2; exit 1 ;;
esac

count=$(ls "$WORK"/frame_*.svg | wc -l)
echo "rasterising $count frames…"
i=0
for svg in "$WORK"/frame_*.svg; do
  chromium --headless --no-sandbox --disable-gpu --hide-scrollbars \
           --window-size=1200,840 --screenshot="${svg%.svg}.png" "$svg" 2>/dev/null
  i=$((i + 1))
  printf '\r  %d/%d' "$i" "$count"
done
echo

# Hold on the last frame so the loop reads as a sentence rather than a strobe.
last=$(ls "$WORK"/frame_*.png | tail -1)
for ((h = 0; h < HOLD; h++)); do
  cp "$last" "$(printf '%s/zhold_%03d.png' "$WORK" "$h")"
done

mkdir -p "$(dirname "$OUT")"
magick -delay 8 -loop 0 "$WORK"/frame_*.png "$WORK"/zhold_*.png \
       -resize "$WIDTH" -dither None -colors 128 -layers Optimize "$OUT"
echo "$OUT  $(du -h "$OUT" | cut -f1)"
