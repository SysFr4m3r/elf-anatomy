# Rendering notes

## Why SVG first

The browser build is phase 1c. This renderer exists so the idea can be judged before any
WASM toolchain work: if bytes-flying-into-memory is compelling, it is compelling as flat
rectangles. See `PROJECT_PLAN.md` §0.4.

It also forces the split the plan wants anyway — geometry and layout live in `elfa-render`
behind a plain function, and the canvas renderer becomes a second backend rather than a
rewrite.

## Bands, not bytes

A binary has thousands of leaf claims and a chart with thousands of bars is a barcode.
`runs()` merges consecutive leaves that share a top-level ancestor, which collapses
`/bin/ls` to around thirty bands, each one a section. The merge is asserted to tile the
file exactly — same invariant as the parser, one level up.

## Two label floors

Labels are suppressed when they would collide with the previous one. The floor is tracked
separately for the mapped column and the left-behind column: they sit at different x, so
their labels cannot collide with each other, and sharing one floor silently dropped the
`.debug_*` labels — the very things the frame is meant to show.

## Left-behind bands stay legible

Unmapped bands fade, but not below 28% opacity. They are the argument of the picture, not
its background: this is what a binary carries that never becomes part of a process.

## Verify with a real renderer

ImageMagick's built-in SVG rasteriser drew `.bss` as a black box with a teal border, which
looked like a fill bug. Chromium rendered it correctly as solid teal. Check frames with

```sh
chromium --headless --no-sandbox --window-size=1200,840 --screenshot=out.png frame.svg
```
