# Format notes

Things the specimens taught us that the spec does not say plainly.

## A bare `cc` is not a distro build

On Debian/Kali, `cc -o hello hello.c` emits **lazy binding and partial RELRO**. Every binary
in `/usr/bin` is built through `dpkg-buildflags`, which adds `-Wl,-z,now`, so `/bin/ls` has
`FLAGS: BIND_NOW` and full RELRO.

This matters twice. The `hello-dyn` fixture sets the hardening flags explicitly, or it would
be byte-for-byte identical to the `lazy` fixture and the matrix would silently cover one case
instead of two. And it means "what the toolchain does by default" and "what you find on a
running system" are different claims — the UI must describe the binary in front of it rather
than the ecosystem around it.

## DT_RELR earns its keep immediately

`-Wl,-z,pack-relative-relocs` on the hello fixture turns 5 `R_X86_64_RELATIVE` entries
(120 bytes of `.rela.dyn`) into 24 bytes of `DT_RELR` bitmap. On real binaries with
thousands of relative relocations the ratio is what makes the format worth implementing —
and it is why a parser that only knows `REL`/`RELA` now misses most of the relocations in a
modern binary.

## A static binary is not a relocation-free binary

`hello-static` has no dynamic section and 22 `R_X86_64_IRELATIVE` relocations: glibc's ifunc
resolvers for `memcpy` and friends still run at startup, selecting implementations by CPU
feature. Code executes before `main` even with no loader in the picture at all. `static-pie`
goes further — 1103 `R_X86_64_RELATIVE` on top, applied by the program to itself.

## Half of a hello-world is padding

`fixtures/out/hello-dyn` is 18,632 bytes, of which **9,383 (50.4%) is not part of any
structure**. Almost all of it is alignment:

```
0x00001175  3,723  after .fini, before .rodata      (page alignment)
0x00002140  3,184  after .note.ABI-tag, before .init_array
0x00000670  2,448  after .rela.plt, before .init    (page alignment)
```

Modern binutils defaults to `-z separate-code`, which splits the image into four
page-aligned `PT_LOAD` segments (R, RX, R, RW) so that each gets its own protection. The
file is laid out to match, and the padding between segments is the price. On an 18KB binary
that price is half the file; on `/bin/ls` at 167KB it is 1.3%, because the padding is
roughly constant and the content is not.

The second gap is not page-aligned and is a different rule: `p_offset ≡ p_vaddr (mod
page_size)` is required so a single `mmap` can place a segment at the right address. The RW
segment sits at vaddr `0x3db0`, so it must start at a file offset congruent to `0xdb0` —
hence the jump from `0x2140` to `0x2db0`.

Neither of these is visible in `readelf` output. You get them for free from the coverage
invariant: claim every byte, and the leftovers explain themselves.

**But padding is not the same as absent.** An early version of this note said 84.1% of
`hello-dyn` never loads. That was wrong, and wrong in an instructive way: it measured
against segment extents, while the kernel maps whole pages. Most of that padding shares a
page with real content and is therefore in the process, occupying address space, doing
nothing.

The corrected figures for `hello-dyn`:

| | bytes | |
|---|---|---|
| in the process | 12,312 | 66.1% |
| never loaded | 6,320 | 33.9% — section headers, symtab, `.debug_*` |
| zero-filled | 1,064 | `.bss`, in no file |
| mapped twice | 4,096 | one file page at two addresses |

33.9% is a smaller number than 84.1% and a true one. See `docs/CONFORMANCE.md`.
