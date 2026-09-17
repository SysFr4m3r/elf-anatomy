# Conformance: modeled vs observed

The plan (§7.1) puts the modeled/observed diff in phase 4. These are the divergences
already visible at phase 1b, found by comparing `elfa map` against `/proc/<pid>/maps` for a
running process. Recording them now because each one is a fact about loading, not a bug to
be quietly fixed.

Reference observation, glibc 2.42, Linux 7.0.12, x86-64:

```
$ readelf -lW /usr/bin/sleep          # four PT_LOADs
  off 0x000000  vaddr 0x0000  filesz 0x1660  R
  off 0x002000  vaddr 0x2000  filesz 0x5029  R E
  off 0x008000  vaddr 0x8000  filesz 0x1fb8  R
  off 0x00ab30  vaddr 0xab30  filesz 0x0570  memsz 0x0758  RW

$ grep sleep /proc/<pid>/maps        # five VMAs
  ...b5e000-...b60000 r--p 00000000   /usr/bin/sleep
  ...b60000-...b66000 r-xp 00002000   /usr/bin/sleep
  ...b66000-...b68000 r--p 00008000   /usr/bin/sleep
  ...b68000-...b69000 r--p 0000a000   /usr/bin/sleep
  ...b69000-...b6a000 rw-p 0000b000   /usr/bin/sleep
```

## 1. The kernel maps pages, not byte ranges

`MemImage` records segment extents exactly: `p_vaddr .. p_vaddr + p_filesz`. `mmap` works
in whole pages, so the real VMA is the segment rounded out to page boundaries at both ends.
The first segment is `0x0..0x1660` in the file and `0x0..0x2000` in memory.

Consequence: a byte in the padding *after* a segment's file content but *within* its last
page **is** loaded, and `vaddr_of()` currently says it is not. The "never loaded"
percentage is therefore an overestimate by up to one page per segment — for `hello-dyn`,
that is a meaningful fraction of the headline 84.1%.

**Fixed.** `MemImage` now carries three views: segment extents (what the morph draws),
page-rounded `Vma`s (what the kernel created), and `Resident` file ranges (what "never
loaded" is measured against). `vaddr_of` is page-aware.

The two ends round by different rules, which is the part that is easy to get wrong:

- **Leading**: `mmap` starts at the page containing `p_offset`, so the tail of whatever
  precedes the segment is pulled in with it.
- **Trailing**: whole pages come from the file, so bytes past `p_filesz` in the last page
  are present too — *unless* `memsz > filesz`, in which case `padzero()` wipes them.

Verified against a live process:

```
$ gdb -batch -ex starti -ex 'info proc mappings' fixtures/out/hello-dyn
  0x555555554000 0x555555555000  r--p  offset 0x0
  0x555555555000 0x555555556000  r-xp  offset 0x1000
  0x555555556000 0x555555557000  r--p  offset 0x2000
  0x555555557000 0x555555559000  rw-p  offset 0x2000

$ elfa map fixtures/out/hello-dyn
  0x00000000-0x00001000  r--
  0x00001000-0x00002000  r-x
  0x00002000-0x00003000  r--
  0x00003000-0x00005000  rw-
```

Base-relative, the model and the kernel agree exactly.

### And a fact that fell out of it

Look at the file offsets in the two bottom rows: **0x2000 twice**. The read-only segment
ends at file `0x2140` and the read-write segment begins at file `0x2db0`, both inside file
page `0x2000`. The kernel maps that one page at two addresses with two different
protections. `.rodata` is readable at `0x2000`; the same 4KB is writable at `0x3000`.

`double_mapped_bytes()` reports this. For `hello-dyn` it is 4,096 bytes — 22% of the file
exists twice in the address space.

## 2. RELRO splits one segment into two mappings

Four `PT_LOAD`s produce five VMAs. The RW segment spans pages `0xa000`–`0xc000`, and the
first of those pages comes back **`r--p`**: `ld.so` walked `PT_GNU_RELRO` and `mprotect`ed
it read-only after relocation, so the GOT cannot be written once the program is running.

A model that maps segments and stops will always report one mapping where reality has two,
and will report `rw-` where reality says `r--`. This is not an error to correct in
`elfa-model` — it is step L6 of the loader timeline, and it belongs in phase 3.

It also means **segment count never equals VMA count** on a hardened binary, which is worth
knowing before writing a diff that assumes they line up.

`elfa trace` now captures this directly. The two snapshots differ by exactly one
`mprotect`:

```
at interpreter entry            at program entry
  ...554000 r--p off 0x0          ...554000 r--p off 0x0
  ...555000 r-xp off 0x1000       ...555000 r-xp off 0x1000
  ...556000 r--p off 0x2000       ...556000 r--p off 0x2000
  ...557000 rw-p off 0x2000  →    ...557000 r--p off 0x2000    ← RELRO applied
    (two pages)                   ...558000 rw-p off 0x3000
```

The kernel handed the loader one writable two-page mapping. The loader relocated through
it, then sealed the first page. Everything in that page — the GOT, `.init_array`,
`.dynamic` — is read-only before `main` runs, and the process has one more VMA than the
file has segments.

## 4. musl and other loaders do not narrate

`LD_DEBUG` is a glibc feature. On musl, `elfa trace` will capture the gdb snapshots and no
steps at all. Static binaries have no loader to observe and are rejected outright.

## 3. ET_DYN addresses are relative

`elfa map` prints `p_vaddr` as written in the file, starting at `0x0`. A real process has a
randomised load base (`0x558fc5b5e000` above). Comparisons must be base-relative, and the
base has to be recovered from the observed trace rather than assumed.
