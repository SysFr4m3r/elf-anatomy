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

## 5. Modelled mappings are segment-exact; VMAs are page-rounded and merged

`Timeline::state_at` returns `Mapping`s with exact extents — `.bss` is its own entry even
though it shares a page, and a mapping is not merged with its neighbour just because they
ended up with the same protection. The kernel does both.

For `hello-dyn` the model ends with 6 mappings and `/proc` shows 5. Neither is wrong; they
are different views.

**Done.** `State::vmas()` builds the kernel's view page by page, later mappings overwriting
earlier ones. `elfa diff` compares on that. Getting the merge rule right took three
corrections, each found by a binary that broke the previous version:

1. **Protection alone is not enough.** `hello-dyn` has two adjacent read-only VMAs whose
   protections match. They stay separate because both segments start inside file page
   `0x2000`, so the second does not continue the first's offset.
2. **Contiguous offsets are not enough either.** `/bin/true`'s third segment ends at page
   `0x9000` and RELRO turns the first page of the fourth read-only — two adjacent
   read-only pages whose offsets *do* line up (`0x7000 + 0x2000 = 0x9000`), and the kernel
   still reports them separately. A VMA merge requires identical `vm_flags`, and those two
   carry different lineage. The model never merges across segments, which reproduces every
   table observed so far.
3. **`.bss` past the last file-backed page is anonymous.** `/bin/ls` has `p_memsz`
   overrunning its final file page, and the kernel gives the remainder a VMA with no path.
   Filtering observed rows by path drops it, and the model then looks like it invented a
   mapping. `elfa diff` follows anonymous rows that continue directly from the object's.

With those three rules the model reproduces the mapping table exactly — addresses,
protections, offsets and boundaries — for `hello-dyn`, `hello-nopie`, `lazy`, `relr`,
`/bin/true` and `/bin/ls`.

## 7. ET_EXEC has no load base

`elfa diff` normalises observed addresses by subtracting the lowest mapping start, so a
PIE's randomised base does not read as a divergence. An `ET_EXEC` is mapped at the
addresses written in its headers — `hello-nopie` at `0x400000` — and subtracting anything
turns a perfect match into a whole-table divergence. The normalisation applies to `ET_DYN`
only.

## 8. glibc annotates lazy objects

`LD_DEBUG` prints `relocation processing: <object> (lazy)` when an object binds lazily.
That is the loader stating the binding mode it actually used, which is better evidence than
inferring it from `DT_FLAGS` — so `elfa diff` checks the model's reading of `DT_FLAGS`
against it. The suffix has to be stripped before the name is matched, or nothing matches
the object again.

## 6. RELRO rounds down at both ends

`_dl_protect_relro` in glibc:

```c
start = ALIGN_DOWN (l->l_addr + l->l_relro_addr, pagesize);
end   = ALIGN_DOWN (l->l_addr + l->l_relro_addr + l->l_relro_size, pagesize);
```

The **end rounds down**, not up. A RELRO region that stops mid-page leaves that page
writable, and if the region is smaller than a page, `start == end` and nothing is protected
at all.

Every fixture on this host has a page-aligned RELRO end — `relr` is `0x3d98 + 0x268 =
0x4000`, `hello-dyn` is `0x3db0 + 0x250 = 0x4000` — so rounding up and rounding down give
the same answer and the difference is invisible. The model rounded up until this was
checked against the glibc source.

It matters because the error is in the flattering direction: a tool that reports the GOT as
sealed when it is still writable is worse than one that says nothing. The unit test uses a
synthetic segment with a mid-page end, since no fixture can exercise it.

## 9. Relocations naming a symbol and symbols the loader binds are different sets

The obvious check — does the model's symbol count equal the loader's — is wrong in both
directions, and the error is consistent enough to look like an off-by-two.

For `hello-dyn`, 7 relocations name a symbol and the loader reports 9 binds for the object:

```
model, from relocations        loader, from LD_DEBUG
  __libc_start_main              __libc_start_main
  __cxa_finalize                 __cxa_finalize
  stdout        (COPY)           stdout
  fputs         (JUMP_SLOT)      fputs
  _ITM_deregisterTMCloneTable    calloc
  _ITM_registerTMCloneTable      free
  __gmon_start__                 malloc
                                 realloc
                                 _r_debug
```

Three in the model are **weak and undefined**. `__gmon_start__` and the `_ITM_*` pair have
no definition anywhere; the loader resolves them to zero, does not fail, and prints no bind
line. `Reloc::weak` records this, read from `st_info >> 4 == STB_WEAK` with `st_shndx ==
SHN_UNDEF`.

Five on the loader's side are lookups **no relocation asked for**. `_r_debug` is the
debugger interface, and `malloc`/`calloc`/`free`/`realloc` are resolved against the global
scope so a program can interpose them — `ld.so` needs its own reference to whichever
definition wins.

So `elfa diff` checks **containment**, not equality: every non-weak symbol a relocation
names must appear in the loader's binds, and the loader's own extra lookups are reported
rather than judged. Forcing the numbers to agree would have meant fitting the model to the
measurement, which is the failure mode this whole document exists to prevent.

On a lazily-bound object the extra count rises by one: the PLT symbol is excluded from the
model's set (nothing is written before `main`) but the loader still binds it on first call,
and the trace covers the whole process.
