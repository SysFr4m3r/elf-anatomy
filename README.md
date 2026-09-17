# elf-anatomy

> Watch a binary become a process.

Scroll a real ELF file and watch it load. Every byte on the left is claimed by exactly one
structure; the right-hand panel shows where that byte lands in memory, who rewrites it, and
in what order. The loader simulation is checked against a real `ld.so`, so the animation is a
measurement rather than an illustration.

**Status: phase 1b.** The parser works, and the file→memory morph renders as SVG frames.

## Use

```sh
cargo build --release
./target/release/elfa verify /bin/ls
```

```
/bin/ls  ET_DYN EM_X86_64  entry 0x6a60
  interp /lib64/ld-linux-x86-64.so.2   needed libselinux.so.1, libc.so.6   BIND_NOW

  coverage      ok — every byte claimed exactly once
  size          166,792 bytes
  claims        1,267 (1,210 leaves, depth 3)
  explained          164,546   98.7%
  unexplained          2,246    1.3%

  largest unexplained regions
    0x00026578       1,880  after .note.ABI-tag, before .init_array
    0x00003f50         176  after .rela.plt, before .init  (page alignment)
```

`elfa dump <file>` prints the claim tree; `elfa at <file> <offset>` says what covers one
byte. Try it on a hello-world and see how much of the file is page-alignment padding —
[docs/FORMAT-NOTES.md](docs/FORMAT-NOTES.md) has the numbers.

## The morph

```sh
elfa map fixtures/out/hello-dyn      # what the kernel maps, and what it leaves behind
elfa morph fixtures/out/hello-dyn -o frames/
```

`morph` writes a frame sequence interpolating between two drawings of the same bytes: the
file in file order, and the same file at the addresses the kernel maps it to. Bands that
are mapped slide across; bands that are not — section headers, symbol tables, debug info,
the padding between segments — stay put and fade, because nothing loads them. `.bss` grows
from nothing on the memory side, since it is in `p_memsz` and in no file.

For an unstripped hello-world, **33.9% of the file never becomes part of the process** —
section headers, symbol table, debug info. Another 4,096 bytes exist *twice*: the read-only
and read-write segments share a file page, so the kernel maps it at two addresses with two
different protections. Both numbers are checked against `/proc/<pid>/maps`; see
[docs/CONFORMANCE.md](docs/CONFORMANCE.md).

## Build

```sh
cargo test --workspace
make -C fixtures          # build the specimen matrix (needs cc + binutils)
make -C fixtures summary  # what each fixture demonstrates
```

## License

MIT OR Apache-2.0
