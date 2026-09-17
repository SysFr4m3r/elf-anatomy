# elf-anatomy

> Watch a binary become a process.

Scroll a real ELF file and watch it load. Every byte on the left is claimed by exactly one
structure; the right-hand panel shows where that byte lands in memory, who rewrites it, and
in what order. The loader simulation is checked against a real `ld.so`, so the animation is a
measurement rather than an illustration.

**Status: phase 0.** Foundations only — span/claim data model, coverage invariant, interval
index, fixture build matrix. No parser yet.

## Build

```sh
cargo test --workspace
make -C fixtures          # build the specimen matrix (needs cc + binutils)
make -C fixtures summary  # what each fixture demonstrates
```

## License

MIT OR Apache-2.0
