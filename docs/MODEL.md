# The loader model

`Timeline::plan(summary, image)` turns a parsed file into an ordered list of steps.
`state_at(n)` replays the effects of steps `0..=n`. Nothing is stored per step: state is
derived, so scrubbing backwards costs what scrubbing forwards costs and the two cannot
disagree.

Everything here is checked against a real `ld.so` by `elfa diff`. Where the model and
reality differ, the difference is recorded in [CONFORMANCE.md](CONFORMANCE.md) rather than
quietly reconciled.

## Shape

```rust
struct Step {
    n: u32,
    phase: Phase,          // Kernel Interp Resolve Relocate Protect Init Entry
    actor: Actor,          // Kernel | Interp | Program
    narration: String,
    reads: Vec<Span>,      // file bytes this step consults
    effects: Vec<Effect>,
}

enum Effect {
    Map(Mapping),
    Protect { start: u64, len: u64, to: Prot },
    Write(Poke),           // addr, len, cause
}
```

`reads` is what drives the byte-river highlight: a relocation step points back at the
`Elf64_Rela` entry that produced it, so selecting a step selects the bytes that caused it.

## The steps

**Kernel** — everything before any code of the program's has run.

| Step | Shows |
|---|---|
| read the first page, check `e_ident` | why a wrong-arch binary fails here and not later |
| `PT_INTERP` | the path string that makes a program dynamic |
| map each `PT_LOAD` | file offsets becoming virtual addresses |
| zero-fill `p_memsz - p_filesz` | `.bss` appearing from nothing |
| build the stack | argv, envp, and the auxiliary vector |
| jump to the **interpreter's** entry | the program's own entry is not what runs first |

**Interp / Resolve** — `ld.so` relocates itself before it can touch a global, reads
`PT_DYNAMIC`, walks `DT_NEEDED`, and builds the global symbol scope.

**Relocate** — tables in the order glibc applies them: `DT_RELR`, `DT_RELA`, `DT_REL`,
`DT_JMPREL`. Each relocation is its own step with its own `Poke`.

`DT_RELR` is expanded during parsing. One bitmap word encodes up to 63 relative
relocations and the loader applies each separately; a timeline showing "one bitmap word"
shows nothing. The expansion agrees with `readelf` on the `relr` fixture: 3 entries, 5
locations.

Under lazy binding `DT_JMPREL` produces **no writes at all** — the step says so, and a
later step accounts for where they happen instead. Most ELF tutorials animate lazy PLT
resolution as though it were the normal case; on a distro-built binary it never runs.

**Protect** — `PT_GNU_RELRO`, rounded **down** at both ends as glibc does, which can mean
protecting nothing. `mprotect` splits the mapping rather than recolouring it, which is why
a hardened binary has more VMAs than segments.

**Init / Entry** — `DT_INIT`, `DT_INIT_ARRAY`, then the jump to `e_entry`. Initialisers are
narrated but produce no pokes: modelling what a constructor writes would mean running it.

## Scope

The model covers the **main object**. Dependencies are named as they resolve but are not
themselves mapped, relocated, or initialised — that means loading and parsing libc, which
is its own pass.

Not modelled: ifunc resolvers, TLS block layout and the DTV, symbol interposition order,
`LD_PRELOAD`, and lazy PLT resolution as it actually happens at first call. `elfa diff`
marks the areas it cannot check `--` rather than passing them silently.
