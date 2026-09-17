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
