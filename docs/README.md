# Documentation

`index.html` here is the browser viewer (built by `scripts/build-web.sh` into `pkg/`), and
`player.html` is the pre-rendered fallback that needs no wasm. GitHub Pages serves this
directory.

| | |
|---|---|
| [MODEL.md](MODEL.md) | The loader model: the step list, what each phase does, what is out of scope |
| [CONFORMANCE.md](CONFORMANCE.md) | Every place the model and a real `ld.so` disagreed, and what each disagreement turned out to be |
| [FORMAT-NOTES.md](FORMAT-NOTES.md) | What the specimens taught us that the spec does not say plainly |
| [RENDERING.md](RENDERING.md) | Why the renderer is headless first, and how to check a frame |

`CONFORMANCE.md` is the one to read if you only read one. It is the record of the project
being wrong ten times and finding out, which is the only reason to trust the rest.
