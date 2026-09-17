# Specimen matrix. Each fixture isolates one thing the loader does differently.
# `make` builds them, `make summary` prints what each one demonstrates.
#
# Phase 0 builds the first six. The rest of the matrix (ifunc, TLS models, C++
# init ordering, preload interposition, cross-arch) lands with the phases that
# need them — see PROJECT_PLAN.md §8.

CC      ?= cc
OUT     := out
SRC     := src/hello.c
CFLAGS  ?= -O1 -g

FIXTURES := \
	$(OUT)/hello-dyn \
	$(OUT)/hello-static \
	$(OUT)/hello-static-pie \
	$(OUT)/hello-nopie \
	$(OUT)/lazy \
	$(OUT)/relr

.PHONY: all clean summary check
all: $(FIXTURES)

$(OUT):
	@mkdir -p $(OUT)

# The baseline: dynamic PIE, BIND_NOW, full RELRO — what your distro ships.
# The hardening flags are explicit on purpose: a bare `cc` on Debian/Kali emits
# lazy binding and partial RELRO, while every binary in /usr/bin is built with
# dpkg-buildflags and gets -z now. Without these, this fixture and `lazy` below
# are byte-for-byte the same specimen.
$(OUT)/hello-dyn: $(SRC) | $(OUT)
	$(CC) $(CFLAGS) -Wl,-z,now -Wl,-z,relro -o $@ $<

# No interpreter at all. The kernel maps it and jumps straight to _start.
$(OUT)/hello-static: $(SRC) | $(OUT)
	$(CC) $(CFLAGS) -static -o $@ $<

# Self-relocating with no ld.so: relocations processed by the program itself.
$(OUT)/hello-static-pie: $(SRC) | $(OUT)
	$(CC) $(CFLAGS) -static-pie -o $@ $< || \
		echo "SKIP $@ (toolchain lacks static-pie support)"

# Fixed load address. The contrast that makes ASLR visible in the memory panel.
$(OUT)/hello-nopie: $(SRC) | $(OUT)
	$(CC) $(CFLAGS) -no-pie -o $@ $<

# Lazy PLT binding, deliberately. The animation everyone teaches, which almost
# nothing actually uses any more.
$(OUT)/lazy: $(SRC) | $(OUT)
	$(CC) $(CFLAGS) -Wl,-z,lazy -Wl,-z,norelro -o $@ $<

# DT_RELR: relative relocations as a bitmap rather than a table.
$(OUT)/relr: $(SRC) | $(OUT)
	$(CC) $(CFLAGS) -Wl,-z,pack-relative-relocs -o $@ $< || \
		echo "SKIP $@ (linker lacks -z pack-relative-relocs)"

clean:
	rm -rf $(OUT)

# What the parser will have to handle, straight from the specimens.
summary: all
	@for f in $(FIXTURES); do \
		[ -f $$f ] || continue; \
		printf '\n== %s ==\n' $$f; \
		readelf -hW $$f | awk '/Type:|Entry point/'; \
		readelf -dW $$f 2>/dev/null | grep -Ei 'RELR|FLAGS|NEEDED|BIND_NOW' || echo '  (no dynamic section)'; \
		printf '  relro:'; readelf -lW $$f | awk '/GNU_RELRO/{printf " GNU_RELRO"} END{print ""}'; \
		printf '  relocations:'; \
		readelf -rW $$f 2>/dev/null | awk '$$3 ~ /^R_/ {print $$3}' | sort | uniq -c | \
			awk '{printf " %s×%s", $$1, $$2}'; \
		echo; \
	done

# Every fixture must at least run, or it is not a specimen of anything.
check: all
	@for f in $(FIXTURES); do \
		[ -f $$f ] || continue; \
		$$f >/dev/null && echo "ok   $$f" || echo "FAIL $$f"; \
	done
