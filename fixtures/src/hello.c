/* The smallest program that still exercises the interesting parts of a load:
 * one libc call (a PLT relocation), one initialised global (a RELATIVE relocation),
 * one zero-initialised global (.bss, which exists in no file), and a constructor
 * (DT_INIT_ARRAY, which runs before main). */
#include <stdio.h>

const char *greeting = "hello, loader\n";
static int zeroed[256];

__attribute__((constructor)) static void before_main(void) {
    zeroed[0] = 1;
}

int main(void) {
    fputs(greeting, stdout);
    return zeroed[0] - 1;
}
