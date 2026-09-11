// Target for HookOverpatch.java
// gcc -O0 -fno-inline -no-pie -g -o test_hookoverpatch test_hookoverpatch.c
// slow_path: mov [rbp-0x4],0 @0x40114f, 7B hook site
// Nearby (auto) cave -> 2B short JMP; a far cave (e.g. 0x401230) forces the
// 5B JMP whose overrun hits the relative call helper @0x40115b.
// pad_cave supplies 256 NOP bytes for the auto-scan.

#include <stdio.h>

__attribute__((noinline)) int helper(int x) { return x * 2; }

__attribute__((noinline)) int slow_path(int x) {
  int r = 0;
  r = helper(x);
  return r;
}

__attribute__((noinline, used)) static void pad_cave(void) {
  __asm__ volatile(".fill 256, 1, 0x90");
}

int main(void) {
  printf("slow_path(21) = %d\n", slow_path(21));
  if (0)
    pad_cave();
  return 0;
}
