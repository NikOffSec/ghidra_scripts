// Target for PatchFromFile.java
// gcc -O0 -fno-inline -no-pie -g -o test_patchfromfile test_patchfromfile.c
// check_license success path: mov eax,0 @0x40115c, 5B (patch 4B -> 1 NOP)
// add_two: add eax,edx @0x401173, 2B (exact-fill, no NOP)

#include <stdio.h>

__attribute__((noinline)) int check_license(const char *key) {
  if (key == NULL)
    return 0;
  return 0;
}

__attribute__((noinline)) int add_two(int a, int b) { return a + b; }

int main(void) {
  puts(check_license("DEMO") ? "licensed" : "unlicensed");
  printf("add_two(7, 3) = %d\n", add_two(7, 3));
  return 0;
}
