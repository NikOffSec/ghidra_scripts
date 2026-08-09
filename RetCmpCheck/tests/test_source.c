/*
 * Make sure to call each function at least 4 times to trigger script (unless
 * you changed it)
 *
 * Build:  gcc -O1 -fno-inline -g -o compiled_test test_source.c
 * (if you want cleaner decompilation)
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Keeps the optimizer from deleting results we never use
volatile uintptr_t sink;

struct rec {
  int id;
  char name[32];
};

//  malloc -- 5 call sites: 4 check the result, 1 does not.

__attribute__((noinline)) struct rec *rec_new(int id) {
  struct rec *r = malloc(sizeof *r); // site 1 -- checked
  if (r == NULL)
    return NULL;
  r->id = id;
  return r;
}

__attribute__((noinline)) char *str_copy(const char *s) {
  char *b = malloc(strlen(s) + 1); // site 2 -- checked
  if (!b)
    return NULL;
  strcpy(b, s);
  return b;
}

__attribute__((noinline)) int *int_array(int n) {
  int *v = malloc(n * sizeof(int)); // site 3 -- checked
  if (v == NULL)
    return NULL;
  v[0] = n;
  return v;
}

__attribute__((noinline)) char *make_buf(size_t n) {
  char *b = malloc(n); // site 4 -- checked
  if (b != NULL) {
    b[0] = 'x';
    return b;
  }
  return NULL;
}

// BUG 1: no NULL check, then dereferences. */
__attribute__((noinline)) struct rec *rec_new_bad(int id) {
  struct rec *r = malloc(sizeof *r); // site 5 -- BUG
  r->id = id;                        // crashes if malloc failed
  return r;
}

// strchr -- 5 call sites: 4 check the result, 1 does not.

__attribute__((noinline)) int split_colon(char *s) {
  char *c = strchr(s, ':'); // site 6 -- checked
  if (c == NULL)
    return -1;
  *c = '\0';
  return 0;
}

__attribute__((noinline)) int split_equals(char *s) {
  char *c = strchr(s, '='); // site 7 -- checked
  if (!c)
    return -1;
  *c = '\0';
  return 0;
}

__attribute__((noinline)) int split_comma(char *s) {
  char *c = strchr(s, ','); // site 8 -- checked
  if (c != NULL) {
    *c = '\0';
    return 0;
  }
  return -1;
}

__attribute__((noinline)) int has_at_sign(const char *s) {
  const char *c = strchr(s, '@'); // site 9 -- checked
  if (c == NULL)
    return 0;
  return 1;
}

// BUG 2: no NULL check, then dereferences.
__attribute__((noinline)) int split_semi_bad(char *s) {
  char *c = strchr(s, ';'); // site 10 -- BUG
  *c = '\0';                // crashes if ';' is absent
  return 0;
}

// open -- 5 call sites: 4 check the result, 1 does not.

__attribute__((noinline)) int file_exists(const char *path) {
  int fd = open(path, O_RDONLY); // site 11 -- checked (< 0)
  if (fd < 0)
    return 0;
  close(fd);
  return 1;
}

__attribute__((noinline)) int file_open_ro(const char *path) {
  int fd = open(path, O_RDONLY); // site 12 -- checked (== -1)
  if (fd == -1)
    return -1;
  close(fd);
  return 0;
}

__attribute__((noinline)) int file_open_rw(const char *path) {
  int fd = open(path, O_RDWR); // site 13 -- checked (>= 0)
  if (fd >= 0) {
    close(fd);
    return 0;
  }
  return -1;
}

__attribute__((noinline)) int file_touch(const char *path) {
  int fd = open(path, O_WRONLY | O_CREAT, 0644); // site 14 -- checked
  if (fd < 0)
    return -1;
  close(fd);
  return 0;
}

// BUG 3: fd is never tested; read() runs on a possibly-invalid fd.
__attribute__((noinline)) int file_peek_bad(const char *path, char *out) {
  int fd = open(path, O_RDONLY); // site 15 -- BUG */
  read(fd, out, 16);
  return 0;
}

// getenv -- 4 call sites, ALL checked. Nothing should be reported
//
__attribute__((noinline)) int read_config(void) {
  const char *a = getenv("PATH"); // site 16 -- checked
  if (a == NULL)
    return -1;

  const char *b = getenv("HOME"); // site 17 -- checked
  if (b == NULL)
    return -1;

  const char *c = getenv("USER"); // site 18 -- checked
  if (c == NULL)
    return -1;

  const char *d = getenv("SHELL"); // site 19 -- checked
  if (d == NULL)
    return -1;

  sink += (uintptr_t)a + (uintptr_t)b + (uintptr_t)c + (uintptr_t)d;
  return 0;
}

// main -- calls everything so nothing gets optimized away.

int main(int argc, char **argv) {
  char text[64] = "user:name=a,b@host;port";
  char buf[32];

  sink += (uintptr_t)rec_new(argc);
  sink += (uintptr_t)str_copy(text);
  sink += (uintptr_t)int_array(4);
  sink += (uintptr_t)make_buf(16);
  sink += (uintptr_t)rec_new_bad(argc);

  sink += split_colon(text);
  sink += split_equals(text);
  sink += split_comma(text);
  sink += has_at_sign(text);
  sink += split_semi_bad(text);

  sink += file_exists(argv[0]);
  sink += file_open_ro(argv[0]);
  sink += file_open_rw("/tmp/bench_test");
  sink += file_touch("/tmp/bench_test");
  sink += file_peek_bad(argv[0], buf);

  sink += read_config();

  return (int)(sink & 1);
}
