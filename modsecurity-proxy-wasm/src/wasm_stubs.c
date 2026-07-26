// libc/syscall stubs unavailable in Envoy proxy-wasm V8 (see src/wasm_getentropy.c for RNG).

#include <stddef.h>

int wordexp(const char *wordexp_wordlist, void *pwordexp, int flags) {
  (void)wordexp_wordlist;
  (void)pwordexp;
  (void)flags;
  return -1;
}

void wordfree(void *wordexp_t) { (void)wordexp_t; }

int getaddrinfo(const char *node, const char *service, const void *hints, void **res) {
  (void)node;
  (void)service;
  (void)hints;
  if (res) {
    *res = 0;
  }
  return -1;
}

void freeaddrinfo(void *res) { (void)res; }

int __syscall_fchmod(int a, int b, int c) {
  (void)a;
  (void)b;
  (void)c;
  return -1;
}

int __syscall_chmod(const char *p, int m) {
  (void)p;
  (void)m;
  return -1;
}

int __syscall_unlinkat(int d, const char *p, int f) {
  (void)d;
  (void)p;
  (void)f;
  return -1;
}