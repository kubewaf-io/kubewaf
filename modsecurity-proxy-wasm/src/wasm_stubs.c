// libc/syscall stubs unavailable in Envoy proxy-wasm V8 (see src/wasm_getentropy.c for RNG).
//
// Signatures must match Emscripten's WASI/libc stubs used under LTO (emsdk 3.x).
// Mismatch examples cause: wasm-ld: warning: function signature mismatch: __syscall_fchmod

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

// fchmod(fd, mode) — two i32 args (not three; older stubs were wrong under emsdk 3.x LTO).
int __syscall_fchmod(int fd, int mode) {
  (void)fd;
  (void)mode;
  return -1;
}

// chmod(path, mode)
int __syscall_chmod(const char *path, int mode) {
  (void)path;
  (void)mode;
  return -1;
}

// unlinkat(dirfd, path, flags)
int __syscall_unlinkat(int dirfd, const char *path, int flags) {
  (void)dirfd;
  (void)path;
  (void)flags;
  return -1;
}
