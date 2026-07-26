// getentropy for Envoy proxy-wasm V8 via Emscripten WASI (clock_time_get).
// Envoy imports wasi_snapshot_preview1.clock_time_get but not random_get.

#include <stddef.h>
#include <stdint.h>
#include <wasi/api.h>

static uint64_t stir(uint64_t state) {
  return state * 6364136223846793005ULL + 1ULL;
}

int getentropy(void *buffer, size_t len) {
  if (buffer == NULL || len == 0 || len > 256) {
    return -1;
  }

  __wasi_timestamp_t realtime = 0;
  __wasi_timestamp_t monotonic = 0;
  if (__wasi_clock_time_get(__WASI_CLOCKID_REALTIME, 1, &realtime) != __WASI_ERRNO_SUCCESS) {
    return -1;
  }
  if (__wasi_clock_time_get(__WASI_CLOCKID_MONOTONIC, 1, &monotonic) != __WASI_ERRNO_SUCCESS) {
    return -1;
  }

  uint64_t state = realtime ^ (monotonic << 1) ^ (uint64_t)(uintptr_t)buffer ^ (uint64_t)len;
  unsigned char *out = (unsigned char *)buffer;
  for (size_t i = 0; i < len; i++) {
    state = stir(state);
    out[i] = (unsigned char)(state ^ (state >> 33) ^ realtime ^ monotonic ^ (uint64_t)i);
  }
  return 0;
}