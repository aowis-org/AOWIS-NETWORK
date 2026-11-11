#pragma once

// Hand-maintained ABI boundary matching bridge/main.go //export declarations.
// The Go compiler also emits its own generated header at build time.
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t AowisWGStart(const char* address,
                      const char* dns_servers,
                      const char* private_key,
                      const char* public_key,
                      const char* preshared_key,
                      const char* endpoint,
                      const char* allowed_ips,
                      int mtu,
                      int keepalive_seconds,
                      uint16_t* proxy_port,
                      char* proxy_username,
                      int username_capacity,
                      char* proxy_password,
                      int password_capacity,
                      char* error,
                      int error_capacity);
void AowisWGStop(uint64_t handle);
// One-peer diagnostics, without exposing raw IPC (which includes secrets).
// The endpoint is written as a NUL-terminated string. Returns 1 on success.
int AowisWGReadPeerStats(uint64_t handle, uint64_t* received_bytes,
                         uint64_t* transmitted_bytes, int64_t* last_handshake_seconds,
                         char* endpoint, int endpoint_capacity,
                         char* error, int error_capacity);

#ifdef __cplusplus
}
#endif
