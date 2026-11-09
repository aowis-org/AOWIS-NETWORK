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

#ifdef __cplusplus
}
#endif
