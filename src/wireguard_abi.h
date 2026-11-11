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
// Returns 1 and fills every output on success; 0 with error text otherwise.
int AowisWGTelemetry(uint64_t handle,
                     int64_t* started_unix_ms,
                     int64_t* last_handshake_unix_ms,
                     uint64_t* rx_bytes,
                     uint64_t* tx_bytes,
                     uint64_t* persistent_keepalive_seconds,
                     uint64_t* active_proxy_connections,
                     uint64_t* accepted_proxy_connections,
                     uint64_t* failed_proxy_dials,
                     char* endpoint,
                     int endpoint_capacity,
                     char* error,
                     int error_capacity);

#ifdef __cplusplus
}
#endif
