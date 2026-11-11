package main

import (
	"strings"
	"testing"
)

// UAPI "get" output as produced by wireguard-go for one configured peer.
// Keys are placeholders; the parser must ignore and never retain them.
const telemetrySample = "private_key=0000000000000000000000000000000000000000000000000000000000000001\n" +
	"listen_port=40000\n" +
	"public_key=0000000000000000000000000000000000000000000000000000000000000002\n" +
	"preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n" +
	"protocol_version=1\n" +
	"endpoint=192.0.2.10:51820\n" +
	"last_handshake_time_sec=1700000000\n" +
	"last_handshake_time_nsec=250000000\n" +
	"tx_bytes=1480\n" +
	"rx_bytes=92\n" +
	"persistent_keepalive_interval=25\n" +
	"allowed_ip=10.50.0.0/24\n\n"

func TestTelemetryParsesPeerStatus(t *testing.T) {
	var sample tunnelTelemetry
	if err := parsePeerTelemetry(telemetrySample, &sample); err != nil {
		t.Fatal(err)
	}
	if sample.endpoint != "192.0.2.10:51820" || sample.rxBytes != 92 || sample.txBytes != 1480 ||
		sample.persistentKeepalive != 25 || sample.lastHandshakeUnixMs != 1700000000250 {
		t.Fatalf("unexpected telemetry %+v", sample)
	}
}

func TestTelemetryReportsMissingHandshakeAsZero(t *testing.T) {
	status := strings.Replace(telemetrySample, "last_handshake_time_sec=1700000000", "last_handshake_time_sec=0", 1)
	status = strings.Replace(status, "last_handshake_time_nsec=250000000", "last_handshake_time_nsec=0", 1)
	var sample tunnelTelemetry
	if err := parsePeerTelemetry(status, &sample); err != nil {
		t.Fatal(err)
	}
	if sample.lastHandshakeUnixMs != 0 {
		t.Fatalf("absent handshake reported as %d", sample.lastHandshakeUnixMs)
	}
}

func TestTelemetryRejectsMalformedStatus(t *testing.T) {
	var sample tunnelTelemetry
	if err := parsePeerTelemetry(strings.Replace(telemetrySample, "rx_bytes=92", "rx_bytes=x", 1), &sample); err == nil {
		t.Fatal("accepted malformed counter")
	}
	if err := parsePeerTelemetry("listen_port=1\n", &sample); err == nil {
		t.Fatal("accepted status without a peer")
	}
}
