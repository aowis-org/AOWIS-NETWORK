package main

import (
	"strings"
	"testing"
)

func TestPeerStatsParser(t *testing.T) {
	sample := "private_key=supersecret\npublic_key=not-a-secret\nendpoint=127.0.0.1:51820\nrx_bytes=12345\ntx_bytes=6789\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=1\npreshared_key=anothersecret\n"
	got, err := parsePeerStats(sample)
	if err != nil || got.receivedBytes != 12345 || got.transmittedBytes != 6789 ||
		got.handshakeSeconds != 1700000000 || got.endpoint != "127.0.0.1:51820" {
		t.Fatalf("wrong parsed statistics: %+v, %v", got, err)
	}
	for _, modified := range []string{
		strings.Replace(sample, "rx_bytes=12345", "rx_bytes=garbage", 1),
		strings.Replace(sample, "tx_bytes=6789", "tx_bytes=-1", 1),
		strings.Replace(sample, "last_handshake_time_sec=1700000000", "last_handshake_time_sec=-1", 1),
		strings.Replace(sample, "endpoint=127.0.0.1:51820", "endpoint=invalid", 1),
		strings.Replace(sample, "public_key=not-a-secret", "", 1),
		sample + "public_key=secondpeer\n",
		sample + "rx_bytes=5432\n",
	} {
		_, err := parsePeerStats(modified)
		if err == nil || strings.Contains(err.Error(), "supersecret") || strings.Contains(err.Error(), "anothersecret") {
			t.Fatalf("invalid stats were accepted or secrets appeared in error: %v", err)
		}
	}
}

func TestPeerStatsBeforeHandshake(t *testing.T) {
	// Some wireguard-go versions omit the handshake fields until the first exchange.
	got, err := parsePeerStats("public_key=x\nrx_bytes=0\ntx_bytes=0\n")
	if err != nil || got.handshakeSeconds != 0 || got.receivedBytes != 0 {
		t.Fatalf("missing handshake must not imply failure: %+v %v", got, err)
	}
}
