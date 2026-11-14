package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestReresolveStaleness(t *testing.T) {
	firstSend := time.Unix(1700000000, 0)
	if endpointStale(firstSend.Add(time.Hour), time.Time{}, 0) {
		t.Fatal("stale although nothing was ever sent")
	}
	if endpointStale(firstSend.Add(14*time.Second), firstSend, 0) {
		t.Fatal("stale less than 15 s after the first unanswered packet")
	}
	if !endpointStale(firstSend.Add(15*time.Second), firstSend, 0) {
		t.Fatal("not stale 15 s after the first unanswered packet")
	}
	handshake := firstSend.Add(10 * time.Minute)
	if endpointStale(handshake.Add(2*time.Minute), firstSend, handshake.UnixMilli()) {
		t.Fatal("a peer renewing every 2 minutes was reported stale")
	}
	if !endpointStale(handshake.Add(3*time.Minute), firstSend, handshake.UnixMilli()) {
		t.Fatal("handshake 3 minutes old was not reported stale")
	}
	if reresolveSpacing(0) != 15*time.Second || reresolveSpacing(handshake.UnixMilli()) != 30*time.Second {
		t.Fatal("unexpected re-resolution spacing")
	}
}

func TestReresolveNextEndpoint(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	mapped := netip.MustParseAddr("::ffff:192.0.2.3")
	if _, changed := nextPeerEndpoint("192.0.2.1:51820", nil, 51820); changed {
		t.Fatal("changed endpoint without any resolved address")
	}
	if _, changed := nextPeerEndpoint("192.0.2.1:51820", []netip.Addr{first}, 51820); changed {
		t.Fatal("changed endpoint although the name still has only the current address")
	}
	if endpoint, changed := nextPeerEndpoint("192.0.2.1:51820", []netip.Addr{first, second}, 51820); !changed || endpoint.String() != "192.0.2.2:51820" {
		t.Fatalf("no failover to the next address: %v %v", endpoint, changed)
	}
	if endpoint, changed := nextPeerEndpoint("192.0.2.2:51820", []netip.Addr{first, second}, 51820); !changed || endpoint.String() != "192.0.2.1:51820" {
		t.Fatalf("failover does not wrap around: %v %v", endpoint, changed)
	}
	// The name moved (dynamic DNS): use its new address, unmapped.
	if endpoint, changed := nextPeerEndpoint("192.0.2.1:51820", []netip.Addr{mapped}, 51820); !changed || endpoint.String() != "192.0.2.3:51820" {
		t.Fatalf("moved name not followed: %v %v", endpoint, changed)
	}
}
