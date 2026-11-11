package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestReresolveStaleness(t *testing.T) {
	started := time.Unix(1700000000, 0)
	if endpointStale(started.Add(134*time.Second), started, 0) {
		t.Fatal("stale before 135 s without a first handshake")
	}
	if !endpointStale(started.Add(135*time.Second), started, 0) {
		t.Fatal("not stale 135 s after start without a handshake")
	}
	handshake := started.Add(10 * time.Minute)
	if endpointStale(handshake.Add(2*time.Minute), started, handshake.UnixMilli()) {
		t.Fatal("a peer renewing every 2 minutes was reported stale")
	}
	if !endpointStale(handshake.Add(3*time.Minute), started, handshake.UnixMilli()) {
		t.Fatal("handshake 3 minutes old was not reported stale")
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
