package main

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// readPeerStats selects only non-secret fields from wireguard-go's IPC.
// IpcGet also contains private and preshared keys: NEVER return or log it.
// This embedded client configures exactly one peer per tunnel.
type peerStats struct {
	receivedBytes    uint64
	transmittedBytes uint64
	handshakeSeconds int64
	endpoint         string
}

func parsePeerStats(ipc string) (peerStats, error) {
	var stats peerStats
	var peerCount int
	var received, transmitted, handshake, endpointSeen bool
	for _, line := range strings.Split(ipc, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			peerCount++
		case "rx_bytes":
			if received {
				return peerStats{}, errors.New("duplicate WireGuard received counter")
			}
			number, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return peerStats{}, errors.New("invalid WireGuard received counter")
			}
			stats.receivedBytes, received = number, true
		case "tx_bytes":
			if transmitted {
				return peerStats{}, errors.New("duplicate WireGuard sent counter")
			}
			number, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return peerStats{}, errors.New("invalid WireGuard sent counter")
			}
			stats.transmittedBytes, transmitted = number, true
		case "last_handshake_time_sec":
			if handshake {
				return peerStats{}, errors.New("duplicate WireGuard handshake timestamp")
			}
			number, err := strconv.ParseInt(value, 10, 64)
			if err != nil || number < 0 {
				return peerStats{}, errors.New("invalid WireGuard handshake timestamp")
			}
			stats.handshakeSeconds, handshake = number, true
		case "endpoint":
			if endpointSeen {
				return peerStats{}, errors.New("duplicate WireGuard peer endpoint")
			}
			if _, err := netip.ParseAddrPort(value); err != nil {
				return peerStats{}, errors.New("invalid WireGuard peer endpoint")
			}
			stats.endpoint, endpointSeen = value, true
		}
	}
	if peerCount != 1 || !received || !transmitted {
		return peerStats{}, errors.New("WireGuard peer statistics unavailable")
	}
	return stats, nil
}
