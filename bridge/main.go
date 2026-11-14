// AOWIS-Network embedded WireGuard engine. No OS TUN devices or processes.
// The C ABI is intentionally small; do not expose Go object pointers to C++.
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type tunnelSession struct {
	device  *device.Device
	network *netstack.Net
	proxy   *proxyServer
	started time.Time
	// mu serializes telemetry sampling against close(): IpcGet() is never
	// called on a device that is being or has been closed.
	mu     sync.Mutex
	closed bool

	// Endpoint re-resolution (see monitorEndpoint). Only for host names;
	// numeric endpoints never change and get no monitor.
	peerHost      string
	peerPort      uint16
	peerPublicHex string
	resolve       func(context.Context, string) ([]netip.Addr, error)
	monitorCancel context.CancelFunc
	monitorDone   chan struct{}
	// Monitor goroutine only: when traffic was first seen without any
	// handshake yet, and when the name was last re-resolved.
	firstSend     time.Time
	lastReresolve time.Time
}

// The 135 s threshold is wireguard-tools' reresolve-dns.sh: sessions renew
// every 120 s (REKEY_AFTER_TIME) while packets flow, plus a retry margin,
// so a live peer never reaches it. The name is resolved once at start.
//
// Before the first handshake a much shorter limit applies, counted from the
// first packet sent: a name with several addresses (typically IPv6 and
// IPv4) is started on the first one, and at a site without working IPv6 the
// tunnel otherwise stayed dead for over two minutes before trying IPv4.
// wireguard-go retransmits a handshake initiation every 5 s, so 15 s is
// three unanswered initiations to one address.
const (
	reresolveStaleAfter      = 135 * time.Second
	firstHandshakeStaleAfter = 15 * time.Second
	reresolveCheckInterval   = 5 * time.Second
	reresolveMinimumSpacing  = 30 * time.Second
	reresolveLookupTimeout   = 5 * time.Second
)

// endpointStale reports whether the peer endpoint should be re-resolved:
// no handshake for reresolveStaleAfter after the last one, or, while there
// has never been one, firstHandshakeStaleAfter after the first packet sent
// (firstSend zero: nothing sent yet, nothing to judge).
func endpointStale(now, firstSend time.Time, lastHandshakeUnixMs int64) bool {
	if lastHandshakeUnixMs > 0 {
		return now.Sub(time.UnixMilli(lastHandshakeUnixMs)) >= reresolveStaleAfter
	}
	return !firstSend.IsZero() && now.Sub(firstSend) >= firstHandshakeStaleAfter
}

// reresolveSpacing is the minimum time between two re-resolutions: short
// while no handshake ever succeeded (each address gets its 15 s), otherwise
// long enough that a peer that is down for hours does not cause a DNS query
// every check interval.
func reresolveSpacing(lastHandshakeUnixMs int64) time.Duration {
	if lastHandshakeUnixMs == 0 {
		return firstHandshakeStaleAfter
	}
	return reresolveMinimumSpacing
}

// nextPeerEndpoint picks the endpoint to try after a stale period: the
// address after the current one when the name still resolves to it (fails
// over across multi-address hosts), else the first address (the name moved).
// Returns false when that is the endpoint already in use.
func nextPeerEndpoint(current string, addresses []netip.Addr, port uint16) (netip.AddrPort, bool) {
	if len(addresses) == 0 {
		return netip.AddrPort{}, false
	}
	candidate := netip.AddrPortFrom(addresses[0].Unmap(), port)
	for index, address := range addresses {
		if netip.AddrPortFrom(address.Unmap(), port).String() == current {
			candidate = netip.AddrPortFrom(addresses[(index+1)%len(addresses)].Unmap(), port)
			break
		}
	}
	return candidate, candidate.String() != current
}

func (session *tunnelSession) monitorEndpoint(ctx context.Context) {
	defer close(session.monitorDone)
	ticker := time.NewTicker(reresolveCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			session.reresolveIfStale(ctx, now)
		}
	}
}

// reresolveIfStale re-resolves the peer host name once its handshake is
// stale and points the peer at the next address. wireguard-go keeps
// retrying handshakes itself; it only needs to be told a new address.
func (session *tunnelSession) reresolveIfStale(ctx context.Context, now time.Time) {
	sample, err := session.telemetry()
	if err != nil {
		return
	}
	if sample.lastHandshakeUnixMs == 0 && sample.txBytes > 0 && session.firstSend.IsZero() {
		session.firstSend = now
	}
	if !endpointStale(now, session.firstSend, sample.lastHandshakeUnixMs) {
		return
	}
	if !session.lastReresolve.IsZero() &&
		now.Sub(session.lastReresolve) < reresolveSpacing(sample.lastHandshakeUnixMs) {
		return
	}
	session.lastReresolve = now
	lookup, cancel := context.WithTimeout(ctx, reresolveLookupTimeout)
	addresses, err := session.resolve(lookup, session.peerHost)
	cancel()
	if err != nil {
		return // Keep the current endpoint; try again next interval.
	}
	endpoint, changed := nextPeerEndpoint(sample.endpoint, addresses, session.peerPort)
	if !changed {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return
	}
	if err := session.device.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n",
		session.peerPublicHex, endpoint.String())); err != nil {
		return // Keep the current endpoint; try again next interval.
	}
	if sample.lastHandshakeUnixMs == 0 {
		// The new address gets its own first-handshake period.
		session.firstSend = now
	}
}

var (
	sessionMu sync.Mutex
	sessions  = make(map[uint64]*tunnelSession)
	nextID    atomic.Uint64
)

func (session *tunnelSession) close() {
	// Stop the monitor first and outside mu: it takes mu itself, and a
	// pending lookup is cancelled rather than awaited.
	if session.monitorCancel != nil {
		session.monitorCancel()
		<-session.monitorDone
		session.monitorCancel = nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return
	}
	session.closed = true
	session.proxy.close()
	session.device.Close()
}

// tunnelTelemetry is redacted runtime state: counters, timestamps and the
// resolved numeric peer endpoint. It never carries keys or configuration.
type tunnelTelemetry struct {
	startedUnixMs            int64
	lastHandshakeUnixMs      int64 // 0: no handshake has completed yet
	rxBytes                  uint64
	txBytes                  uint64
	persistentKeepalive      uint64
	endpoint                 string
	activeProxyConnections   uint64
	acceptedProxyConnections uint64
	failedProxyDials         uint64
}

// parsePeerTelemetry reads the documented wireguard-go UAPI "get" fields of
// the single configured peer. Unknown keys (allowed_ip, protocol_version,
// public_key, ...) are ignored; private_key and preshared_key are never kept.
func parsePeerTelemetry(status string, out *tunnelTelemetry) error {
	var handshakeSeconds, handshakeNanoseconds int64
	peers := 0
	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		var err error
		switch key {
		case "public_key":
			peers++
		case "endpoint":
			out.endpoint = value
		case "last_handshake_time_sec":
			handshakeSeconds, err = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			handshakeNanoseconds, err = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			out.rxBytes, err = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			out.txBytes, err = strconv.ParseUint(value, 10, 64)
		case "persistent_keepalive_interval":
			out.persistentKeepalive, err = strconv.ParseUint(value, 10, 64)
		}
		if err != nil {
			return fmt.Errorf("invalid WireGuard status field %s", key)
		}
	}
	if peers != 1 {
		return errors.New("WireGuard status does not describe exactly one peer")
	}
	// wireguard-go reports 0/0 until the first handshake completes.
	if handshakeSeconds > 0 || handshakeNanoseconds > 0 {
		out.lastHandshakeUnixMs = handshakeSeconds*1000 + handshakeNanoseconds/1000000
	}
	return nil
}

func (session *tunnelSession) telemetry() (tunnelTelemetry, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return tunnelTelemetry{}, errors.New("WireGuard tunnel is stopped")
	}
	status, err := session.device.IpcGet()
	if err != nil {
		return tunnelTelemetry{}, fmt.Errorf("WireGuard status: %w", err)
	}
	result := tunnelTelemetry{startedUnixMs: session.started.UnixMilli()}
	if err := parsePeerTelemetry(status, &result); err != nil {
		return tunnelTelemetry{}, err
	}
	result.activeProxyConnections = session.proxy.active.Load()
	result.acceptedProxyConnections = session.proxy.accepted.Load()
	result.failedProxyDials = session.proxy.failedDials.Load()
	return result, nil
}

type tunnelConfig struct {
	address      string
	dns          string
	privateKey   string
	publicKey    string
	presharedKey string
	endpoint     string
	allowedIPs   string
	mtu          int
	keepalive    int
}

func decodeKey(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("WireGuard key must be 32 bytes encoded as base64")
	}
	return hex.EncodeToString(decoded), nil
}

func parseAddress(value string) (netip.Addr, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr(), nil
	}
	return netip.ParseAddr(value)
}

func parseAddresses(input string) ([]netip.Addr, error) {
	if input == "" {
		return nil, nil
	}
	parts := strings.Split(input, ",")
	result := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		address, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || address.IsUnspecified() {
			return nil, errors.New("invalid tunnel DNS address")
		}
		result = append(result, address)
	}
	return result, nil
}

// wireguard-go's IPC accepts only a numeric UDP endpoint. Resolve the
// outer peer on the host before starting the private network stack.
func resolvePeerEndpoint(endpoint string) (netip.AddrPort, error) {
	if endpoint == "" {
		return netip.AddrPort{}, errors.New("missing WireGuard peer endpoint")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || strings.ContainsAny(host, "\r\n\t ") {
		return netip.AddrPort{}, errors.New("invalid WireGuard peer endpoint")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return netip.AddrPort{}, errors.New("invalid WireGuard peer UDP port")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("resolve WireGuard peer %q: %w", host, err)
		}
		if len(addresses) == 0 {
			return netip.AddrPort{}, fmt.Errorf("no IP addresses for WireGuard peer %q", host)
		}
		addr = addresses[0]
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(portNumber)), nil
}

func validateConfig(config tunnelConfig) ([]netip.Addr, []netip.Addr, string, error) {
	address, err := parseAddress(config.address)
	if err != nil || address.IsUnspecified() {
		return nil, nil, "", errors.New("invalid WireGuard tunnel address")
	}
	dns, err := parseAddresses(config.dns)
	if err != nil {
		return nil, nil, "", err
	}
	if config.mtu < 576 || config.mtu > 65535 || config.keepalive < 0 || config.keepalive > 65535 {
		return nil, nil, "", errors.New("invalid WireGuard MTU or keepalive")
	}
	private, err := decodeKey(config.privateKey)
	if err != nil {
		return nil, nil, "", err
	}
	public, err := decodeKey(config.publicKey)
	if err != nil {
		return nil, nil, "", err
	}
	if config.allowedIPs == "" {
		return nil, nil, "", errors.New("missing WireGuard allowed IPs")
	}
	var ipc strings.Builder
	fmt.Fprintf(&ipc, "private_key=%s\nreplace_peers=true\npublic_key=%s\n", private, public)
	if config.presharedKey != "" {
		preshared, err := decodeKey(config.presharedKey)
		if err != nil {
			return nil, nil, "", err
		}
		fmt.Fprintf(&ipc, "preshared_key=%s\n", preshared)
	}
	peer, err := resolvePeerEndpoint(config.endpoint)
	if err != nil {
		return nil, nil, "", err
	}
	fmt.Fprintf(&ipc, "endpoint=%s\npersistent_keepalive_interval=%d\n", peer.String(), config.keepalive)
	for _, item := range strings.Split(config.allowedIPs, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			return nil, nil, "", errors.New("invalid WireGuard allowed IP prefix")
		}
		fmt.Fprintf(&ipc, "allowed_ip=%s\n", prefix.Masked().String())
	}
	return []netip.Addr{address}, dns, ipc.String(), nil
}

func startSession(config tunnelConfig) (*tunnelSession, string, string, uint16, error) {
	addresses, dns, ipc, err := validateConfig(config)
	if err != nil {
		return nil, "", "", 0, err
	}
	tun, tnet, err := netstack.CreateNetTUN(addresses, dns, config.mtu)
	if err != nil {
		return nil, "", "", 0, fmt.Errorf("userspace netstack: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "aowis-network: "))
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, "", "", 0, fmt.Errorf("WireGuard peer configuration: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, "", "", 0, fmt.Errorf("WireGuard startup: %w", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		dev.Close()
		return nil, "", "", 0, fmt.Errorf("local proxy listener: %w", err)
	}
	username, err := randomToken()
	if err != nil {
		listener.Close()
		dev.Close()
		return nil, "", "", 0, err
	}
	password, err := randomToken()
	if err != nil {
		listener.Close()
		dev.Close()
		return nil, "", "", 0, err
	}
	proxy := newProxyServer(listener, username, password, tnet.DialContext)
	proxy.start()
	session := &tunnelSession{device: dev, network: tnet, proxy: proxy, started: time.Now()}
	if err := session.startEndpointMonitor(config); err != nil {
		session.close()
		return nil, "", "", 0, err
	}
	return session, username, password, uint16(listener.Addr().(*net.TCPAddr).Port), nil
}

func (session *tunnelSession) startEndpointMonitor(config tunnelConfig) error {
	host, port, err := net.SplitHostPort(config.endpoint)
	if err != nil {
		return errors.New("invalid WireGuard peer endpoint")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil // Numeric endpoint: nothing to re-resolve.
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("invalid WireGuard peer UDP port")
	}
	public, err := decodeKey(config.publicKey)
	if err != nil {
		return err
	}
	session.peerHost = host
	session.peerPort = uint16(portNumber)
	session.peerPublicHex = public
	session.resolve = func(ctx context.Context, name string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	}
	ctx, cancel := context.WithCancel(context.Background())
	session.monitorCancel = cancel
	session.monitorDone = make(chan struct{})
	go session.monitorEndpoint(ctx)
	return nil
}

func randomToken() (string, error) {
	var bytes [24]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func writeCString(out *C.char, capacity C.int, value string) bool {
	if out == nil || capacity < 1 || len(value) >= int(capacity) {
		return false
	}
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(capacity))
	copy(buffer, value)
	buffer[len(value)] = 0
	return true
}

//export AowisWGStart
func AowisWGStart(address, dns, privateKey, publicKey, presharedKey, endpoint, allowedIPs *C.char,
	mtu, keepalive C.int, proxyPort *C.uint16_t, username *C.char, usernameCapacity C.int,
	password *C.char, passwordCapacity C.int, errorOut *C.char, errorCapacity C.int) C.uint64_t {
	if proxyPort == nil || username == nil || password == nil || errorOut == nil ||
		usernameCapacity < 49 || passwordCapacity < 49 || errorCapacity < 2 ||
		address == nil || dns == nil || privateKey == nil || publicKey == nil ||
		presharedKey == nil || endpoint == nil || allowedIPs == nil {
		writeCString(errorOut, errorCapacity, "invalid WireGuard ABI arguments")
		return 0
	}
	config := tunnelConfig{
		address: C.GoString(address), dns: C.GoString(dns),
		privateKey: C.GoString(privateKey), publicKey: C.GoString(publicKey),
		presharedKey: C.GoString(presharedKey), endpoint: C.GoString(endpoint),
		allowedIPs: C.GoString(allowedIPs), mtu: int(mtu), keepalive: int(keepalive),
	}
	session, user, pass, port, err := startSession(config)
	if err != nil {
		writeCString(errorOut, errorCapacity, err.Error())
		return 0
	}
	if !writeCString(username, usernameCapacity, user) || !writeCString(password, passwordCapacity, pass) {
		session.close()
		writeCString(errorOut, errorCapacity, "proxy credentials buffer too small")
		return 0
	}
	id := nextID.Add(1)
	sessionMu.Lock()
	sessions[id] = session
	sessionMu.Unlock()
	*proxyPort = C.uint16_t(port)
	writeCString(errorOut, errorCapacity, "")
	return C.uint64_t(id)
}

//export AowisWGStop
func AowisWGStop(handle C.uint64_t) {
	sessionMu.Lock()
	session := sessions[uint64(handle)]
	delete(sessions, uint64(handle))
	sessionMu.Unlock()
	if session != nil {
		session.close()
	}
}

//export AowisWGTelemetry
func AowisWGTelemetry(handle C.uint64_t, startedUnixMs, lastHandshakeUnixMs *C.int64_t,
	rxBytes, txBytes, persistentKeepalive, activeProxy, acceptedProxy, failedDials *C.uint64_t,
	endpoint *C.char, endpointCapacity C.int, errorOut *C.char, errorCapacity C.int) C.int {
	if startedUnixMs == nil || lastHandshakeUnixMs == nil || rxBytes == nil || txBytes == nil ||
		persistentKeepalive == nil || activeProxy == nil || acceptedProxy == nil ||
		failedDials == nil || endpoint == nil || endpointCapacity < 2 ||
		errorOut == nil || errorCapacity < 2 {
		writeCString(errorOut, errorCapacity, "invalid WireGuard ABI arguments")
		return 0
	}
	sessionMu.Lock()
	session := sessions[uint64(handle)]
	sessionMu.Unlock()
	if session == nil {
		writeCString(errorOut, errorCapacity, "unknown WireGuard tunnel")
		return 0
	}
	sample, err := session.telemetry()
	if err != nil {
		writeCString(errorOut, errorCapacity, err.Error())
		return 0
	}
	if !writeCString(endpoint, endpointCapacity, sample.endpoint) {
		writeCString(errorOut, errorCapacity, "endpoint buffer too small")
		return 0
	}
	*startedUnixMs = C.int64_t(sample.startedUnixMs)
	*lastHandshakeUnixMs = C.int64_t(sample.lastHandshakeUnixMs)
	*rxBytes = C.uint64_t(sample.rxBytes)
	*txBytes = C.uint64_t(sample.txBytes)
	*persistentKeepalive = C.uint64_t(sample.persistentKeepalive)
	*activeProxy = C.uint64_t(sample.activeProxyConnections)
	*acceptedProxy = C.uint64_t(sample.acceptedProxyConnections)
	*failedDials = C.uint64_t(sample.failedProxyDials)
	writeCString(errorOut, errorCapacity, "")
	return 1
}

func main() {}
