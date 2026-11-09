// AOWIS-Network embedded WireGuard engine. No OS TUN devices or processes.
// The C ABI is intentionally small; do not expose Go object pointers to C++.
package main

/*
#include <stdint.h>
*/
import "C"

import (
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
	"unsafe"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type tunnelSession struct {
	device *device.Device
	proxy  *proxyServer
}

var (
	sessionMu sync.Mutex
	sessions  = make(map[uint64]*tunnelSession)
	nextID    atomic.Uint64
)

func (session *tunnelSession) close() {
	session.proxy.close()
	session.device.Close()
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
	if config.endpoint == "" {
		return nil, nil, "", errors.New("missing WireGuard peer endpoint")
	}
	host, port, err := net.SplitHostPort(config.endpoint)
	if err != nil || host == "" || strings.ContainsAny(host, "\r\n\t ") {
		return nil, nil, "", errors.New("invalid WireGuard peer endpoint")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, nil, "", errors.New("invalid WireGuard peer UDP port")
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
	fmt.Fprintf(&ipc, "endpoint=%s\npersistent_keepalive_interval=%d\n", config.endpoint, config.keepalive)
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
	session := &tunnelSession{device: dev, proxy: proxy}
	return session, username, password, uint16(listener.Addr().(*net.TCPAddr).Port), nil
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

func main() {}
