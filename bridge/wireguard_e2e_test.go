package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Real WireGuard handshakes over loopback UDP; server HTTP runs only on its
// userspace netstack. Neither side opens a TUN interface or changes OS routes.
const (
	testServerIP = "10.173.91.1"
	testClientIP = "10.173.91.2"
	testHTTPPort = 18080
)

type testPeerKeys struct {
	private string
	public  string
}

func generateTestKeys(t *testing.T) testPeerKeys {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testPeerKeys{
		private: base64.StdEncoding.EncodeToString(key.Bytes()),
		public:  base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
	}
}

func wireGuardPort(t *testing.T, dev *device.Device) int {
	t.Helper()
	status, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(status, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.Atoi(value)
			if err != nil || port == 0 {
				t.Fatalf("invalid WireGuard listen port %q", value)
			}
			return port
		}
	}
	t.Fatal("WireGuard did not report a bound UDP port")
	return 0
}

func hasHandshake(t *testing.T, dev *device.Device) bool {
	t.Helper()
	status, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(status, "\n") {
		if value, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			seconds, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			if seconds > 0 {
				return true
			}
		}
	}
	return false
}

type testWireGuardServer struct {
	device     *device.Device
	keys       testPeerKeys
	clientKeys testPeerKeys
	endpoint   string
	httpServer *http.Server
}

func newTestWireGuardServer(t *testing.T, marker string) *testWireGuardServer {
	t.Helper()
	serverKeys := generateTestKeys(t)
	clientKeys := generateTestKeys(t)
	tun, network, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(testServerIP)}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "aowis-e2e-server: "))
	t.Cleanup(func() { dev.Close() })
	config := fmt.Sprintf(
		"private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(mustDecodeTestKey(t, serverKeys.private)),
		hex.EncodeToString(mustDecodeTestKey(t, clientKeys.public)), testClientIP)
	if err := dev.IpcSet(config); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	port := wireGuardPort(t, dev)
	listener, err := network.ListenTCP(&net.TCPAddr{Port: testHTTPPort})
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/probe" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, "aowis-wireguard-e2e:"+marker)
	})
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second}
	t.Cleanup(func() { _ = httpServer.Close() })
	go func() { _ = httpServer.Serve(listener) }()
	return &testWireGuardServer{
		device: dev, keys: serverKeys, clientKeys: clientKeys,
		endpoint:   net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		httpServer: httpServer,
	}
}

func mustDecodeTestKey(t *testing.T, key string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(data) != 32 {
		t.Fatal("invalid generated test key")
	}
	return data
}

func (server *testWireGuardServer) startClient(t *testing.T, peerPublicKey string) (*tunnelSession, uint16, string, string) {
	t.Helper()
	session, username, password, port, err := startSession(tunnelConfig{
		address: testClientIP + "/32", privateKey: server.clientKeys.private,
		publicKey: peerPublicKey, endpoint: server.endpoint,
		allowedIPs: testServerIP + "/32", mtu: 1420,
	})
	if err != nil {
		t.Fatalf("embedded client startup: %v", err)
	}
	return session, port, username, password
}

func newSOCKSHTTPClient(port uint16, username, password string, timeout time.Duration) *http.Client {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	proxyURL := &url.URL{Scheme: "socks5", Host: address, User: url.UserPassword(username, password)}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	return &http.Client{Transport: transport, Timeout: timeout}
}

func requestThroughTunnel(t *testing.T, port uint16, user, pass, marker string) {
	t.Helper()
	client := newSOCKSHTTPClient(port, user, pass, 5*time.Second)
	defer client.CloseIdleConnections()
	response, err := client.Get(fmt.Sprintf("http://%s:%d/probe", testServerIP, testHTTPPort))
	if err != nil {
		t.Fatalf("HTTP through encrypted tunnel: %v", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(data) != "aowis-wireguard-e2e:"+marker {
		t.Fatalf("wrong tunnel response: status=%d body=%q", response.StatusCode, data)
	}
}

func TestWireGuardE2EEncryptedHTTPAndRestart(t *testing.T) {
	server := newTestWireGuardServer(t, "first")
	session, port, user, pass := server.startClient(t, server.keys.public)
	requestThroughTunnel(t, port, user, pass, "first")
	if !hasHandshake(t, server.device) || !hasHandshake(t, session.device) {
		t.Fatal("HTTP succeeded but WireGuard handshake was not recorded on both peers")
	}
	session.close()
	if conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), 150*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("proxy listener remains open after session shutdown")
	}
	restarted, newPort, newUser, newPass := server.startClient(t, server.keys.public)
	defer restarted.close()
	requestThroughTunnel(t, newPort, newUser, newPass, "first")
}

func TestWireGuardE2EWrongPeerKeyFailsClosed(t *testing.T) {
	server := newTestWireGuardServer(t, "never-expose")
	wrongKeys := generateTestKeys(t)
	session, port, user, pass := server.startClient(t, wrongKeys.public)
	defer session.close()
	client := newSOCKSHTTPClient(port, user, pass, 1500*time.Millisecond)
	defer client.CloseIdleConnections()
	response, err := client.Get(fmt.Sprintf("http://%s:%d/probe", testServerIP, testHTTPPort))
	if err == nil {
		response.Body.Close()
		t.Fatal("wrong WireGuard peer key unexpectedly reached HTTP service")
	}
	if hasHandshake(t, session.device) || hasHandshake(t, server.device) {
		t.Fatal("wrong WireGuard peer key recorded a successful handshake")
	}
}

func TestWireGuardE2EIndependentTunnels(t *testing.T) {
	first := newTestWireGuardServer(t, "alpha")
	second := newTestWireGuardServer(t, "beta")
	one, portOne, userOne, passOne := first.startClient(t, first.keys.public)
	defer one.close()
	two, portTwo, userTwo, passTwo := second.startClient(t, second.keys.public)
	defer two.close()
	requestThroughTunnel(t, portOne, userOne, passOne, "alpha")
	requestThroughTunnel(t, portTwo, userTwo, passTwo, "beta")
	bad := newSOCKSHTTPClient(portTwo, userOne, passOne, 2*time.Second)
	defer bad.CloseIdleConnections()
	response, err := bad.Get(fmt.Sprintf("http://%s:%d/probe", testServerIP, testHTTPPort))
	if err == nil {
		response.Body.Close()
		t.Fatal("tunnel A credentials were accepted by tunnel B")
	}
}

func TestWireGuardE2ENoDirectHostFallback(t *testing.T) {
	server := newTestWireGuardServer(t, "private")
	session, port, user, pass := server.startClient(t, server.keys.public)
	defer session.close()

	// This is an OS-hosted HTTP listener, deliberately outside the tunnel.
	// A bug that bypasses SOCKS5 and uses the host TCP/IP stack would reach it.
	hostListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reached := make(chan struct{}, 1)
	hostServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case reached <- struct{}{}:
		default:
		}
		writer.WriteHeader(http.StatusOK)
	})}
	defer hostServer.Close()
	go func() { _ = hostServer.Serve(hostListener) }()

	client := newSOCKSHTTPClient(port, user, pass, 2*time.Second)
	defer client.CloseIdleConnections()
	response, err := client.Get("http://" + hostListener.Addr().String() + "/")
	if err == nil {
		response.Body.Close()
		t.Fatal("proxy escaped into the host network instead of using its userspace netstack")
	}
	select {
	case <-reached:
		t.Fatal("OS-only HTTP server received traffic that should have stayed in netstack")
	default:
	}
}
