package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aowis-org/AOWIS-NETWORK/bridge/internal/testdns"
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
	// Reserved TLD (RFC 6761): never resolvable outside the test tunnel.
	testServiceName = "dvmdb.aowis.test"
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
	network    *netstack.Net
	keys       testPeerKeys
	clientKeys testPeerKeys
	endpoint   string
	httpServer *http.Server
	hits       atomic.Int64
	serveError chan error
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
	t.Cleanup(func() {
		start := time.Now()
		dev.Close()
		t.Logf("phase server WireGuard device shutdown: %s", time.Since(start).Round(time.Millisecond))
	})
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
	server := &testWireGuardServer{
		device: dev, network: network, keys: serverKeys, clientKeys: clientKeys,
		endpoint:   net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		serveError: make(chan error, 1),
	}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		server.hits.Add(1)
		if request.URL.Path != "/probe" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, "aowis-wireguard-e2e:"+marker)
	})
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second}
	t.Cleanup(func() {
		start := time.Now()
		_ = httpServer.Close()
		t.Logf("phase server HTTP shutdown: %s", time.Since(start).Round(time.Millisecond))
	})
	server.httpServer = httpServer
	go func() {
		if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			server.serveError <- err
		}
	}()
	return server
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
	return server.startClientWithDNS(t, peerPublicKey, "")
}

// dns: the client profile's "DNS =" (comma-separated); empty: none.
func (server *testWireGuardServer) startClientWithDNS(t *testing.T, peerPublicKey, dns string) (*tunnelSession, uint16, string, string) {
	t.Helper()
	session, username, password, port, err := startSession(tunnelConfig{
		address: testClientIP + "/32", dns: dns, privateKey: server.clientKeys.private,
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

// Only report publicly observable WireGuard counters and endpoints. IpcGet
// includes private and preshared keys: NEVER put its raw output in logs.
func peerDiagnostics(dev *device.Device) string {
	status, err := dev.IpcGet()
	if err != nil {
		return "WireGuard status unavailable: " + err.Error()
	}
	var selected []string
	for _, line := range strings.Split(status, "\n") {
		for _, prefix := range []string{
			"listen_port=", "endpoint=", "last_handshake_time_sec=",
			"tx_bytes=", "rx_bytes=", "allowed_ip=",
		} {
			if strings.HasPrefix(line, prefix) {
				selected = append(selected, line)
				break
			}
		}
	}
	return strings.Join(selected, ", ")
}

func directNetstackProbe(session *tunnelSession) string {
	// Diagnostic only. Never use the host TCP/IP stack as fallback.
	transport := &http.Transport{DialContext: session.network.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(fmt.Sprintf("http://%s:%d/probe", testServerIP, testHTTPPort))
	if err != nil {
		return "failed: " + err.Error()
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "body read failed: " + err.Error()
	}
	return fmt.Sprintf("HTTP %d, body=%q", response.StatusCode, data)
}

func requestThroughTunnel(t *testing.T, server *testWireGuardServer, session *tunnelSession, port uint16, user, pass, marker string) {
	t.Helper()
	started := time.Now()
	// The WireGuard handshake retry interval is ~5 seconds. A 5-second HTTP
	// timeout can prematurely kill the first (cold-start) handshake attempt.
	client := newSOCKSHTTPClient(port, user, pass, 12*time.Second)
	defer client.CloseIdleConnections()
	var mu sync.Mutex
	var stages []string
	appendStage := func(stage string) {
		mu.Lock()
		stages = append(stages, fmt.Sprintf("+%s %s", time.Since(started).Round(time.Millisecond), stage))
		mu.Unlock()
	}
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn:              func(httptrace.GotConnInfo) { appendStage("SOCKS5 CONNECT completed") },
		WroteRequest:         func(info httptrace.WroteRequestInfo) { appendStage(fmt.Sprintf("HTTP request written: %v", info.Err)) },
		GotFirstResponseByte: func() { appendStage("first HTTP response byte received") },
	})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://%s:%d/probe", testServerIP, testHTTPPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	appendStage("HTTP request dispatched")
	response, err := client.Do(request)
	if err == nil {
		appendStage(fmt.Sprintf("HTTP status %d received", response.StatusCode))
	}
	if err != nil {
		mu.Lock()
		stagesText := strings.Join(stages, " -> ")
		mu.Unlock()
		serverError := "none"
		select {
		case problem := <-server.serveError:
			serverError = problem.Error()
		default:
		}
		t.Errorf("HTTP through encrypted tunnel: %v\nSOCKS/HTTP stages: %s\nserver requests: %d; serve error: %s\nserver WireGuard: %s\nclient WireGuard: %s\ndirect gVisor diagnostic (still through WireGuard): %s",
			err, stagesText, server.hits.Load(), serverError, peerDiagnostics(server.device),
			peerDiagnostics(session.device), directNetstackProbe(session))
		t.FailNow()
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(data) != "aowis-wireguard-e2e:"+marker {
		t.Fatalf("wrong tunnel response: status=%d body=%q", response.StatusCode, data)
	}
	appendStage("HTTP body validated")
	mu.Lock()
	stagesText := strings.Join(stages, " -> ")
	mu.Unlock()
	t.Logf("phase encrypted HTTP: %s; trace: %s", time.Since(started).Round(time.Millisecond), stagesText)
}

func logE2EPhase(t *testing.T, name string, started time.Time) {
	t.Helper()
	t.Logf("phase %s: %s", name, time.Since(started).Round(time.Millisecond))
}

func TestWireGuardE2EPeerEndpointForms(t *testing.T) {
	for _, endpoint := range []string{"192.0.2.1:51825", "[2001:db8::1]:51825", "[fe80::1%eth0]:51825"} {
		got, err := resolvePeerEndpoint(endpoint)
		if err != nil || got.String() != endpoint {
			t.Fatalf("endpoint %s: got %v, err %v", endpoint, got, err)
		}
	}
	for _, endpoint := range []string{"", "localhost", "localhost:0", "localhost:65536"} {
		if _, err := resolvePeerEndpoint(endpoint); err == nil {
			t.Fatalf("accepted invalid endpoint %q", endpoint)
		}
	}
}

func TestWireGuardE2EEncryptedHTTPAndRestart(t *testing.T) {
	testStarted := time.Now()
	phaseStarted := time.Now()
	server := newTestWireGuardServer(t, "first")
	logE2EPhase(t, "server setup", phaseStarted)

	phaseStarted = time.Now()
	session, port, user, pass := server.startClient(t, server.keys.public)
	logE2EPhase(t, "initial client startup", phaseStarted)
	defer func() {
		if session != nil {
			started := time.Now()
			session.close()
			logE2EPhase(t, "fallback initial client shutdown", started)
		}
	}()

	requestThroughTunnel(t, server, session, port, user, pass, "first")
	if !hasHandshake(t, server.device) || !hasHandshake(t, session.device) {
		t.Fatal("HTTP succeeded but WireGuard handshake was not recorded on both peers")
	}
	// The exported telemetry must reflect the same session state.
	sample, err := session.telemetry()
	if err != nil {
		t.Fatal(err)
	}
	if sample.lastHandshakeUnixMs == 0 || sample.rxBytes == 0 || sample.txBytes == 0 ||
		sample.acceptedProxyConnections == 0 || sample.failedProxyDials != 0 ||
		sample.endpoint == "" || sample.startedUnixMs == 0 {
		t.Fatalf("telemetry does not reflect the completed request: %+v", sample)
	}
	phaseStarted = time.Now()
	stoppedSession := session
	session.close()
	logE2EPhase(t, "initial client shutdown", phaseStarted)
	session = nil
	if _, err := stoppedSession.telemetry(); err == nil {
		t.Fatal("telemetry sampled a closed WireGuard device")
	}
	if conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), 150*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("proxy listener remains open after session shutdown")
	}

	// The same server peer accepts handshake initiations no more often than
	// wireguard-go's HandshakeInitationRate (20 ms). An immediate restart
	// can legitimately have its first initiation rate-limited, triggering
	// the normal five-second handshake retry. Keep this ordinary restart
	// test outside that deliberately exercised edge case.
	phaseStarted = time.Now()
	time.Sleep(device.HandshakeInitationRate + 10*time.Millisecond)
	logE2EPhase(t, "peer handshake initiation cooldown", phaseStarted)

	phaseStarted = time.Now()
	// Exercise the hostname path on restart using local name resolution.
	_, udpPort, err := net.SplitHostPort(server.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	server.endpoint = net.JoinHostPort("localhost", udpPort)
	restarted, newPort, newUser, newPass := server.startClient(t, server.keys.public)
	logE2EPhase(t, "restarted client startup", phaseStarted)
	defer func() {
		started := time.Now()
		restarted.close()
		logE2EPhase(t, "restarted client shutdown", started)
	}()
	requestThroughTunnel(t, server, restarted, newPort, newUser, newPass, "first")
	logE2EPhase(t, "test body excluding deferred shutdown", testStarted)
}

// An abrupt restart may occur within the server peer's 20 ms handshake
// rate-limit window. In that case the first handshake may be dropped and the
// client must still recover using WireGuard's normal retransmission (roughly
// five seconds). This is a separate reliability test: the ordinary restart
// test should not mistake intended protocol flood protection for slow startup.
func TestWireGuardE2EImmediateRestartWithRetry(t *testing.T) {
	server := newTestWireGuardServer(t, "immediate-restart")
	first, firstPort, firstUser, firstPass := server.startClient(t, server.keys.public)
	defer func() {
		if first != nil {
			first.close()
		}
	}()
	requestThroughTunnel(t, server, first, firstPort, firstUser, firstPass, "immediate-restart")
	first.close()
	first = nil

	// No cooldown here: test the real rapid-restart condition. A normal
	// WireGuard retransmission can cost about five seconds, so retain the
	// 12-second HTTP deadline and never retry through the host TCP/IP stack.
	restarted, port, username, password := server.startClient(t, server.keys.public)
	defer restarted.close()
	requestThroughTunnel(t, server, restarted, port, username, password, "immediate-restart")
	if !hasHandshake(t, restarted.device) {
		t.Fatal("rapidly restarted WireGuard client did not complete a handshake")
	}
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
	requestThroughTunnel(t, first, one, portOne, userOne, passOne, "alpha")
	requestThroughTunnel(t, second, two, portTwo, userTwo, passTwo, "beta")
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

// Host names in service URLs are resolved only by the profile's DNS server,
// through the tunnel: the SOCKS5 proxy receives the name unresolved and the
// userspace netstack queries the in-tunnel DNS. The host resolver is never
// used, so a name only the host knows must fail rather than leak.
func TestWireGuardE2EInTunnelDNS(t *testing.T) {
	server := newTestWireGuardServer(t, "dns")
	udp, err := server.network.ListenUDP(&net.UDPAddr{Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := testdns.Serve(udp, testServiceName, netip.MustParseAddr(testServerIP))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resolver.Close() })

	// A host-side HTTP listener that must never be reached through the
	// tunnel: "localhost" resolves to it on the host, and only there.
	hostListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var hostHits atomic.Int64
	hostServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		hostHits.Add(1)
		_, _ = io.WriteString(writer, "host-resolver-leak")
	}), ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = hostServer.Serve(hostListener) }()
	t.Cleanup(func() { _ = hostServer.Close() })
	_, hostPort, _ := net.SplitHostPort(hostListener.Addr().String())

	session, port, user, pass := server.startClientWithDNS(t, server.keys.public, testServerIP)
	client := newSOCKSHTTPClient(port, user, pass, 12*time.Second)

	// 1. The service name resolves through the tunnel (Go's SOCKS5 client
	//    sends names unresolved, as Qt does with HostNameLookupCapability).
	response, err := client.Get(fmt.Sprintf("http://%s:%d/probe", testServiceName, testHTTPPort))
	if err != nil {
		t.Fatalf("request by in-tunnel name: %v (DNS queries %d)\nclient WireGuard: %s",
			err, resolver.Queries(), peerDiagnostics(session.device))
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "aowis-wireguard-e2e:dns" || resolver.Queries() == 0 {
		t.Fatalf("name not resolved through the tunnel: status=%d body=%q queries=%d",
			response.StatusCode, body, resolver.Queries())
	}

	// 2. A name only the host can resolve must not reach the host.
	if response, err := client.Get("http://localhost:" + hostPort + "/probe"); err == nil {
		leaked, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("host-only name was served: status=%d body=%q", response.StatusCode, leaked)
	}
	if hostHits.Load() != 0 {
		t.Fatal("a tunnel request reached the host resolver's address")
	}
	client.CloseIdleConnections()
	session.close()

	// 3. Without "DNS =" names fail closed: no host resolver, no query.
	time.Sleep(device.HandshakeInitationRate + 10*time.Millisecond)
	queriesBefore := resolver.Queries()
	noDNS, noDNSPort, noDNSUser, noDNSPass := server.startClientWithDNS(t, server.keys.public, "")
	defer noDNS.close()
	noDNSClient := newSOCKSHTTPClient(noDNSPort, noDNSUser, noDNSPass, 12*time.Second)
	defer noDNSClient.CloseIdleConnections()
	if response, err := noDNSClient.Get(fmt.Sprintf("http://%s:%d/probe", testServiceName, testHTTPPort)); err == nil {
		response.Body.Close()
		t.Fatal("service name resolved without a tunnel DNS server")
	}
	sample, err := noDNS.telemetry()
	if err != nil {
		t.Fatal(err)
	}
	if resolver.Queries() != queriesBefore || sample.failedProxyDials == 0 || hostHits.Load() != 0 {
		t.Fatalf("no-DNS request: queries %d -> %d, failed dials %d, host hits %d",
			queriesBefore, resolver.Queries(), sample.failedProxyDials, hostHits.Load())
	}
}
