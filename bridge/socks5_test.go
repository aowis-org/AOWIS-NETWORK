package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidateConfig(t *testing.T) {
	private := make([]byte, 32)
	public := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(public); err != nil {
		t.Fatal(err)
	}
	config := tunnelConfig{
		address: "10.30.0.2/32", privateKey: base64.StdEncoding.EncodeToString(private),
		publicKey: base64.StdEncoding.EncodeToString(public),
		// Numeric (TEST-NET-1): validation must not depend on host DNS.
		// Host-name endpoints are resolved at start; see resolvePeerEndpoint.
		endpoint: "192.0.2.10:51820", allowedIPs: "10.30.0.0/24,10.31.0.0/24",
		mtu: 1420, keepalive: 25,
	}
	addresses, _, ipc, err := validateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0].String() != "10.30.0.2" {
		t.Fatal(addresses)
	}
	if !strings.Contains(ipc, "allowed_ip=10.31.0.0/24\n") {
		t.Fatal("missing peer route")
	}
	if !strings.Contains(ipc, "endpoint=192.0.2.10:51820\n") {
		t.Fatal("missing peer endpoint")
	}
	config.privateKey = "not-a-key"
	if _, _, _, err = validateConfig(config); err == nil {
		t.Fatal("malformed key accepted")
	}
	config.privateKey = base64.StdEncoding.EncodeToString(private)
	config.allowedIPs = "broken"
	if _, _, _, err = validateConfig(config); err == nil {
		t.Fatal("bad CIDR accepted")
	}
}

func newTestProxy(t *testing.T) (net.Listener, *proxyServer) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := newProxyServer(listener, "testuser", "testpass", (&net.Dialer{}).DialContext)
	proxy.start()
	t.Cleanup(proxy.close)
	return listener, proxy
}

func dialTestProxy(t *testing.T, listener net.Listener) net.Conn {
	t.Helper()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { client.Close() })
	return client
}

func TestSOCKS5RejectsNoAuth(t *testing.T) {
	listener, _ := newTestProxy(t)
	client := dialTestProxy(t, listener)
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, []byte{5, 255}) {
		t.Fatal(response)
	}
}

func TestSOCKS5RejectsWrongPassword(t *testing.T) {
	listener, _ := newTestProxy(t)
	client := dialTestProxy(t, listener)
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, []byte{5, 2}) {
		t.Fatal(response)
	}
	user, pass := "testuser", "wrong"
	packet := append([]byte{1, byte(len(user))}, []byte(user)...)
	packet = append(packet, byte(len(pass)))
	packet = append(packet, []byte(pass)...)
	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, []byte{1, 1}) {
		t.Fatal(response)
	}
}

func TestSOCKS5AuthenticatedTCPForwarding(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		remote, err := target.Accept()
		if err != nil {
			return
		}
		defer remote.Close()
		io.Copy(remote, remote)
	}()
	listener, _ := newTestProxy(t)
	client := dialTestProxy(t, listener)
	client.Write([]byte{5, 1, 2})
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(method, []byte{5, 2}) {
		t.Fatal(method)
	}
	user, pass := "testuser", "testpass"
	packet := append([]byte{1, byte(len(user))}, []byte(user)...)
	packet = append(packet, byte(len(pass)))
	packet = append(packet, []byte(pass)...)
	client.Write(packet)
	if _, err := io.ReadFull(client, method); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(method, []byte{1, 0}) {
		t.Fatal(method)
	}
	_, portString, _ := net.SplitHostPort(target.Addr().String())
	port, _ := strconv.Atoi(portString)
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	client.Write(request)
	response := make([]byte, 10)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if response[0] != 5 || response[1] != 0 {
		t.Fatal(response)
	}
	message := []byte("AOWIS-Network")
	if _, err := client.Write(message); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(message))
	if _, err := io.ReadFull(client, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, message) {
		t.Fatal(echo)
	}
}
