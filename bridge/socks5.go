package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type dialFunction func(context.Context, string, string) (net.Conn, error)

type proxyServer struct {
	listener net.Listener
	username string
	password string
	dial     dialFunction
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	clients  map[net.Conn]net.Conn
	// Telemetry only; never gate behaviour on these counters.
	accepted    atomic.Uint64 // authenticated CONNECT requests
	active      atomic.Uint64 // relays currently copying through the tunnel
	failedDials atomic.Uint64 // in-tunnel dials that failed (peer/service unreachable)
}

func newProxyServer(listener net.Listener, username, password string, dial dialFunction) *proxyServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &proxyServer{
		listener: listener, username: username, password: password,
		dial: dial, ctx: ctx, cancel: cancel, clients: make(map[net.Conn]net.Conn),
	}
}

func (proxy *proxyServer) start() {
	proxy.wg.Add(1)
	go proxy.accept()
}

func (proxy *proxyServer) accept() {
	defer proxy.wg.Done()
	for {
		client, err := proxy.listener.Accept()
		if err != nil {
			return
		}
		proxy.mu.Lock()
		if proxy.ctx.Err() != nil {
			proxy.mu.Unlock()
			client.Close()
			return
		}
		proxy.clients[client] = nil
		proxy.wg.Add(1)
		proxy.mu.Unlock()
		go func() {
			defer proxy.wg.Done()
			defer client.Close()
			defer func() {
				proxy.mu.Lock()
				delete(proxy.clients, client)
				proxy.mu.Unlock()
			}()
			proxy.handle(client)
		}()
	}
}

func (proxy *proxyServer) close() {
	proxy.cancel()
	proxy.listener.Close()
	proxy.mu.Lock()
	for client, remote := range proxy.clients {
		client.Close()
		if remote != nil {
			remote.Close()
		}
	}
	proxy.mu.Unlock()
	proxy.wg.Wait()
}

func readExact(client net.Conn, data []byte) error {
	_, err := io.ReadFull(client, data)
	return err
}

func (proxy *proxyServer) authenticate(client net.Conn) error {
	var header [2]byte
	if err := readExact(client, header[:]); err != nil || header[0] != 5 || header[1] == 0 {
		return errors.New("invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(header[1]))
	if err := readExact(client, methods); err != nil {
		return err
	}
	usernamePassword := false
	for _, method := range methods {
		if method == 2 {
			usernamePassword = true
		}
	}
	if !usernamePassword {
		client.Write([]byte{5, 255})
		return errors.New("SOCKS5 username/password authentication required")
	}
	if _, err := client.Write([]byte{5, 2}); err != nil {
		return err
	}
	var versionAndSize [2]byte
	if err := readExact(client, versionAndSize[:]); err != nil || versionAndSize[0] != 1 {
		return errors.New("invalid SOCKS5 authentication")
	}
	user := make([]byte, int(versionAndSize[1]))
	if err := readExact(client, user); err != nil {
		return err
	}
	var size [1]byte
	if err := readExact(client, size[:]); err != nil {
		return err
	}
	password := make([]byte, int(size[0]))
	if err := readExact(client, password); err != nil {
		return err
	}
	valid := subtle.ConstantTimeCompare(user, []byte(proxy.username)) &
		subtle.ConstantTimeCompare(password, []byte(proxy.password))
	if valid != 1 {
		client.Write([]byte{1, 1})
		return errors.New("SOCKS5 authentication failed")
	}
	_, err := client.Write([]byte{1, 0})
	return err
}

func destination(client net.Conn) (string, error) {
	var header [4]byte
	if err := readExact(client, header[:]); err != nil {
		return "", err
	}
	if header[0] != 5 || header[1] != 1 || header[2] != 0 {
		return "", errors.New("SOCKS5 only supports TCP CONNECT")
	}
	var host string
	switch header[3] {
	case 1:
		var address [4]byte
		if err := readExact(client, address[:]); err != nil {
			return "", err
		}
		host = net.IP(address[:]).String()
	case 3:
		var length [1]byte
		if err := readExact(client, length[:]); err != nil || length[0] == 0 {
			return "", errors.New("invalid SOCKS5 domain length")
		}
		address := make([]byte, int(length[0]))
		if err := readExact(client, address); err != nil {
			return "", err
		}
		host = string(address)
	case 4:
		var address [16]byte
		if err := readExact(client, address[:]); err != nil {
			return "", err
		}
		host = net.IP(address[:]).String()
	default:
		return "", errors.New("unsupported SOCKS5 address type")
	}
	var port [2]byte
	if err := readExact(client, port[:]); err != nil {
		return "", err
	}
	if binary.BigEndian.Uint16(port[:]) == 0 {
		return "", errors.New("invalid SOCKS5 destination port")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func (proxy *proxyServer) handle(client net.Conn) {
	client.SetDeadline(time.Now().Add(15 * time.Second))
	if err := proxy.authenticate(client); err != nil {
		return
	}
	target, err := destination(client)
	if err != nil {
		client.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	proxy.accepted.Add(1)
	ctx, cancel := context.WithTimeout(proxy.ctx, 15*time.Second)
	defer cancel()
	remote, err := proxy.dial(ctx, "tcp", target)
	if err != nil {
		proxy.failedDials.Add(1)
		client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	proxy.active.Add(1)
	// Adding ^uint64(0) is the documented atomic decrement.
	defer proxy.active.Add(^uint64(0))
	proxy.mu.Lock()
	if proxy.ctx.Err() != nil {
		proxy.mu.Unlock()
		return
	}
	proxy.clients[client] = remote
	proxy.mu.Unlock()
	if _, err := client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	client.SetDeadline(time.Time{})
	copyDone := make(chan struct{})
	go func() {
		io.Copy(remote, client)
		if halfClose, ok := remote.(interface{ CloseWrite() error }); ok {
			halfClose.CloseWrite()
		}
		close(copyDone)
	}()
	io.Copy(client, remote)
	client.Close()
	remote.Close()
	<-copyDone
}
