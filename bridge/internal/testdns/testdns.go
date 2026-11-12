// Package testdns is a minimal authoritative DNS responder for the WireGuard
// end-to-end tests. It runs on a PacketConn inside a peer's userspace
// netstack, so it is reachable only through the tunnel, and it answers one A
// record. Test-only: imported by _test files and the test peer executable,
// never by the shipped engine (package main of the bridge).
package testdns

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"

	"golang.org/x/net/dns/dnsmessage"
)

// Server answers queries for one name; every other name gets NXDOMAIN.
type Server struct {
	conn    net.PacketConn
	name    string // lower-case, fully qualified ("dvmdb.aowis.test.")
	address [4]byte
	queries atomic.Int64
	done    chan struct{}
}

// Serve answers on conn until Close. name is a plain host name
// ("dvmdb.aowis.test"); address must be IPv4.
func Serve(conn net.PacketConn, name string, address netip.Addr) (*Server, error) {
	if !address.Is4() {
		return nil, errors.New("testdns serves IPv4 A records only")
	}
	server := &Server{
		conn:    conn,
		name:    strings.ToLower(strings.TrimSuffix(name, ".")) + ".",
		address: address.As4(),
		done:    make(chan struct{}),
	}
	go server.loop()
	return server, nil
}

// Queries counts well-formed questions received, for any name or type.
func (server *Server) Queries() int64 { return server.queries.Load() }

func (server *Server) Close() error {
	err := server.conn.Close()
	<-server.done
	return err
}

func (server *Server) loop() {
	defer close(server.done)
	buffer := make([]byte, 1500)
	for {
		size, from, err := server.conn.ReadFrom(buffer)
		if err != nil {
			return // Closed.
		}
		if response := server.answer(buffer[:size]); response != nil {
			_, _ = server.conn.WriteTo(response, from)
		}
	}
}

func (server *Server) answer(message []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil || header.Response {
		return nil
	}
	question, err := parser.Question()
	if err != nil {
		return nil
	}
	server.queries.Add(1)
	known := strings.ToLower(question.Name.String()) == server.name
	reply := dnsmessage.Header{
		ID: header.ID, Response: true, Authoritative: true,
		RecursionDesired: header.RecursionDesired, RCode: dnsmessage.RCodeSuccess,
	}
	if !known {
		reply.RCode = dnsmessage.RCodeNameError
	}
	builder := dnsmessage.NewBuilder(nil, reply)
	builder.EnableCompression()
	if builder.StartQuestions() != nil || builder.Question(question) != nil {
		return nil
	}
	// A for the known name; other types of it (AAAA) are NOERROR/no data.
	if known && question.Type == dnsmessage.TypeA && question.Class == dnsmessage.ClassINET {
		if builder.StartAnswers() != nil {
			return nil
		}
		if builder.AResource(dnsmessage.ResourceHeader{
			Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60,
		}, dnsmessage.AResource{A: server.address}) != nil {
			return nil
		}
	}
	response, err := builder.Finish()
	if err != nil {
		return nil
	}
	return response
}
