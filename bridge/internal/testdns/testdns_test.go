package testdns

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, server *Server, name string, kind dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	request, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	var message dnsmessage.Message
	if err := message.Unpack(server.answer(request)); err != nil {
		t.Fatal(err)
	}
	return message
}

// Answers on loopback UDP here; the e2e tests run it inside a netstack.
func TestDNSResponder(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := Serve(conn, "dvmdb.aowis.test", netip.MustParseAddr("10.173.91.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	found := query(t, server, "DVMDB.aowis.test.", dnsmessage.TypeA)
	if found.Header.RCode != dnsmessage.RCodeSuccess || len(found.Answers) != 1 ||
		found.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 173, 91, 1} || found.Header.ID != 7 {
		t.Fatalf("A answer: %+v", found)
	}
	noData := query(t, server, "dvmdb.aowis.test.", dnsmessage.TypeAAAA)
	if noData.Header.RCode != dnsmessage.RCodeSuccess || len(noData.Answers) != 0 {
		t.Fatalf("AAAA should be NOERROR without data: %+v", noData)
	}
	missing := query(t, server, "localhost.", dnsmessage.TypeA)
	if missing.Header.RCode != dnsmessage.RCodeNameError || len(missing.Answers) != 0 {
		t.Fatalf("unknown name should be NXDOMAIN: %+v", missing)
	}
	if server.Queries() != 3 {
		t.Fatalf("query count %d", server.Queries())
	}
}
