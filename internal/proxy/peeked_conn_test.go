package proxy

import (
	"bytes"
	"testing"
)

func TestPeekedConn_CapturesClientHello(t *testing.T) {
	// Construct a minimal synthetic TLS record:
	// content_type(1) + version(2) + length(2) + body(length)
	body := []byte("fake-client-hello-data")
	record := make([]byte, 5+len(body))
	record[0] = 0x16 // TLS handshake
	record[1] = 0x03 // TLS major version
	record[2] = 0x01 // TLS minor version
	record[3] = byte(len(body) >> 8)
	record[4] = byte(len(body))
	copy(record[5:], body)

	conn := newFakeConn(record)
	peeked := newPeekedConn(conn)

	// Read it all out.
	buf := make([]byte, len(record))
	n, _ := peeked.Read(buf)
	if n != len(record) {
		t.Fatalf("expected to read %d bytes, got %d", len(record), n)
	}

	hello := peeked.ClientHelloBytes()
	if hello == nil {
		t.Fatal("ClientHelloBytes returned nil after complete record was read")
	}
	if !bytes.Equal(hello, record) {
		t.Errorf("captured bytes do not match original record")
	}
}

func TestPeekedConn_NilBeforeComplete(t *testing.T) {
	body := []byte("partial")
	// Only send 3 bytes — not a complete record.
	conn := newFakeConn(body[:3])
	peeked := newPeekedConn(conn)

	buf := make([]byte, 3)
	peeked.Read(buf)

	if peeked.ClientHelloBytes() != nil {
		t.Error("expected nil before complete TLS record is captured")
	}
}
