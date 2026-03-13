package botguard

import (
	"bytes"
	"net"
	"sync"
)

// helloConn wraps a net.Conn and captures the first TLS record (the ClientHello)
// into a buffer. After Handshake() is called on the tls.Conn wrapping this,
// Hello() returns the captured bytes.
//
// Reads from the underlying conn are forwarded to both the TLS engine and
// the capture buffer simultaneously. Once the full ClientHello record has
// been buffered, the tee is disabled so subsequent traffic is not captured.
type helloConn struct {
	net.Conn

	mu       sync.Mutex
	buf      bytes.Buffer
	captured bool // true once the ClientHello record is complete
	teeOn    bool // false after capture is done
}

// newHelloConn wraps conn. Start capturing before calling tls.Server.
func newHelloConn(conn net.Conn) *helloConn {
	return &helloConn{Conn: conn, teeOn: true}
}

// Read overrides the embedded conn's Read. While teeOn is true, bytes read
// from the underlying conn are also written into buf. The tee is disabled
// once a complete TLS record has been accumulated.
func (c *helloConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	if c.teeOn && n > 0 {
		c.buf.Write(b[:n])
		// Heuristic: a TLS ClientHello record starts with byte 0x16 (handshake).
		// Once we have accumulated enough bytes for a complete record header (5 bytes)
		// plus the declared payload length, the full ClientHello is in the buffer.
		if c.buf.Len() >= 9 {
			raw := c.buf.Bytes()
			if raw[0] == 0x16 && len(raw) >= 5 {
				recordLen := int(raw[3])<<8 | int(raw[4])
				if c.buf.Len() >= 5+recordLen {
					c.teeOn = false
					c.captured = true
				}
			}
		}
	}
	c.mu.Unlock()
	return n, err
}

// Hello returns the captured ClientHello bytes, or nil if capture is incomplete.
// Call this after tls.Server(...).Handshake() has returned.
func (c *helloConn) Hello() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.captured {
		return nil
	}
	captured := make([]byte, c.buf.Len())
	copy(captured, c.buf.Bytes())
	return captured
}
