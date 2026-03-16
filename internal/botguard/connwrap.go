package botguard

import (
	"bytes"
	"net"
	"sync"
)

// helloConn tees reads into a buffer until the first TLS record (ClientHello) is
// complete, then disables the tee so subsequent traffic is not captured.
type helloConn struct {
	net.Conn

	mu       sync.Mutex
	buf      bytes.Buffer
	captured bool // true once the ClientHello record is complete
	teeOn    bool // false after capture is done
}

// newHelloConn wraps conn. Must be passed to tls.Server before the handshake.
func newHelloConn(conn net.Conn) *helloConn {
	return &helloConn{Conn: conn, teeOn: true}
}

func (c *helloConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	if c.teeOn && n > 0 {
		c.buf.Write(b[:n])
		// Stop tee-ing once we have the full record: header (5 bytes) + declared payload.
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

// Hello returns the captured bytes. Must be called after Handshake() completes.
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
