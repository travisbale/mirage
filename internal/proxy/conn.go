package proxy

import (
	"net"
	"sync"
)

// PeekedConn wraps a net.Conn and records all bytes read during the first
// TLS record so the JA4 fingerprint can be computed before the handshake
// is handed to crypto/tls.
type PeekedConn struct {
	net.Conn

	mu          sync.Mutex
	accumulated []byte // bytes accumulated from Read calls
	peeking     bool   // true until first record boundary is crossed
	helloBytes  []byte // the complete ClientHello record; nil until captured
}

// NewPeekedConn wraps conn. Begin reading immediately — the TLS stack will
// call Read during its handshake, which populates helloBytes.
func NewPeekedConn(conn net.Conn) *PeekedConn {
	return &PeekedConn{Conn: conn, peeking: true}
}

// Read intercepts bytes and accumulates them until the first TLS record is
// complete (5-byte header + length-indicated body), then marks capture done.
func (c *PeekedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peeking && n > 0 {
		c.accumulated = append(c.accumulated, b[:n]...)
		// TLS record: content_type(1) + version(2) + length(2) + body(length)
		if len(c.accumulated) >= 5 {
			recordLen := int(c.accumulated[3])<<8 | int(c.accumulated[4])
			if len(c.accumulated) >= 5+recordLen {
				c.helloBytes = make([]byte, 5+recordLen)
				copy(c.helloBytes, c.accumulated)
				c.peeking = false
			}
		}
	}
	return n, err
}

// ClientHelloBytes returns the complete TLS ClientHello record bytes,
// or nil if capture has not finished yet.
func (c *PeekedConn) ClientHelloBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.helloBytes
}
