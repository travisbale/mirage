package proxy

import (
	"net"
	"sync"
)

// peekedConn wraps a net.Conn and records all bytes read during the first
// TLS record so the JA4 fingerprint can be computed before the handshake
// is handed to crypto/tls.
type peekedConn struct {
	net.Conn

	mu          sync.Mutex
	accumulated []byte // bytes accumulated from Read calls
	peeking     bool   // true until first record boundary is crossed
	helloBytes  []byte // the complete ClientHello record; nil until captured
}

// newPeekedConn wraps conn. The TLS stack calls Read during its handshake,
// which transparently accumulates helloBytes without blocking.
func newPeekedConn(conn net.Conn) *peekedConn {
	return &peekedConn{Conn: conn, peeking: true}
}

const tlsRecordHeaderLen = 5 // content_type(1) + version(2) + length(2)

func (c *peekedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.accumulate(b[:n])
	}
	return n, err
}

// accumulate appends newly read bytes and checks whether a complete TLS
// ClientHello record has been captured. Once the full record is available,
// it is copied into helloBytes and accumulation stops.
func (c *peekedConn) accumulate(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.peeking {
		return
	}
	c.accumulated = append(c.accumulated, data...)
	if len(c.accumulated) < tlsRecordHeaderLen {
		return
	}
	recordLen := int(c.accumulated[3])<<8 | int(c.accumulated[4])
	totalLen := tlsRecordHeaderLen + recordLen
	if len(c.accumulated) < totalLen {
		return
	}
	c.helloBytes = make([]byte, totalLen)
	copy(c.helloBytes, c.accumulated)
	c.peeking = false
}

// ClientHelloBytes returns the captured record, or nil if the handshake isn't complete yet.
func (c *peekedConn) ClientHelloBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.helloBytes
}
