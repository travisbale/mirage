package botguard

import "net"

// HelloConn is an exported alias for helloConn used in tests.
type HelloConn = helloConn

// NewHelloConnForTest wraps conn in a helloConn so external test packages
// can exercise the capture logic without exporting the type permanently.
func NewHelloConnForTest(conn net.Conn) *HelloConn {
	return newHelloConn(conn)
}
