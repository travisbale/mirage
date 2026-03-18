package request

import "net"

// hostWithoutPort strips the port from a host[:port] string.
// If host has no port (or is malformed), it is returned unchanged.
// Handles IPv6 literals: "[::1]:443" → "::1".
func hostWithoutPort(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}
