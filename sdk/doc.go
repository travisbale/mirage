/*
Package sdk provides a typed Go client for the mirage management API.

# Authentication

All API requests are authenticated via mutual TLS (mTLS). The client
certificate and private key identify the operator; the CA certificate
is used to pin the server's certificate instead of trusting the system
roots.

Use [NewClient] to construct a Client:

	client, err := sdk.NewClient(
		"https://203.0.113.1:443",  // address — TCP dial target
		"mgmt.example.com",         // secretHostname — TLS SNI and Host header
		certPEM, keyPEM, caCertPEM,
	)

The address and secretHostname are intentionally separate: the TCP
connection dials address directly so the operator's workstation does not
need to resolve secretHostname via DNS. This allows the management
interface to be hosted on a non-public hostname.

# Client methods

Methods are grouped by resource domain:

  - Sessions  — list, get, delete, export cookies, stream lifecycle events
  - Lures      — CRUD, generate phishing URL, pause/unpause
  - Phishlets  — enable/disable/hide/unhide, create/delete sub-phishlets
  - Blacklist  — list, add, remove entries
  - BotGuard   — manage JA4 signatures, update bot score threshold
  - System     — status, reload
*/
package sdk
