package request

import (
	"bytes"
	"io"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
)

// readAndRestoreBody reads the request body and replaces it with a new reader
// so the body can be read again by subsequent handlers or the upstream transport.
func readAndRestoreBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(req.Body)
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(b))
	return b, err
}

// getRequestBody returns the request body, reading it from the wire on first
// call and caching on ctx.RequestBody for subsequent handlers.
func getRequestBody(ctx *aitm.ProxyContext, req *http.Request) ([]byte, error) {
	if ctx.RequestBody != nil {
		return ctx.RequestBody, nil
	}
	body, err := readAndRestoreBody(req)
	if err != nil {
		return nil, err
	}
	ctx.RequestBody = body
	return body, nil
}
