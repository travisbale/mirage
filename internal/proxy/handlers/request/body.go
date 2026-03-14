package request

import (
	"bytes"
	"io"
	"net/http"
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
