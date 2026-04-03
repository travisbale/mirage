package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
)

// bufferedResponseWriter collects the entire response in memory and writes
// it to the wire in one shot when flush() is called. Used for normal API
// requests where the handler runs to completion before responding.
type bufferedResponseWriter struct {
	conn      net.Conn
	header    http.Header
	code      int
	buf       []byte
	keepAlive bool
}

func newBufferedResponseWriter(conn net.Conn) *bufferedResponseWriter {
	return &bufferedResponseWriter{
		conn:   conn,
		header: make(http.Header),
		code:   http.StatusOK,
	}
}

func (w *bufferedResponseWriter) Header() http.Header {
	return w.header
}

func (w *bufferedResponseWriter) WriteHeader(code int) {
	w.code = code
}

func (w *bufferedResponseWriter) Write(b []byte) (int, error) {
	w.buf = append(w.buf, b...)
	return len(b), nil
}

func (w *bufferedResponseWriter) flush() {
	resp := &http.Response{
		StatusCode:    w.code,
		Header:        w.header,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewReader(w.buf)),
		ContentLength: int64(len(w.buf)),
		Close:         !w.keepAlive,
	}
	_ = resp.Write(w.conn) // raw connection write; error unrecoverable at this point
}

// streamingResponseWriter writes HTTP headers and body directly to the wire
// without buffering. Used for SSE endpoints that need to flush data to the
// client as it's produced.
type streamingResponseWriter struct {
	writer      *bufio.Writer
	header      http.Header
	wroteHeader bool
}

func newStreamingResponseWriter(conn net.Conn) *streamingResponseWriter {
	return &streamingResponseWriter{
		writer: bufio.NewWriter(conn),
		header: make(http.Header),
	}
}

func (w *streamingResponseWriter) Header() http.Header {
	return w.header
}

func (w *streamingResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	fmt.Fprintf(w.writer, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	_ = w.header.Write(w.writer)
	_, _ = w.writer.WriteString("\r\n")
	_ = w.writer.Flush()
}

func (w *streamingResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.writer.Write(b)

	return n, err
}

func (w *streamingResponseWriter) Flush() {
	_ = w.writer.Flush()
}

// hijackableResponseWriter wraps a net.Conn and satisfies http.Hijacker for WebSocket upgrades.
type hijackableResponseWriter struct {
	conn   net.Conn
	header http.Header
	code   int
}

func newHijackableResponseWriter(conn net.Conn) *hijackableResponseWriter {
	return &hijackableResponseWriter{
		conn:   conn,
		header: make(http.Header),
		code:   http.StatusOK,
	}
}

func (w *hijackableResponseWriter) Header() http.Header {
	return w.header
}

func (w *hijackableResponseWriter) WriteHeader(code int) {
	w.code = code
}

func (w *hijackableResponseWriter) Write(b []byte) (int, error) {
	return w.conn.Write(b)
}

func (w *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn))
	return w.conn, brw, nil
}
