package services

import (
	"bytes"
	"compress/gzip"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// minCompressSize skips responses too small for compression to pay for its
// own framing. Responses of unknown length (chunked) are always compressed.
const minCompressSize = 1024

type encoder interface {
	io.WriteCloser
	Flush() error
	Reset(io.Writer)
}

type zstdEncoder struct{ *zstd.Encoder }

func (z zstdEncoder) Reset(w io.Writer) { z.Encoder.Reset(w) }

var encoderPools = map[string]*sync.Pool{
	"zstd": {New: func() any {
		e, _ := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
		return zstdEncoder{e}
	}},
	"gzip": {New: func() any { return gzip.NewWriter(nil) }},
}

// negotiateEncoding picks zstd, then gzip, from the client's Accept-Encoding,
// honoring an explicit q=0 refusal. Other q-values are ignored: the server's
// preference order decides between encodings the client accepts.
func negotiateEncoding(accept string) string {
	ok := map[string]bool{}
	for _, part := range strings.Split(accept, ",") {
		name, params, _ := strings.Cut(part, ";")
		q := 1.0
		if v, found := strings.CutPrefix(strings.TrimSpace(params), "q="); found {
			q, _ = strconv.ParseFloat(v, 64)
		}
		ok[strings.ToLower(strings.TrimSpace(name))] = q > 0
	}
	for _, enc := range []string{"zstd", "gzip"} {
		if ok[enc] {
			return enc
		}
	}
	return ""
}

// compressibleType reports whether a Content-Type is text-like. Images,
// video, archives and fonts that are already compressed (woff/woff2) are
// excluded; text/event-stream is excluded so SSE passes through untouched.
func compressibleType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	switch {
	case mt == "text/event-stream":
		return false
	case strings.HasPrefix(mt, "text/"),
		strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+xml"):
		return true
	}
	switch mt {
	case "application/json", "application/javascript", "application/x-javascript",
		"application/xml", "application/wasm", "image/svg+xml",
		"font/ttf", "font/otf", "application/vnd.ms-fontobject":
		return true
	}
	return false
}

// compressResponse re-encodes a proxied response's body when the client
// accepts zstd or gzip and the backend sent an uncompressed, text-like body.
// Upgrades (101), HEAD, 204/206/304, already-encoded bodies, small bodies
// and Cache-Control: no-transform are left alone.
func compressResponse(resp *http.Response) {
	h := resp.Header
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusPartialContent || resp.Request == nil || resp.Request.Method == http.MethodHead ||
		h.Get("Content-Encoding") != "" || h.Get("Content-Range") != "" || !compressibleType(h.Get("Content-Type")) ||
		strings.Contains(strings.ToLower(h.Get("Cache-Control")), "no-transform") {
		return
	}
	// The body depends on Accept-Encoding from here on, whichever branch
	// this client takes, so caches must keep the variants apart.
	if !headerHasToken(h, "Vary", "Accept-Encoding") {
		h.Add("Vary", "Accept-Encoding")
	}
	if resp.ContentLength >= 0 && resp.ContentLength < minCompressSize {
		return
	}
	enc := negotiateEncoding(resp.Request.Header.Get("Accept-Encoding"))
	if enc == "" {
		return
	}
	pool := encoderPools[enc]
	cb := &compressBody{src: resp.Body, pool: pool, buf: make([]byte, 32<<10)}
	cb.enc = pool.Get().(encoder)
	cb.enc.Reset(&cb.out)
	resp.Body = cb
	resp.ContentLength = -1
	h.Del("Content-Length")
	h.Set("Content-Encoding", enc)
	// A strong ETag promises byte-identical bodies; the encoded body isn't.
	if et := h.Get("ETag"); strings.HasPrefix(et, `"`) {
		h.Set("ETag", "W/"+et)
	}
}

func headerHasToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// compressBody encodes src on the fly. Each upstream read is flushed through
// the encoder before it is returned, so a streaming backend's chunks reach
// the client as they arrive instead of waiting for the encoder's window to
// fill. With ContentLength -1, ReverseProxy flushes every write to the client.
type compressBody struct {
	src  io.ReadCloser
	enc  encoder
	pool *sync.Pool
	out  bytes.Buffer
	buf  []byte
	done bool
}

func (c *compressBody) Read(p []byte) (int, error) {
	for c.out.Len() == 0 {
		if c.done {
			return 0, io.EOF
		}
		n, err := c.src.Read(c.buf)
		if n > 0 {
			if _, werr := c.enc.Write(c.buf[:n]); werr != nil {
				return 0, werr
			}
		}
		switch {
		case err == io.EOF:
			c.done = true
			if cerr := c.enc.Close(); cerr != nil {
				return 0, cerr
			}
		case err != nil:
			return 0, err
		case n > 0:
			if ferr := c.enc.Flush(); ferr != nil {
				return 0, ferr
			}
		}
	}
	return c.out.Read(p)
}

func (c *compressBody) Close() error {
	if c.enc != nil {
		c.enc.Reset(io.Discard)
		c.pool.Put(c.enc)
		c.enc = nil
	}
	return c.src.Close()
}
