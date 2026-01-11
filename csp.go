package cspmodifier

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(CSPModifier{})
	httpcaddyfile.RegisterHandlerDirective("csp_modifier", parseCaddyfile)
}

type CSPModifier struct {
	AddDomains   []string `json:"add_domains,omitempty"`
	InjectScript string   `json:"inject_script,omitempty"`
}

func (CSPModifier) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.csp_modifier",
		New: func() caddy.Module { return new(CSPModifier) },
	}
}

func (m *CSPModifier) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	rec := &responseBuffer{
		ResponseWriter: w,
		header:         make(http.Header),
		addDomains:     m.AddDomains,
		injectScript:   m.InjectScript,
	}

	if err := next.ServeHTTP(rec, r); err != nil {
		return err
	}

	return rec.finish()
}

type responseBuffer struct {
	http.ResponseWriter
	header       http.Header
	body         bytes.Buffer
	status       int
	addDomains   []string
	injectScript string
}

var nonceRegex = regexp.MustCompile(`'nonce-([^']+)'`)

func (r *responseBuffer) Header() http.Header {
	return r.header
}

func (r *responseBuffer) WriteHeader(status int) {
	r.status = status
}

func (r *responseBuffer) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(b)
}

func (r *responseBuffer) finish() error {
	csp := r.header.Get("Content-Security-Policy")
	nonce := ""

	if csp != "" {
		nonce, csp = r.processCSP(csp)
		r.header.Set("Content-Security-Policy", csp)
	}

	body := r.body.Bytes()
	contentType := r.header.Get("Content-Type")
	contentEncoding := r.header.Get("Content-Encoding")

	if r.injectScript != "" && strings.HasPrefix(contentType, "text/html") {
		decompressed, err := r.decompress(body, contentEncoding)
		if err == nil && decompressed != nil {
			body = decompressed
			r.header.Del("Content-Encoding")
		}

		script := r.injectScript
		if nonce != "" {
			script = strings.Replace(script, "<script", `<script nonce="`+nonce+`"`, 1)
		}

		body = bytes.Replace(body, []byte("</body>"), []byte(script+"</body>"), 1)
	}

	for k, vv := range r.header {
		for _, v := range vv {
			r.ResponseWriter.Header().Add(k, v)
		}
	}

	r.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(body)))
	r.ResponseWriter.WriteHeader(r.status)
	_, err := r.ResponseWriter.Write(body)
	return err
}

func (r *responseBuffer) decompress(data []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)

	case "deflate":
		reader := flate.NewReader(bytes.NewReader(data))
		defer reader.Close()
		return io.ReadAll(reader)

	case "br":
		reader := brotli.NewReader(bytes.NewReader(data))
		return io.ReadAll(reader)

	default:
		return nil, nil
	}
}

func (r *responseBuffer) processCSP(csp string) (nonce string, modified string) {
	directives := parseCSP(csp)

	if scriptSrc, ok := directives["script-src"]; ok {
		if match := nonceRegex.FindStringSubmatch(scriptSrc); len(match) > 1 {
			nonce = match[1]
		}
		for _, domain := range r.addDomains {
			if !strings.Contains(scriptSrc, domain) {
				directives["script-src"] = scriptSrc + " " + domain
			}
		}
	} else if defaultSrc, ok := directives["default-src"]; ok {
		if match := nonceRegex.FindStringSubmatch(defaultSrc); len(match) > 1 {
			nonce = match[1]
		}
		scriptSrc := defaultSrc
		for _, domain := range r.addDomains {
			scriptSrc += " " + domain
		}
		directives["script-src"] = scriptSrc
	}

	modified = buildCSP(directives)
	return
}

func parseCSP(csp string) map[string]string {
	directives := make(map[string]string)
	parts := strings.Split(csp, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, " ")
		if idx == -1 {
			directives[part] = ""
		} else {
			directives[part[:idx]] = part[idx+1:]
		}
	}
	return directives
}

func buildCSP(directives map[string]string) string {
	var parts []string
	for name, value := range directives {
		if value == "" {
			parts = append(parts, name)
		} else {
			parts = append(parts, name+" "+value)
		}
	}
	return strings.Join(parts, "; ")
}

func (m *CSPModifier) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	for d.NextBlock(0) {
		switch d.Val() {
		case "add_domain":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AddDomains = append(m.AddDomains, d.Val())
		case "inject_script":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.InjectScript = d.Val()
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m CSPModifier
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

var (
	_ caddyhttp.MiddlewareHandler = (*CSPModifier)(nil)
	_ caddyfile.Unmarshaler       = (*CSPModifier)(nil)
)
