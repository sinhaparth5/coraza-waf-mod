package proxy

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

//go:embed blockpage.html
var blockPageHTML string

var blockPageTmpl = template.Must(template.New("block").Parse(blockPageHTML))

// blockMessages is what a blocked visitor reads, keyed by X-WAF-Block-Reason.
// Deliberately a category only: rule IDs and matched data stay in the logs,
// found there by the request ID.
var blockMessages = map[string][2]string{
	"ip_blocked":   {"Access denied", "Requests from your network are blocked on this site."},
	"geo_blocked":  {"Access denied", "This site is not available in your region."},
	"waf_rule":     {"Request blocked", "Your request looked unsafe and was stopped by the site's firewall."},
	"rate_limited": {"Too many requests", "You are sending requests too quickly. Wait a moment and try again."},
}

// deny writes a block response: a readable page for browsers, the JSON body
// (plus request_id) for everything else. reason must be a blockMessages key.
func deny(c echo.Context, status int, reason, reqID string, body map[string]any) error {
	c.Response().Header().Set("X-WAF-Block-Reason", reason)
	if !strings.Contains(c.Request().Header.Get("Accept"), "text/html") {
		body["request_id"] = reqID
		return c.JSON(status, body)
	}
	msg := blockMessages[reason]
	var buf bytes.Buffer
	if err := blockPageTmpl.Execute(&buf, map[string]any{
		"Status":     status,
		"StatusText": http.StatusText(status),
		"Title":      msg[0],
		"Message":    msg[1],
		"Host":       c.Request().Host,
		"Time":       time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		"RequestID":  reqID,
	}); err != nil {
		return c.JSON(status, body)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.HTMLBlob(status, buf.Bytes())
}
