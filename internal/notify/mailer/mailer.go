// Package mailer sends the daily report email over SMTP with implicit TLS
// (SMTPS, port 465) — the only submission mode Cloudflare Email Service
// supports. Credentials live in the DB meta table (storage.EmailConfig),
// entered through the admin UI; they are never shipped in the binary or read
// from config.yaml.
package mailer

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"coraza-waf-mod/internal/storage"
)

// Cloudflare Email Service is the only supported provider: the submission
// endpoint, the literal "api_token" username, and the sender address are
// fixed. Only the API token (the SMTP password) and the recipients come from
// the DB config.
const (
	smtpHost     = "smtp.mx.cloudflare.net"
	smtpPort     = 465 // implicit TLS only — Cloudflare does not offer STARTTLS
	smtpUsername = "api_token"
	// Sender is the fixed From address; its domain must stay onboarded for
	// Email Sending on the Cloudflare account that owns the API token.
	Sender = "alert@astrareconslabs.com"
	// SenderName is the display name mail clients show instead of the bare
	// address ("Coraza WAF Mod" in the Gmail sender column, not alert@…).
	SenderName = "Coraza WAF Mod"
)

// fromHeader is the RFC 5322 From value; the envelope MAIL FROM stays the
// bare Sender address.
func fromHeader() string { return SenderName + " <" + Sender + ">" }

// sendTimeout bounds the whole SMTP session (dial, auth, data, quit) so a
// stalled server can never wedge the reporter goroutine or a UI test request.
const sendTimeout = 45 * time.Second

// Send delivers one multipart (plain + HTML) message using cfg. Recipients
// are the comma-separated cfg.To list.
func Send(cfg storage.EmailConfig, subject, textBody, htmlBody string) error {
	if cfg.To == "" || cfg.Token == "" {
		return fmt.Errorf("email is not fully configured (recipient and API token are required)")
	}
	recipients := splitAddrs(cfg.To)
	if len(recipients) == 0 {
		return fmt.Errorf("no valid recipient address in %q", cfg.To)
	}

	addr := net.JoinHostPort(smtpHost, strconv.Itoa(smtpPort))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	// Implicit TLS from the first byte.
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: smtpHost})
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(sendTimeout))

	c, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp greeting: %w", err)
	}
	defer c.Close()

	// PlainAuth is safe here: net/smtp marks the session as TLS because the
	// underlying conn is a *tls.Conn, so it allows AUTH PLAIN.
	if err := c.Auth(smtp.PlainAuth("", smtpUsername, cfg.Token, smtpHost)); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := c.Mail(Sender); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, rcpt := range recipients {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp RCPT TO %s: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(buildMessage(fromHeader(), recipients, subject, textBody, htmlBody)); err != nil {
		return fmt.Errorf("smtp write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp end of data: %w", err)
	}
	return c.Quit()
}

// buildMessage assembles an RFC 5322 multipart/alternative message with CRLF
// line endings (dot-stuffing is handled by net/smtp's DATA writer).
func buildMessage(from string, to []string, subject, textBody, htmlBody string) []byte {
	boundary := randomBoundary()
	var b strings.Builder
	writeLine := func(s string) { b.WriteString(s); b.WriteString("\r\n") }

	writeLine("From: " + from)
	writeLine("To: " + strings.Join(to, ", "))
	writeLine("Subject: " + subject)
	writeLine("Date: " + time.Now().Format(time.RFC1123Z))
	writeLine("MIME-Version: 1.0")
	writeLine(`Content-Type: multipart/alternative; boundary="` + boundary + `"`)
	writeLine("")
	writeLine("--" + boundary)
	writeLine(`Content-Type: text/plain; charset="utf-8"`)
	writeLine("")
	writeLine(crlf(textBody))
	writeLine("--" + boundary)
	writeLine(`Content-Type: text/html; charset="utf-8"`)
	writeLine("")
	writeLine(crlf(htmlBody))
	writeLine("--" + boundary + "--")
	return []byte(b.String())
}

// crlf normalizes bare LF line endings to CRLF as SMTP requires.
func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

func randomBoundary() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return "cz-" + hex.EncodeToString(buf[:])
}

// splitAddrs splits a comma-separated recipient list, dropping empties.
func splitAddrs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
