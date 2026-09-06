package ui

import (
	"strings"
	"time"
)

// deviceRow is one line of the Settings page's "Registered devices" card.
type deviceRow struct {
	Token     string
	Device    string // "Chrome on Windows"
	IP        string
	Location  string // country name, or "Unknown"
	Flag      string // ISO country code for the flag icon, empty if unknown
	FirstSeen time.Time
	LastSeen  time.Time
	Current   bool // the device viewing this page right now
	Live      bool // still authenticates requests
}

// browserOS turns a User-Agent into a short "Browser on OS" label.
//
// Deliberately a hand-rolled prefix match rather than a UA-parsing
// dependency: this feeds one line of admin UI, and the failure mode of a
// wrong guess is a slightly vague label, not a security decision. Order
// matters — every Chromium browser also says "Chrome", and Chrome and Edge
// both say "Safari", so the more specific brand has to be tested first.
func browserOS(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return "Unknown device"
	}
	browser := "Unknown browser"
	for _, c := range []struct{ needle, name string }{
		{"Edg/", "Edge"},
		{"OPR/", "Opera"},
		{"Brave", "Brave"},
		{"Vivaldi", "Vivaldi"},
		{"SamsungBrowser", "Samsung Internet"},
		{"Firefox/", "Firefox"},
		{"Chrome/", "Chrome"},
		{"Safari/", "Safari"},
		{"curl/", "curl"},
		{"Wget/", "Wget"},
	} {
		if strings.Contains(ua, c.needle) {
			browser = c.name
			break
		}
	}
	os := "Unknown OS"
	for _, c := range []struct{ needle, name string }{
		{"iPhone", "iPhone"},
		{"iPad", "iPad"},
		{"Android", "Android"},
		{"Windows NT 10.0", "Windows"},
		{"Windows", "Windows"},
		{"Mac OS X", "macOS"},
		{"CrOS", "ChromeOS"},
		{"Linux", "Linux"},
	} {
		if strings.Contains(ua, c.needle) {
			os = c.name
			break
		}
	}
	return browser + " on " + os
}

// deviceRows renders the session history for the template, marking the row
// belonging to current (the caller's own session token).
func (h *Handler) deviceRows(current string) []deviceRow {
	sessions, err := h.db.ListSessions()
	if err != nil {
		return nil
	}
	rows := make([]deviceRow, 0, len(sessions))
	for _, s := range sessions {
		country := h.geoBl.LookupCountry(s.IP)
		location, flag := "Unknown", ""
		if name := countryName(country); name != "" {
			location, flag = name, country
		}
		rows = append(rows, deviceRow{
			Token:     s.Token,
			Device:    browserOS(s.UserAgent),
			IP:        s.IP,
			Location:  location,
			Flag:      flag,
			FirstSeen: s.CreatedAt,
			LastSeen:  s.LastActiveAt,
			Current:   s.Token == current,
			Live:      s.Live(),
		})
	}
	return currentFirst(rows)
}

// currentFirst moves the caller's own device to the top, preserving the
// order of everything else. ListSessions already sorts live sessions first,
// which is enough while the one-live-session rule holds, but a deployment
// upgraded from before that rule can still have a second live row that
// would otherwise outrank "This device".
func currentFirst(rows []deviceRow) []deviceRow {
	for i := range rows {
		if rows[i].Current && i > 0 {
			cur := rows[i]
			copy(rows[1:], rows[:i]) // copy is memmove-safe on overlap
			rows[0] = cur
			break
		}
	}
	return rows
}
