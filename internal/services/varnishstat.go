package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// VarnishStats is the handful of varnishstat counters the admin UI shows.
// They are Varnish-wide: every cache-routed service shares one storage pool,
// so Evicted (LRU nukes) climbing means services are pushing each other out.
type VarnishStats struct {
	Uptime    uint64 // seconds since the cache child started
	Hits      uint64
	Misses    uint64
	Objects   uint64
	Evicted   uint64 // MAIN.n_lru_nuked
	BytesUsed uint64 // cache storage in use (Transient excluded)
	BytesFree uint64 // cache storage still available (Transient excluded)
}

// ReadVarnishStats runs varnishstat once and parses its JSON. It needs
// read access to varnishd's shared-memory log (the installer adds the
// service user to the varnish group); any failure is returned for display,
// never treated as fatal.
func ReadVarnishStats(ctx context.Context) (VarnishStats, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "varnishstat", "-1", "-j",
		"-f", "MAIN.uptime", "-f", "MAIN.cache_hit", "-f", "MAIN.cache_miss",
		"-f", "MAIN.n_object", "-f", "MAIN.n_lru_nuked",
		"-f", "SMA.*.g_bytes", "-f", "SMA.*.g_space").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return VarnishStats{}, fmt.Errorf("varnishstat: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return VarnishStats{}, fmt.Errorf("varnishstat: %w", err)
	}
	return parseVarnishStats(out)
}

type varnishCounter struct {
	Value uint64 `json:"value"`
}

// parseVarnishStats accepts both JSON shapes: Varnish 7+ nests counters
// under "counters"; 6.x puts them at the top level next to "timestamp".
func parseVarnishStats(b []byte) (VarnishStats, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return VarnishStats{}, fmt.Errorf("varnishstat: bad JSON: %w", err)
	}
	if raw, ok := top["counters"]; ok {
		top = nil
		if err := json.Unmarshal(raw, &top); err != nil {
			return VarnishStats{}, fmt.Errorf("varnishstat: bad counters: %w", err)
		}
	}
	var s VarnishStats
	for name, raw := range top {
		var c varnishCounter
		if json.Unmarshal(raw, &c) != nil {
			continue // "timestamp"/"version" in the 6.x flat shape
		}
		switch {
		case name == "MAIN.uptime":
			s.Uptime = c.Value
		case name == "MAIN.cache_hit":
			s.Hits = c.Value
		case name == "MAIN.cache_miss":
			s.Misses = c.Value
		case name == "MAIN.n_object":
			s.Objects = c.Value
		case name == "MAIN.n_lru_nuked":
			s.Evicted = c.Value
		case strings.HasPrefix(name, "SMA.Transient."):
			// Unbounded scratch storage for pass/short-lived objects — not
			// the cache pool an admin sizes with -s malloc.
		case strings.HasPrefix(name, "SMA.") && strings.HasSuffix(name, ".g_bytes"):
			s.BytesUsed += c.Value
		case strings.HasPrefix(name, "SMA.") && strings.HasSuffix(name, ".g_space"):
			s.BytesFree += c.Value
		}
	}
	return s, nil
}
