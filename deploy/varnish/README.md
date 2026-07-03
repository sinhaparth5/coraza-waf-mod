# Varnish cache behind the WAF

Optional accelerator layer for static assets and cache-eligible endpoints.
Varnish sits **downstream** of the WAF and cache misses loop back through the
WAF's own routing, so the VCL is **install-once** — it never changes when
services are added, edited, or removed:

```
client → coraza-waf-mod (:80/:443) → varnishd (127.0.0.1:6081)
                                          │ hit: served from memory
                                          ▼ miss:
                          coraza-waf-mod cache-return (127.0.0.1:6082)
                                          │ routes by service, from the DB
                                          ▼
                                   the real backend
```

Traffic is fully inspected (challenge gate, blocklists, rate limits, Coraza
CRS) and has its spoofable host headers scrubbed before it ever reaches the
cache, so cache poisoning via `X-Forwarded-Host` / `X-Original-URL` is off
the table. Services without caching skip Varnish entirely.

Day to day there is exactly one control surface: the **Varnish Cache** card
on `/admin/settings` (global on/off + address) and the per-service **Cache**
toggle on `/admin/services`. Both apply live — no restarts, no VCL edits, no
systemctl.

## Setup (once)

`deploy/install.sh` does all of this automatically when it detects (or
installs) Varnish. Manual steps, if you prefer:

```bash
sudo apt install varnish                      # Debian/Ubuntu (dnf/yum for RHEL)
sudo cp default.vcl /etc/varnish/default.vcl  # this file, verbatim — no editing
sudo systemctl edit varnish
```

```ini
[Service]
ExecStart=
ExecStart=/usr/sbin/varnishd -a 127.0.0.1:6081 -f /etc/varnish/default.vcl -s malloc,256m
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now varnish
sudo systemctl restart varnish
```

Then flip on the **Varnish Cache** card in `/admin/settings` and toggle
**Cache** on the services that should use it. Done.

## Why loopback-only everywhere

Varnish (`:6081`) must only be reachable by the WAF, and the WAF's
cache-return port (`:6082`) proxies straight to backends with no WAF pipeline
in front — so both bind `127.0.0.1` exclusively. The admin UI refuses to save
a non-loopback Varnish address, the WAF refuses to bind a non-loopback return
address, and the VCL's `local_only` ACL rejects non-local clients as defense
in depth.

## Verify

```bash
curl -sI https://your-site.example/logo.svg | grep -i x-cache   # MISS, then HIT
varnishstat -1 -f MAIN.cache_hit -f MAIN.cache_miss
```

## Operations

- **App deployed a new version?** Nothing to do if your assets use hashed
  filenames. Otherwise empty the cache: `sudo varnishadm "ban req.url ~ ."`
- **Varnish down?** Cache-enabled services return 502 (the WAF's proxy error
  path). Fix Varnish, or flip the Settings toggle off to route those services
  directly to their backends again — applies instantly.
