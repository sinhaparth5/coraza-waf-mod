vcl 4.1;

# Varnish sits BEHIND the Coraza WAF proxy, never in front of it, and this
# file is install-once — it does NOT change when services are added, edited,
# or removed in the admin UI:
#
#   client -> coraza-waf-mod (:80/:443, WAF-inspected)
#          -> varnishd (127.0.0.1:6081, this config)
#          -> coraza-waf-mod cache-return (127.0.0.1:6082, the ONLY backend here)
#          -> the service's real backend (routed by the WAF from its DB)
#
# The WAF only forwards a request here after the full pipeline (challenge
# gate, IP/geo blocklists, rate limits, Coraza CRS) has passed, and it scrubs
# spoofable host headers (X-Forwarded-Host, X-Original-URL, ...) first — so
# nothing client-controlled can poison a cache key. Every request carries
# X-Cache-Service (the service name, set by the WAF): it partitions the cache
# per service here, and tells the WAF's cache-return listener which backend a
# miss belongs to. Backend selection therefore lives in the WAF's database,
# not in this file.

import std;

acl local_only {
    "127.0.0.1";
    "::1";
}

# The WAF's cache-return listener — the single, permanent backend.
# Must match the return address in the WAF (default 127.0.0.1:6082).
backend waf_return {
    .host = "127.0.0.1";
    .port = "6082";
    .connect_timeout        = 5s;
    .first_byte_timeout     = 15s;
    .between_bytes_timeout  = 10s;
}

sub vcl_recv {
    # Defense in depth: the WAF is the only legitimate client. varnishd is
    # already bound to 127.0.0.1 (see README.md); this catches accidental
    # rebinding to a public interface.
    if (client.ip !~ local_only) {
        return (synth(403, "Forbidden"));
    }

    # Only WAF-tagged traffic belongs here.
    if (!req.http.X-Cache-Service) {
        return (synth(400, "Missing service tag"));
    }

    set req.backend_hint = waf_return;

    # Only safe, idempotent methods are cacheable; everything else goes
    # straight through.
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # The WAF's challenge-bypass cookie (cz_bot_ok) is meaningless to the
    # backend and would needlessly fragment or bypass the cache — drop it,
    # keeping any application cookies intact.
    if (req.http.Cookie) {
        set req.http.Cookie = regsuball(req.http.Cookie, "(^|;\s*)cz_bot_ok=[^;]*", "");
        if (req.http.Cookie ~ "^\s*$") {
            unset req.http.Cookie;
        }
    }

    # Rule A: static assets — cache aggressively, ignore cookies entirely.
    if (req.url ~ "\.(png|jpg|jpeg|gif|webp|avif|css|js|mjs|ico|svg|woff2?|ttf|map)(\?.*)?$") {
        unset req.http.Cookie;
        return (hash);
    }

    # Rule B: authenticated / session traffic — never cache.
    if (req.http.Authorization || req.http.Cookie) {
        return (pass);
    }

    # Everything else: anonymous GET/HEAD — cacheable, TTL driven by the
    # backend's Cache-Control (see vcl_backend_response).
    return (hash);
}

sub vcl_hash {
    # Partition the cache per service: two services can share a host (prefix
    # routing) or serve the same path from different backends — the default
    # host+url hash alone would mix their entries.
    hash_data(req.http.X-Cache-Service);
}

sub vcl_backend_response {
    # Never cache responses that set cookies — that is per-user content, and
    # caching it would leak one user's session to everyone.
    if (beresp.http.Set-Cookie) {
        set beresp.uncacheable = true;
        return (deliver);
    }

    # Static assets: cache aggressively regardless of what the backend sends.
    # This sub is appended to Varnish's built-in vcl_backend_response (we
    # never return() past this point), and that built-in independently marks
    # an object uncacheable when it sees Cache-Control: no-store/no-cache/
    # private or Vary: * — regardless of any ttl we set here. Many app
    # frameworks/security middleware attach exactly that to every response,
    # including static files, which silently turns every hit into a
    # permanent MISS (see #11). Since caching was an explicit admin choice
    # (the Cache toggle in /admin/services), it should win over a backend
    # default aimed at dynamic routes — so rewrite the header, not just ttl.
    if (bereq.url ~ "\.(png|jpg|jpeg|gif|webp|avif|css|js|mjs|ico|svg|woff2?|ttf|map)(\?.*)?$") {
        if (beresp.http.Cache-Control ~ "no-store|no-cache|private" || beresp.ttl < 120s) {
            set beresp.http.Cache-Control = "public, max-age=3600";
            set beresp.ttl = 1h;
        }
        if (beresp.http.Vary == "*") {
            unset beresp.http.Vary;
        }
    }

    # Serve stale content for a short window while a fresh copy is fetched.
    set beresp.grace = 30s;
}

sub vcl_deliver {
    # Surface cache effectiveness to the WAF logs / curl -I debugging.
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
}
