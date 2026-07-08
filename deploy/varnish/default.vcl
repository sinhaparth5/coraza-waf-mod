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

    # Cache purge: the WAF sends this directly (never client traffic) when an
    # admin clicks "Purge" for a service on /admin/services, e.g. right after
    # a deploy. Already past the local_only ACL check above. Bans every
    # object tagged with this service by vcl_backend_response below — objects
    # cached before that tagging existed simply won't match and age out on
    # their own TTL instead.
    if (req.method == "PURGE") {
        ban("obj.http.X-Cache-Service == " + req.http.X-Cache-Service);
        return (synth(200, "Purged"));
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

    # Rule B: authenticated / session traffic — never cache, with one opt-in
    # exception. Bearer-token APIs always pass straight through.
    if (req.http.Authorization) {
        return (pass);
    }
    if (req.http.Cookie) {
        # X-Cache-Session is only set by the WAF when a service has opted
        # into session-aware caching (admin toggle, off by default) AND this
        # request actually carries that service's session cookie — it's a
        # hash of the cookie value, computed after the request already
        # passed the full WAF pipeline. Partition the cache per session
        # instead of refusing to cache at all; vcl_hash folds this value in
        # below, so different sessions never share a cache entry.
        if (req.http.X-Cache-Session) {
            return (hash);
        }
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

    # Session-aware caching (opt-in, see vcl_recv Rule B): further partition
    # by session so two different logged-in users never share a cached
    # response for the same URL.
    if (req.http.X-Cache-Session) {
        hash_data(req.http.X-Cache-Session);
    }
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

    # Session-aware caching (opt-in): a per-session cache entry should go
    # stale fast regardless of what TTL the backend's Cache-Control claims —
    # this is live, personalized content, not a static asset. Responses that
    # rotate the session token still hit the Set-Cookie branch above and stay
    # fully uncacheable, which only busts *this* session's hash bucket, not
    # the whole service's cache (see vcl_hash).
    if (bereq.http.X-Cache-Session && beresp.ttl > 10s) {
        set beresp.ttl = 10s;
    }

    # Per-service TTL floor/ceiling — admin-configurable on /admin/services
    # ("Cache tuning"), sent as X-Cache-TTL-Floor/-Ceiling by the Director in
    # services/registry.go. Absent for a service that hasn't set one, in
    # which case these are no-ops (the guarding if already requires the
    # header to be present before either branch runs).
    if (bereq.http.X-Cache-TTL-Floor && beresp.ttl < std.duration(bereq.http.X-Cache-TTL-Floor + "s", beresp.ttl)) {
        set beresp.ttl = std.duration(bereq.http.X-Cache-TTL-Floor + "s", beresp.ttl);
    }
    if (bereq.http.X-Cache-TTL-Ceiling && beresp.ttl > std.duration(bereq.http.X-Cache-TTL-Ceiling + "s", beresp.ttl)) {
        set beresp.ttl = std.duration(bereq.http.X-Cache-TTL-Ceiling + "s", beresp.ttl);
    }

    # Tag the object with its service so a purge's ban() expression
    # (vcl_recv) can target it without affecting other services' entries.
    # Stripped from the client-visible response in vcl_deliver.
    set beresp.http.X-Cache-Service = bereq.http.X-Cache-Service;

    # Grace: how long a stale object may still be served (e.g. while a fresh
    # copy is being fetched, or if the backend is briefly unreachable). Keep:
    # how much longer after that a stale object is kept around for
    # conditional revalidation instead of being evicted outright. Both are
    # admin-configurable per service (X-Cache-Grace/-Keep) and default to the
    # previous flat 30s otherwise. Note this widens Varnish's existing
    # stale-tolerance window — it is not proactive background revalidation
    # ahead of expiry, which Varnish has no simple built-in primitive for.
    set beresp.grace = 30s;
    set beresp.keep = 30s;
    if (bereq.http.X-Cache-Grace) {
        set beresp.grace = std.duration(bereq.http.X-Cache-Grace + "s", 30s);
    }
    if (bereq.http.X-Cache-Keep) {
        set beresp.keep = std.duration(bereq.http.X-Cache-Keep + "s", 30s);
    }
}

sub vcl_deliver {
    # Surface cache effectiveness to the WAF logs / curl -I debugging.
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
    # Internal partition marker (see vcl_backend_response) — not for clients.
    unset resp.http.X-Cache-Service;
}
