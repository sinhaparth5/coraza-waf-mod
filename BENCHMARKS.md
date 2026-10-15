# Benchmarks

Two ways to measure the request pipeline: Go benchmarks for per-request cost
(repeatable, no server needed), and a load test against a running binary for
throughput and tail latency.

## Go benchmarks

`internal/proxy/bench_test.go` drives `proxy.Handler.Handle` with every stage
active (IP blocklist, geo, bot challenge, rate limit, Coraza + CRS, reverse
proxy) against a local test backend:

| Benchmark | Request |
|---|---|
| `Handle/clean` | browser-like GET, unique query each time, so CRS runs in full |
| `Handle/clean_cached` | the same GET repeated, answered by the WAF verdict cache |
| `Handle/waf_blocked` | SQL injection in the query, 403 from CRS |
| `Handle/large_body` | 64 KiB JSON POST, inspected by CRS |
| `HandleParallel` | `clean` from every core at once; wall time per request, so 1/x is throughput |

```bash
make bench                       # 6 runs of each -> bench.txt
```

To check a change, run `make bench` on `main` and on your branch (same
machine, nothing else busy), then compare:

```bash
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e main.txt branch.txt
```

benchstat marks differences it considers significant; `~` means noise.

### Baseline

2026-10-15, commit 983c97e, Go 1.27.2, Intel i5-8400H (6 cores, 8 threads), WSL2.
Median of 6 runs.

| Benchmark | Time/op | Memory/op | Allocs/op |
|---|---|---|---|
| `Handle/clean` | 1.16 ms | 217 KiB | 3,179 |
| `Handle/clean_cached` | 242 µs | 50 KiB | 178 |
| `Handle/waf_blocked` | 1.39 ms | 178 KiB | 3,244 |
| `Handle/large_body` | 413 ms | 153 MiB | 112,700 |
| `HandleParallel` | 388 µs (≈2,600 req/s) | 214 KiB | 3,202 |

Most of a clean request is CRS evaluation: the verdict cache, which skips the
Coraza transaction, cuts it by about 80%. The 64 KiB JSON body is the outlier
at roughly 400 ms and 150 MiB allocated per request: CRS runs every rule over
every JSON value.

## Load test

Throughput and p50/p95/p99 latency against a real binary. Run everything on
one machine and close other busy programs.

1. Start a backend that answers quickly, e.g. `python3 -m http.server 9000`
   in a directory with an `index.html`.
2. Build and start Palisade on a throwaway database:

   ```bash
   make build
   ./palisade --db /tmp/bench.db
   ```

   Sign in to `/admin`, add a service with Prefix `/` and backend
   `http://127.0.0.1:9000`. Keep bot protection off, or the load generator
   gets challenged instead of proxied.
3. Run the load. With [wrk](https://github.com/wg/wrk):

   ```bash
   wrk -t4 -c64 -d30s --latency http://127.0.0.1:8080/
   ```

   wrk reports p50/p75/p90/p99. For p95, use [k6](https://k6.io):

   ```bash
   k6 run --vus 64 --duration 30s --summary-trend-stats 'avg,p(50),p(95),p(99)' - <<'EOF'
   import http from 'k6/http';
   export default function () { http.get(`http://127.0.0.1:8080/?n=${__VU}-${__ITER}`); }
   EOF
   ```

   The `?n=` query makes every request unique so CRS runs in full. wrk sends
   the same URL every time, so it measures the verdict-cache path.

Record results here with the date, commit, machine and command used.
