# Benchmarks: sirang vs reverst

Comparative performance of **sirang** (reverse HTTP group mode) and
[flipt-io/reverst](https://github.com/flipt-io/reverst) on the same machine,
using the same workload shape: public HTTP front door → QUIC tunnel → local
HTTP backend.

> These numbers are **loopback** measurements on a single host. They are useful
> for relative comparison and regression tracking, not as absolute WAN/production
> SLOs. Architectures differ (see below).

## Environment

| Item | Value |
|------|--------|
| Date | 2026-06-29 |
| Host | Linux (CachyOS), glibc 2.43 |
| CPU | 12th Gen Intel Core i7-12700H |
| Network | `127.0.0.1` loopback only |
| sirang | `0.1.5` release (`cargo build --release`) |
| reverst | `flipt-io/reverst` main, `go build ./cmd/reverstd` + `./cmd/reverst` |
| Load client | Python 3 `urllib` + `ThreadPoolExecutor` |
| Requests / run | 2000 (+ 50 warmup) |
| Concurrency | 50 |
| HTTP client mode | `Connection: close` (new TCP connection per request) |

### What is being compared

| | **reverst** | **sirang** (group HTTP mode) |
|--|-------------|------------------------------|
| Public edge | HTTP/1 → reverse proxy | HTTP/1 (hyper) |
| Tunnel | QUIC + **HTTP/3** (`quic-go`) | QUIC streams + **HTTP/1 framing** (`s2n-quic` + hyper) |
| Routing | Host / tunnel group | Host / tunnel group |
| Auth in test | Basic (`user` / `pass`) | none (open default group) |
| Local client | `reverst http` | `sirang reverse local --group` |
| Backend | Tiny threaded Python HTTP server | Same |

Both stacks proxy `GET /` with `Host: localhost` to a local backend that returns
a fixed body (`ok` for 0‑byte case, or `x` × N).

## Results

Throughput and latency for successful requests (0 errors in all runs below).

### Throughput (req/s)

| Response body | reverst | sirang | sirang / reverst |
|---------------|--------:|-------:|-----------------:|
| 2 B (`ok`) | 3455 | 3953 | **1.14×** |
| 1 KiB | 3598 | 4082 | **1.13×** |
| 64 KiB | 2540 | 3599 | **1.42×** |

### Latency (ms)

#### 2 B body

| Metric | reverst | sirang |
|--------|--------:|-------:|
| avg | 12.90 | **10.13** |
| p50 | 12.11 | **9.42** |
| p95 | 24.63 | **18.43** |
| p99 | 31.36 | **23.47** |
| max | 44.32 | **35.95** |

#### 1 KiB body

| Metric | reverst | sirang |
|--------|--------:|-------:|
| avg | 12.36 | **9.93** |
| p50 | 11.65 | **9.14** |
| p95 | 23.29 | **18.63** |
| p99 | 29.62 | **23.67** |
| max | 36.41 | 38.26 |

#### 64 KiB body

| Metric | reverst | sirang |
|--------|--------:|-------:|
| avg | 17.76 | **11.97** |
| p50 | 16.54 | **11.42** |
| p95 | 31.65 | **21.10** |
| p99 | 39.70 | **26.33** |
| max | 50.18 | **35.88** |

### Summary

On this loopback setup, **sirang’s reverse group HTTP mode was consistently
faster** than reverst for the tested workload: roughly **+13–14% RPS** on small
responses and about **+42% RPS** at 64 KiB, with lower p50/p95/p99 latency in
almost every cell.

That does **not** mean sirang is universally “better” than reverst:

- reverst speaks **HTTP/3 end-to-end on the tunnel** and is designed as a Go
  library + multi-instance LB edge; this bench uses a single client registration
  on both sides.
- sirang uses **HTTP/1 framing over QUIC streams** (hyper), which is cheaper on
  loopback for this client pattern (`Connection: close` per request).
- Auth, TLS verification policy, Go vs Rust runtimes, and QUIC stacks differ.
- WAN conditions, loss, and multi-client LB behavior were **not** measured.

## Methodology notes

1. Start a minimal HTTP backend on loopback returning a fixed body.
2. Start tunnel server (reverstd / `sirang reverse remote --http … --group …`).
3. Start one tunnel client pointing at the backend.
4. Warm up with 50 GETs.
5. Issue 2000 GETs at concurrency 50; record per-request latency and success.
6. Tear down processes between payload sizes and between products.

Latency is measured client-side (time to full response body). RPS is
successful requests divided by wall-clock duration of the concurrent batch.

### Caveats

- **New connection per request** stresses accept/handshake paths more than a
  keep-alive wrk/hey run would.
- Single tunnel client on each side (no multi-client RR contention in the hot path).
- No TLS on the **public** HTTP port for either product in this setup (TLS is on
  the QUIC tunnel).
- Results will vary by CPU governor, background load, and Go/Rust build flags.

## Reproducing

Requires: Rust toolchain, Go toolchain, Python 3.

```bash
# Build sirang
cd /path/to/sirang && cargo build --release

# Build reverst
git clone https://github.com/flipt-io/reverst /tmp/reverst
cd /tmp/reverst && go build -o /tmp/reverstd ./cmd/reverstd
go build -o /tmp/reverst-cli ./cmd/reverst

# Run harness (adjust paths inside the script if needed)
python3 scripts/bench_vs_reverst.py   # or the script used to generate this file
```

Example manual smoke (reverst):

```bash
# backend on :28080, then:
reverstd -n localhost -g examples/simple/group.yml \
  -k examples/simple/server.key -c examples/simple/server.crt \
  -a 127.0.0.1:27171 -s 127.0.0.1:28181
reverst http -a 127.0.0.1:27171 -n localhost \
  --username user --password pass --insecure \
  -c examples/simple/server.crt http://127.0.0.1:28080
curl -H 'Host: localhost' http://127.0.0.1:28181/
```

Example manual smoke (sirang):

```bash
sirang reverse remote -k test_key.pem -c test_cert.pem \
  -q 127.0.0.1:37171 --http 127.0.0.1:38181 --group localhost
sirang reverse local -r localhost:37171 -l 127.0.0.1:38080 --group localhost
curl -H 'Host: localhost' http://127.0.0.1:38181/
```

## Raw data

Machine-readable results from this run (abbreviated):

```json
{
  "meta": {
    "date": "2026-06-29",
    "requests_per_run": 2000,
    "concurrency": 50,
    "warmup": 50,
    "host": "127.0.0.1 (loopback)",
    "cpu": "12th Gen Intel(R) Core(TM) i7-12700H"
  },
  "results": [
    {"name": "reverst", "payload_bytes": 0, "rps": 3455.1, "latency_ms_p50": 12.11, "latency_ms_p99": 31.36, "errors": 0},
    {"name": "sirang",  "payload_bytes": 0, "rps": 3953.1, "latency_ms_p50": 9.42,  "latency_ms_p99": 23.47, "errors": 0},
    {"name": "reverst", "payload_bytes": 1024, "rps": 3597.8, "latency_ms_p50": 11.65, "latency_ms_p99": 29.62, "errors": 0},
    {"name": "sirang",  "payload_bytes": 1024, "rps": 4081.7, "latency_ms_p50": 9.14,  "latency_ms_p99": 23.67, "errors": 0},
    {"name": "reverst", "payload_bytes": 65536, "rps": 2540.2, "latency_ms_p50": 16.54, "latency_ms_p99": 39.70, "errors": 0},
    {"name": "sirang",  "payload_bytes": 65536, "rps": 3599.2, "latency_ms_p50": 11.42, "latency_ms_p99": 26.33, "errors": 0}
  ]
}
```

## Future work

- Keep-alive / HTTP pipelining client (wrk, oha, or hyper client pool)
- Multi-client load-balanced groups (N locals per product)
- Lossy/WAN network emulation
- CPU and memory profiling under sustained load
- Include sirang **forward** tunnel TCP throughput for completeness
