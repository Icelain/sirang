# sirang

An experimental TCP tunnel over QUIC, with **reverst-style** HTTP reverse tunnels:
tunnel groups, host-based routing, round-robin load balancing, and optional registration auth.

## Install

```bash
cargo install sirang
# or
cargo build --release
```

## Forward tunnel

Traffic: **local TCP → QUIC → remote TCP target**.

```bash
# Remote
sirang forward remote -k key.pem -c cert.pem -f 127.0.0.1:80 -q 0.0.0.0:4433

# Local (cert auto-downloaded; DNS names supported)
sirang forward local -r tunnel.example.com:4433 -l 127.0.0.1:8080
```

## Reverse tunnel

### Legacy mode (per-client TCP ports)

```bash
sirang reverse remote -k key.pem -c cert.pem -q 0.0.0.0:4433 -t 0.0.0.0:5000
sirang reverse local -r host:4433 -l 127.0.0.1:3000
# optional: -H/--http to parse and print HTTP on the local side
```

Multiple locals each get their own remote TCP port (preferred port, then ephemeral).

### Reverst-style HTTP groups (load-balanced)

Like [reverst](https://github.com/flipt-io/reverst): clients register into a **tunnel group**;
a shared HTTP listener on the remote routes by `Host` / `X-Forwarded-Host` and
**round-robins** requests across registered locals.

**Remote** (QUIC tunnel + HTTP front door):

```bash
# Quick local setup (default group "localhost", hosts localhost + 127.0.0.1)
sirang reverse remote -k test_key.pem -c test_cert.pem \
  -q 127.0.0.1:7171 --http 127.0.0.1:8181 \
  --group localhost --user user --password pass

# Or with a groups YAML file (reverst-compatible shape)
sirang reverse remote -k test_key.pem -c test_cert.pem \
  -q 127.0.0.1:7171 --http 127.0.0.1:8181 -g examples/groups.yml
```

**Local** (register + proxy to a local HTTP service):

```bash
sirang reverse local -r localhost:7171 -l 127.0.0.1:8080 \
  --group localhost --user user --password pass
```

Then:

```bash
curl -H 'Host: localhost' http://127.0.0.1:8181/
```

Run several locals with the same `--group` to load-balance.

#### Groups YAML

```yaml
groups:
  "localhost":
    hosts:
      - "localhost"
      - "127.0.0.1"
    authentication:
      basic:
        username: "user"
        password: "pass"
      # bearer:
      #   token: "some-token"
```

| Remote flags | Description |
|--------------|-------------|
| `--http` / `-H` | Shared HTTP listen address (enables group mode) |
| `--groups` / `-g` | Path to groups YAML |
| `--group` | Default group name if not using YAML (default `localhost`) |
| `--user` / `--password` | Basic auth for the default group |
| `--token` | Bearer auth for the default group |
| `--quic` / `-q` | QUIC tunnel address (default `0.0.0.0:4433`) |
| `--management` / `-m` | Management HTTP address (`GET /metrics`, `GET /healthz`) |
| `--connect-password` | Optional password; remote challenges locals with `AUTH_REQUIRED` on connect |

#### Connect password (optional)

Reverse remotes can require a password from every local before the tunnel is established
(legacy TCP mode and group HTTP mode):

```bash
# Remote challenges connecting locals
sirang reverse remote -k key.pem -c cert.pem --connect-password s3cret ...

# Local must supply the same password
sirang reverse local -r host:4433 -l 127.0.0.1:3000 --connect-password s3cret
# group mode:
sirang reverse local -r host:4433 -l 127.0.0.1:3000 --group localhost --connect-password s3cret
```

Flow: remote sends `AUTH_REQUIRED` → local replies `AUTH <password>` → remote sends `AUTH_OK`
(or `AUTH_ERR`) → normal `CONNECTED` / `REGISTER` handshake continues.

This is separate from group **basic/bearer** registration auth (`--user` / `--password` / `--token`).

#### HTTP framing & observability (remote)

In group HTTP mode the remote uses **hyper HTTP/1 framing** on both edges:

- Public listener: preserve header case, collect bodies, set definitive `Content-Length`
- Tunnel side: HTTP/1 client handshake over each QUIC stream (not raw byte copy)
- Hop-by-hop headers stripped; `Via: 1.1 sirang` added on requests and responses
- Structured proxy logs: method, URI, host, group, status, bytes, latency

With `--management 127.0.0.1:9090` the remote exposes Prometheus text metrics:

```bash
curl http://127.0.0.1:9090/metrics
curl http://127.0.0.1:9090/healthz
```

Metrics include registrations, active clients, proxy request counts by host/group/status, latency sums, QUIC accepts, and framing/proxy errors.

| Local flags | Description |
|-------------|-------------|
| `--group` | Tunnel group to join (enables registration + HTTP proxy to `--local`) |
| `--user` / `--password` | Basic auth for registration |
| `--token` | Bearer token for registration |
| `--http` / `-H` | Legacy per-stream HTTP parse/print (when not using `--group`) |

TLS certificates for locals are still **auto-downloaded** from the remote (QUIC port + 1) and cached under `~/.sirang/certs/`.

## Tunnel options

Both `forward` and `reverse` accept these flags. They must be placed **between the tunnel type and the side** (i.e. right after `forward` or `reverse`, before `remote` or `local`):

| Flag | Description |
|------|-------------|
| `--debug` / `-d` | Enable debug/trace logging |
| `--buffersize` / `-b` | Copy buffer size in bytes (default 32 KiB) |

```bash
# Correct: flag between the tunnel type and the side
sirang forward --debug local -r tunnel.example.com:4433
sirang reverse -b 65536 remote -k key.pem -c cert.pem

# Wrong: trailing flags are rejected
sirang forward local -r tunnel.example.com:4433 --debug
```

## Feature comparison with reverst (local parity)

| Feature | reverst | sirang |
|---------|---------|--------|
| Reverse HTTP over QUIC | yes (HTTP/3) | yes (HTTP/1 over QUIC streams) |
| Tunnel groups | yes | yes |
| Host / X-Forwarded-Host routing | yes | yes |
| Round-robin multi-client LB | yes | yes |
| Basic / bearer registration auth | yes | yes |
| Groups YAML | yes | yes |
| Forward TCP tunnel | — | yes |
| Auto cert download for clients | — | yes |
| DNS for remote hostnames | yes (TLS SNI) | yes |
| Management metrics (`/metrics`) | yes | yes (Prometheus text) |
| External / k8s auth | yes | not implemented |

## Development

```bash
cargo test
```

Test certificates (`test_cert.pem` / `test_key.pem`) are self-signed for `localhost` / `127.0.0.1`.

## Progress

- [x] Forward and reverse tunnels
- [x] Debug logging
- [x] Testing
- [x] Automatic certificate download for local clients
- [x] DNS resolution for remote hosts
- [x] Multiple local clients per remote instance
- [x] HTTP mode (hyper) on reverse local
- [x] Reverst-style tunnel groups, host routing, and load balancing

## Benchmarks

See [BENCHMARKS.md](./BENCHMARKS.md) for sirang vs reverst loopback performance results.
