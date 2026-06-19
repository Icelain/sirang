# sirang

An experimental TCP tunnel over QUIC. Supports **forward** and **reverse** tunnels, automatic TLS certificate download for local clients, DNS resolution for domain-backed remotes, and multiple local clients per remote instance.

## Install

```bash
cargo install sirang
```

Or install prebuilt binaries from the [GitHub Releases](https://github.com/Icelain/sirang/releases) page.

Or clone and build:

```bash
cargo build --release
```

## Forward tunnel

Traffic flows: **local TCP → QUIC → remote TCP target**.

### Remote

```bash
sirang forward remote --key <PATH> --cert <PATH> --forward <ADDRESS> [--quic <ADDRESS>]
```

| Flag | Description |
|------|-------------|
| `--key` / `-k` | TLS private key (required) |
| `--cert` / `-c` | TLS certificate (required) |
| `--forward` / `-f` | TCP address to forward to (required) |
| `--quic` / `-q` | QUIC listen address (default `0.0.0.0:4433`) |

The remote also serves its certificate over TCP on **QUIC port + 1** so local clients can download it automatically.

### Local

```bash
sirang forward local --remote <HOST:PORT> [--local <ADDRESS>]
```

| Flag | Description |
|------|-------------|
| `--remote` / `-r` | Remote sirang instance as `host:port` or `ip:port` (required). Hostnames are DNS-resolved. |
| `--local` / `-l` | Local TCP listen address (default `127.0.0.1:8080`) |

No `--cert` is needed. On first connect the client downloads the remote certificate and caches it under `~/.sirang/certs/`.

Multiple local clients may connect to the same remote forward instance; each has its own QUIC connection and traffic is handled independently.

## Reverse tunnel

Traffic flows: **remote TCP → QUIC → local TCP target**.

### Remote

```bash
sirang reverse remote --key <PATH> --cert <PATH> [--quic <ADDRESS>] [--tcp <ADDRESS>]
```

| Flag | Description |
|------|-------------|
| `--key` / `-k` | TLS private key (required) |
| `--cert` / `-c` | TLS certificate (required) |
| `--quic` / `-q` | QUIC listen address (default `0.0.0.0:4433`) |
| `--tcp` / `-t` | Preferred TCP listen address for clients (default `0.0.0.0:5000`) |

Certificate download works the same as forward (QUIC port + 1).

Multiple local clients may attach to one reverse remote. The first client gets the preferred `--tcp` address; additional clients receive an ephemeral port on the same IP. Each client is told its public access address during the handshake.

### Local

```bash
sirang reverse local --remote <HOST:PORT> --local <ADDRESS>
```

| Flag | Description |
|------|-------------|
| `--remote` / `-r` | Remote sirang instance as `host:port` (required). Supports DNS names. |
| `--local` / `-l` | Local TCP address to expose remotely (required) |

Again, no `--cert` on the local side.

## Global options

These apply to both `forward` and `reverse`:

| Flag | Description |
|------|-------------|
| `--debug` / `-d` | Enable debug/trace logging |
| `--buffersize` / `-b` | Copy buffer size in bytes (default 32 KiB) |

## Examples

```bash
# Remote (VPS): forward tunnel to an internal HTTP service
sirang forward remote -k key.pem -c cert.pem -f 127.0.0.1:80 -q 0.0.0.0:4433

# Local: reach that service via DNS name (cert auto-downloaded)
sirang forward local -r tunnel.example.com:4433 -l 127.0.0.1:8080

# Remote: reverse tunnel endpoint
sirang reverse remote -k key.pem -c cert.pem

# Local A and B can both connect to the same remote
sirang reverse local -r tunnel.example.com:4433 -l 127.0.0.1:3000
sirang reverse local -r tunnel.example.com:4433 -l 127.0.0.1:3001
```

## Development

```bash
cargo test
```

Test certificates (`test_cert.pem` / `test_key.pem`) are self-signed for `localhost` / `127.0.0.1` and used by the QUIC integration tests.

## Progress

- [x] Forward and reverse tunnels
- [x] Debug logging
- [x] Testing
- [x] Automatic certificate download for local clients
- [x] DNS resolution for remote hosts
- [x] Multiple local clients per remote instance
- [x] Simplified CLI
