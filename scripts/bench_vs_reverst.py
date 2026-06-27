#!/usr/bin/env python3
"""Benchmark sirang vs reverst reverse HTTP tunnels."""
from __future__ import annotations

import json
import os
import signal
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.request import Request, urlopen

SIRANG = "/home/ice/workspace/xai/trace_analysis/sirang/target/release/sirang"
SIRANG_DIR = "/home/ice/workspace/xai/trace_analysis/sirang"
REVERSTD = "/tmp/reverstd"
REVERST = "/tmp/reverst-cli"
REVERST_EX = Path("/tmp/reverst/examples/simple")

REV_QUIC, REV_HTTP, REV_BACKEND = 27171, 28181, 28080
SIR_QUIC, SIR_HTTP, SIR_BACKEND = 37171, 38181, 38080

WARMUP = 50
REQUESTS = 2000
CONCURRENCY = 50
BODY_SIZES = [0, 1024, 64 * 1024]


@dataclass
class Result:
    name: str
    requests: int
    concurrency: int
    errors: int
    rps: float
    latency_ms_avg: float
    latency_ms_p50: float
    latency_ms_p95: float
    latency_ms_p99: float
    latency_ms_max: float
    response_bytes: int
    notes: str = ""


def percentile(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def start_backend(port: int, body: bytes, procs: list):
    p = subprocess.Popen(
        [sys.executable, "/tmp/backend_http.py", str(port), body.decode("latin1")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # backend_http expects body as argv string - for binary x's use len via env
    procs.append(p)
    time.sleep(0.2)


def start_backend2(port: int, body: bytes, procs: list):
    """Backend with body length only (avoids argv encoding issues)."""
    code = (
        "import socket,threading\n"
        f"BODY=b'x'*{len(body)} if {len(body)} else b'ok'\n"
        "RESP=(b'HTTP/1.1 200 OK\\r\\nContent-Length: '+str(len(BODY)).encode()+"
        "b'\\r\\nConnection: close\\r\\n\\r\\n'+BODY)\n"
        "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        f"s.bind(('127.0.0.1',{port}));s.listen(512)\n"
        "def h(c):\n"
        "  d=b''\n"
        "  while b'\\r\\n\\r\\n' not in d:\n"
        "    x=c.recv(65536)\n"
        "    if not x: return\n"
        "    d+=x\n"
        "  try: c.sendall(RESP)\n"
        "  finally: c.close()\n"
        "while True:\n"
        "  c,_=s.accept();threading.Thread(target=h,args=(c,),daemon=True).start()\n"
    )
    p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
    time.sleep(0.2)


def http_once(url: str, host: str | None = None):
    headers = {"Connection": "close"}
    if host:
        headers["Host"] = host
    req = Request(url, headers=headers)
    t0 = time.perf_counter()
    try:
        with urlopen(req, timeout=10) as r:
            data = r.read()
        return (time.perf_counter() - t0) * 1000.0, len(data), True
    except Exception:
        return (time.perf_counter() - t0) * 1000.0, 0, False


def bench(name, url, host, n, concurrency, notes=""):
    for _ in range(WARMUP):
        http_once(url, host)
    latencies = []
    errors = 0
    total_bytes = 0
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(http_once, url, host) for _ in range(n)]
        for f in as_completed(futs):
            dt, nbytes, ok = f.result()
            if ok:
                latencies.append(dt)
                total_bytes += nbytes
            else:
                errors += 1
    elapsed = time.perf_counter() - t0
    latencies.sort()
    ok_n = len(latencies)
    return Result(
        name=name,
        requests=n,
        concurrency=concurrency,
        errors=errors,
        rps=(ok_n / elapsed) if elapsed > 0 else 0.0,
        latency_ms_avg=statistics.fmean(latencies) if latencies else 0.0,
        latency_ms_p50=percentile(latencies, 50),
        latency_ms_p95=percentile(latencies, 95),
        latency_ms_p99=percentile(latencies, 99),
        latency_ms_max=latencies[-1] if latencies else 0.0,
        response_bytes=total_bytes // max(ok_n, 1),
        notes=notes,
    )


def kill_all(procs):
    for p in procs:
        try:
            p.send_signal(signal.SIGTERM)
        except Exception:
            pass
    time.sleep(0.4)
    for p in procs:
        try:
            p.kill()
        except Exception:
            pass


def wait_ok(url, host, tries=40):
    for _ in range(tries):
        _, _, ok = http_once(url, host)
        if ok:
            return True
        time.sleep(0.2)
    return False


def run_reverst(procs, body: bytes) -> Result:
    start_backend2(REV_BACKEND, body, procs)
    p = subprocess.Popen(
        [
            REVERSTD, "-l", "error",
            "-n", "localhost",
            "-g", str(REVERST_EX / "group.yml"),
            "-k", str(REVERST_EX / "server.key"),
            "-c", str(REVERST_EX / "server.crt"),
            "-a", f"127.0.0.1:{REV_QUIC}",
            "-s", f"127.0.0.1:{REV_HTTP}",
        ],
        cwd=str(REVERST_EX),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    procs.append(p)
    time.sleep(0.6)
    p2 = subprocess.Popen(
        [
            REVERST, "http",
            "-a", f"127.0.0.1:{REV_QUIC}",
            "-n", "localhost",
            "--username", "user",
            "--password", "pass",
            "--insecure",
            "-c", str(REVERST_EX / "server.crt"),
            f"http://127.0.0.1:{REV_BACKEND}",
        ],
        cwd=str(REVERST_EX),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    procs.append(p2)
    time.sleep(1.2)
    url = f"http://127.0.0.1:{REV_HTTP}/"
    if not wait_ok(url, "localhost"):
        raise RuntimeError("reverst did not become ready")
    return bench("reverst", url, "localhost", REQUESTS, CONCURRENCY,
                 notes=f"response_body={len(body) if body else 2}B; HTTP/3 (quic-go)")


def run_sirang(procs, body: bytes) -> Result:
    start_backend2(SIR_BACKEND, body, procs)
    p = subprocess.Popen(
        [
            SIRANG, "reverse", "remote",
            "-k", f"{SIRANG_DIR}/test_key.pem",
            "-c", f"{SIRANG_DIR}/test_cert.pem",
            "-q", f"127.0.0.1:{SIR_QUIC}",
            "--http", f"127.0.0.1:{SIR_HTTP}",
            "--group", "localhost",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    procs.append(p)
    time.sleep(0.4)
    p2 = subprocess.Popen(
        [
            SIRANG, "reverse", "local",
            "-r", f"localhost:{SIR_QUIC}",
            "-l", f"127.0.0.1:{SIR_BACKEND}",
            "--group", "localhost",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    procs.append(p2)
    time.sleep(0.8)
    url = f"http://127.0.0.1:{SIR_HTTP}/"
    if not wait_ok(url, "localhost"):
        raise RuntimeError("sirang did not become ready")
    return bench("sirang", url, "localhost", REQUESTS, CONCURRENCY,
                 notes=f"response_body={len(body) if body else 2}B; HTTP/1 over QUIC streams (s2n-quic)")


def main():
    all_results = []
    meta = {
        "date": time.strftime("%Y-%m-%d"),
        "requests_per_run": REQUESTS,
        "concurrency": CONCURRENCY,
        "warmup": WARMUP,
        "host": "127.0.0.1 (loopback)",
        "client": "Python urllib, Connection: close, ThreadPoolExecutor",
        "sirang": subprocess.check_output([SIRANG, "--version"], text=True).strip() if False else "sirang 0.1.5 release",
        "reverst": "flipt-io/reverst (main, go build)",
        "cpu": open("/proc/cpuinfo").read().split("model name")[1].split("\n")[0].split(":")[1].strip() if Path("/proc/cpuinfo").exists() else "unknown",
    }
    try:
        import platform
        meta["platform"] = platform.platform()
    except Exception:
        pass

    for body_len in BODY_SIZES:
        body = b"x" * body_len
        print(f"=== body={body_len}B ===", flush=True)

        procs = []
        try:
            r = run_reverst(procs, body)
            print(r, flush=True)
            all_results.append(asdict(r) | {"payload_bytes": body_len})
        except Exception as e:
            print("reverst failed", e, flush=True)
            all_results.append({"name": "reverst", "error": str(e), "payload_bytes": body_len})
        finally:
            kill_all(procs)
            time.sleep(0.6)

        procs = []
        try:
            r = run_sirang(procs, body)
            print(r, flush=True)
            all_results.append(asdict(r) | {"payload_bytes": body_len})
        except Exception as e:
            print("sirang failed", e, flush=True)
            all_results.append({"name": "sirang", "error": str(e), "payload_bytes": body_len})
        finally:
            kill_all(procs)
            time.sleep(0.6)

    out = {"meta": meta, "results": all_results}
    Path("/tmp/bench_results.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
