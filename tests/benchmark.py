"""Benchmark TLS 1.3 + mTLS vs TCP sin cifrar (RS3).
Uso: python -m tests.benchmark --host vpn.u-secure.es --n 300
"""
import argparse
import csv
import json
import socket
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app.client import _rpc, build_context
from pki import pki_utils as u

OUT = Path(__file__).resolve().parent.parent / "evidence"

def pct(v, p):
    if not v:
        return float("nan")
    v = sorted(v)
    return v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))]

def client(host, port, user, ctx, nmsg, size, barrier):
    try:
        barrier.wait(timeout=120)                   # todos arrancan a la vez
        t0 = time.perf_counter()
        raw = socket.create_connection((host, port), timeout=60)
        s = ctx.wrap_socket(raw, server_hostname=host) if ctx else raw
        t_conn = time.perf_counter() - t0           # TCP (+ handshake TLS)
        f = s.makefile("rwb")
        t1 = time.perf_counter()
        r = _rpc(f, {"cmd": "LOGIN", "user": user, "password": f"Test#2026-{user}"})
        t_login = time.perf_counter() - t1
        if not r.get("ok"):
            raise RuntimeError("login")
        text, rtts = "x" * size, []
        for _ in range(nmsg):
            ts = time.perf_counter()
            _rpc(f, {"cmd": "MSG", "text": text})
            rtts.append(time.perf_counter() - ts)
        _rpc(f, {"cmd": "LOGOUT"})
        s.close()
        return {"ok": True, "conn": t_conn, "login": t_login, "rtts": rtts}
    except Exception as e:
        return {"ok": False, "err": type(e).__name__}

def run_mode(mode, host, port, users, ctxs, nmsg, size):
    barrier = threading.Barrier(len(users))
    t0 = time.perf_counter()
    with ThreadPoolExecutor(len(users)) as ex:
        futs = [ex.submit(client, host, port, usr, ctxs.get(usr), nmsg, size, barrier)
                for usr in users]
        res = [f.result() for f in futs]
    wall = time.perf_counter() - t0
    ok = [r for r in res if r["ok"]]
    rtts = [x for r in ok for x in r["rtts"]]
    conn, login = [r["conn"] for r in ok], [r["login"] for r in ok]
    ms = lambda x: round(x * 1000, 2)
    return {
        "modo": mode, "clientes_ok": len(ok), "errores": len(res) - len(ok),
        "causas": dict(Counter(r["err"] for r in res if not r["ok"])),
        "wall_s": round(wall, 2),
        "msgs_s": round(len(ok) * nmsg / wall, 1),
        "kb_s": round(len(ok) * nmsg * size / 1024 / wall, 1),
        "conn_p50_ms": ms(pct(conn, 50)), "conn_p95_ms": ms(pct(conn, 95)),
        "login_p50_ms": ms(pct(login, 50)), "login_p95_ms": ms(pct(login, 95)),
        "rtt_mean_ms": ms(sum(rtts) / len(rtts)) if rtts else None,
        "rtt_p50_ms": ms(pct(rtts, 50)), "rtt_p95_ms": ms(pct(rtts, 95)),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="vpn.u-secure.es")
    ap.add_argument("--tls-port", type=int, default=8443)
    ap.add_argument("--plain-port", type=int, default=8080)
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--msgs", type=int, default=20)
    ap.add_argument("--size", type=int, default=512)
    a = ap.parse_args()

    users = [e["cn"] for e in u.load_index()["certs"]
             if e["kind"] == "client" and e["status"] == "active"][:a.n]
    if len(users) < a.n:
        print(f"[AVISO] solo hay {len(users)} usuarios activos")
    ctxs = {usr: build_context(usr) for usr in users}

    rows = [run_mode("plain", a.host, a.plain_port, users, {}, a.msgs, a.size),
            run_mode("tls13_mtls", a.host, a.tls_port, users, ctxs, a.msgs, a.size)]
    OUT.mkdir(exist_ok=True)
    (OUT / "benchmark.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    with open(OUT / "benchmark.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        print(r)
    p, t = rows[0], rows[1]
    for k in ("conn_p50_ms", "login_p50_ms", "rtt_mean_ms", "rtt_p95_ms", "wall_s"):
        if p[k]:
            print(f"overhead {k}: {(t[k] - p[k]) / p[k] * 100:+.1f}%")

if __name__ == "__main__":
    main()