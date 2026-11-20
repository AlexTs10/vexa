#!/usr/bin/env python3
"""parity.py — the same requests against the Python gateway and the Rust gateway, side by side.

Each profile boots one service at a time with the same environment against the same fake upstreams
(admin-api, meeting-api, mcp, agent-api, crm, flows-api) and a real redis-server, sends every step,
and records the status, the answer headers that carry meaning, the body, every upstream request the
step caused, and the logevent.v1 lines it printed. Then the other service runs the same steps on a
flushed Redis and fresh upstream logs, and the two records are compared. Random values (trace ids,
token times, ticket ids) become placeholders before the compare.

    cargo build --release --manifest-path apps/vexa-gateway/Cargo.toml
    cd core/gateway/services/gateway
    uv run --frozen python ../../../../apps/vexa-gateway/parity.py [--profile NAME] [--only TEXT] [-v]
"""
from __future__ import annotations

import argparse
import base64
import http.client
import http.server
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
GW_DIR = ROOT / "core" / "gateway" / "services" / "gateway"
SECRET = "parity-internal-secret-5d1e"
FLOWS_KEY = "parity-flows-service-key-91c4"
HEX32 = re.compile(r"\b[0-9a-f]{32}\b")

USERS = {
    "k-bot": {"user_id": 7, "email": "a@example.org", "scopes": ["bot"], "max_concurrent": 2,
              "workspaces": ["w1"], "credential_class": "key"},
    "k-tx": {"user_id": 8, "email": "t@example.org", "scopes": ["tx"]},
    "k-browser": {"user_id": 9, "scopes": ["browser"]},
    "k-admin": {"user_id": 10, "email": "ad@example.org", "scopes": ["bot", "tx"], "is_admin": True,
                "admin_account": True},
    "k-sess": {"user_id": 7, "email": "a@example.org", "scopes": ["bot", "tx"], "credential_class": "session"},
    "vxd_worker": {"user_id": 7, "scopes": ["bot", "tx"],
                   "delegation": {"session_id": "s-1", "regime": "human", "grants": []}},
}


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ─── fake upstreams ───────────────────────────────────────────────────────────

KEPT = ("x-api-key", "x-trace-id", "x-vexa-identity", "x-vexa-taint", "content-type", "content-length",
        "accept", "x-internal-secret", "x-vexa-internal-accepts-delegation", "x-vexa-service-key",
        "x-custom", "mcp-session-id", "x-vexa-flow-id", "authorization", "x-vexa-service")


class Upstream:
    def __init__(self, role: str):
        self.role, self.port, self.log, self.server = role, _free_port(), [], None
        self.routes: dict = {}

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        up = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _any(self):
                up._serve(self)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _any

        http.server.ThreadingHTTPServer.allow_reuse_address = True
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def _serve(self, h):
        if (h.headers.get("transfer-encoding") or "").lower() == "chunked":
            raw = b""
            while True:
                size = int(h.rfile.readline().strip() or b"0", 16)
                if size == 0:
                    h.rfile.readline()
                    break
                raw += h.rfile.read(size)
                h.rfile.readline()
            framing = "chunked"
        else:
            n = int(h.headers.get("content-length") or 0)
            raw = h.rfile.read(n) if n else b""
            framing = "length" if h.headers.get("content-length") is not None else "none"
        path, _, query = h.path.partition("?")
        headers = {k: _norm_header(k, h.headers.get(k)) for k in KEPT if h.headers.get(k) is not None}
        headers.update({k.lower(): v for k, v in h.headers.items() if k.lower().startswith("x-user-")})
        self.log.append({"role": self.role, "method": h.command, "path": path, "query": query,
                         "framing": framing, "headers": headers, "body": raw.decode("utf-8", "replace")})
        answer = self.answer(h.command, path, raw, h)
        if answer is None:
            return
        status, body, extra = answer
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h.send_response(status)
        if "content-type" not in {k.lower() for k in extra}:
            h.send_header("content-type", "application/json")
        for k, v in extra.items():
            h.send_header(k, v)
        h.send_header("content-length", str(len(data)))
        h.end_headers()
        if h.command != "HEAD":
            h.wfile.write(data)

    def answer(self, method, path, raw, h):
        if (method, path) in self.routes:
            got = self.routes[(method, path)]
            if callable(got):
                return got(h, raw)
            return got if len(got) == 3 else (got[0], got[1], {})
        if self.role == "admin" and path == "/internal/validate":
            tok = json.loads(raw or b"{}").get("token")
            return (200, USERS[tok], {}) if tok in USERS else (401, {"detail": "bad"}, {})
        if self.role == "admin" and re.fullmatch(r"/internal/users/\d+/identity", path):
            return 200, {"user_id": int(path.split("/")[3]), "email": "a@example.org", "scopes": ["browser"],
                         "credential_class": "key", "workspaces": ["w1"]}, {}
        if self.role == "meeting" and path == "/ws/authorize-subscribe":
            ms = json.loads(raw or b"{}").get("meetings") or []
            return 200, {"authorized": [{"platform": m["platform"], "native_id": m["native_meeting_id"],
                                         "user_id": 7, "meeting_id": 55} for m in ms
                                        if m["native_meeting_id"] != "denied"],
                         "errors": [f"denied:{m['platform']}" for m in ms if m["native_meeting_id"] == "denied"]}, {}
        return 200, {"ok": True, "role": self.role, "path": path}, {"x-upstream": "1"}


def sse(chunks, status=200, ctype="text/event-stream", extra=None):
    def answer(h, raw):
        h.send_response(status)
        h.send_header("content-type", ctype)
        h.send_header("connection", "close")
        for k, v in (extra or {}).items():
            h.send_header(k, v)
        h.end_headers()
        for c in chunks:
            h.wfile.write(c)
            h.wfile.flush()
            time.sleep(0.05)
        h.close_connection = True
        return None
    return answer


def _claims(token: str) -> dict:
    try:
        part = token.split(".")[1]
        c = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:  # noqa: BLE001
        return {"unreadable": token}
    for k in ("iat", "exp", "jti"):
        if k in c:
            c[k] = f"<{k}>"
    return c


def _norm_header(k: str, v):
    if v is None:
        return None
    if k in ("x-vexa-identity", "x-vexa-subject-ticket", "x-vexa-subject-grant"):
        return [_claims(t) for t in v.split(",")]
    if k == "x-trace-id":
        return "<trace>" if HEX32.fullmatch(v) else v
    return v


# ─── redis ────────────────────────────────────────────────────────────────────

class Redis:
    def __init__(self, tmp: pathlib.Path):
        self.port = _free_port()
        exe = shutil.which("redis-server") or "/opt/homebrew/bin/redis-server"
        self.proc = subprocess.Popen([exe, "--port", str(self.port), "--save", "", "--appendonly", "no",
                                      "--dir", str(tmp)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("redis-server did not start")

    def cmd(self, *args: str) -> bytes:
        s = socket.create_connection(("127.0.0.1", self.port), 2)
        s.sendall(f"*{len(args)}\r\n".encode() + b"".join(b"$%d\r\n%s\r\n" % (len(a.encode()), a.encode()) for a in args))
        out = s.recv(65536)
        s.close()
        return out

    def stop(self):
        self.proc.terminate()
        self.proc.wait(5)


# ─── the services ─────────────────────────────────────────────────────────────

class Service:
    def __init__(self, kind: str, env: dict, rust_bin: pathlib.Path, logdir: pathlib.Path):
        self.kind, self.port, self.door_port = kind, _free_port(), _free_port()
        self.env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp"), "LOG_LEVEL": "warning",
                    **env, "PORT": str(self.port), "HOST": "127.0.0.1",
                    "VEXA_GATEWAY_SERVICE_DOOR_PORT": str(self.door_port)}
        if kind == "py":
            self.env["PYTHONPATH"] = str(GW_DIR / "src")
            cmd = [sys.executable, "-m", "gateway"]
        else:
            self.env["VEXA_SOURCE_DIR"] = str(ROOT)
            cmd = [str(rust_bin)]
        self.log_path = logdir / f"{kind}-{self.port}.log"
        self.log_file = open(self.log_path, "wb")
        self.proc = subprocess.Popen(cmd, env=self.env, cwd=str(GW_DIR), stdout=self.log_file, stderr=subprocess.STDOUT)
        self.read = 0
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{kind} exited: {self.log_path.read_text()[-3000:]}")
            try:
                c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=1)
                c.request("GET", "/health")
                if c.getresponse().status == 200:
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError(f"{kind} did not answer /health")
        time.sleep(0.3)
        self.events()

    def events(self) -> list:
        time.sleep(0.2)
        data = self.log_path.read_bytes()
        new, self.read = data[self.read:], len(data)
        out = []
        for line in new.decode("utf-8", "replace").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if isinstance(e, dict) and "event" in e:
                e["ts"] = "<ts>"
                e["trace_id"] = "<trace>"
                out.append(e)
        return sorted(out, key=lambda e: json.dumps(e, sort_keys=True))

    def rss_kb(self) -> int:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(self.proc.pid)], capture_output=True, text=True).stdout
        return int(out.strip() or 0)

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log_file.close()


# ─── a request and a websocket ────────────────────────────────────────────────

ANSWER_HEADERS = ("content-type", "content-length", "location", "allow", "retry-after", "cache-control",
                  "x-accel-buffering", "mcp-session-id", "mcp-protocol-version", "content-disposition",
                  "content-range", "x-upstream", "transfer-encoding", "x-vexa-subject-ticket",
                  "x-vexa-subject-grant")


def call(port, method, path, headers=None, body=None, raw_body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
    hs = dict(headers or {})
    if body is not None:
        hs.setdefault("content-type", "application/json")
    c.putrequest(method, path, skip_accept_encoding=True)
    for k, v in hs.items():
        c.putheader(k, v)
    if data is not None and "content-length" not in {k.lower() for k in hs}:
        c.putheader("content-length", str(len(data)))
    c.endheaders()
    if data is not None:
        try:
            c.send(data)
        except OSError:
            pass
    r = c.getresponse()
    got = r.read()
    out = {"status": r.status}
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    for k in ANSWER_HEADERS:
        if k in hdrs:
            v = hdrs[k]
            if k == "allow":
                v = sorted(x.strip() for x in v.split(","))
            out[k] = _norm_header(k, v) if k.startswith("x-vexa-subject") else v
    out["x-trace-id"] = _norm_header("x-trace-id", hdrs.get("x-trace-id"))
    text = got.decode("utf-8", "replace")
    try:
        out["json"] = json.loads(text)
    except ValueError:
        out["text"] = HEX32.sub("<hex>", text)
    c.close()
    return out


def ws(port, path, headers=None, protocols=None, script=(), wait=1.0):
    """Open a websocket, send each item of the script (a frame, ("sleep", s) or ("redis", channel,
    message)), and read until the close or a second of silence."""
    from websockets.exceptions import ConnectionClosed, InvalidStatus
    from websockets.sync.client import connect
    out = {"frames": []}
    try:
        conn = connect(f"ws://127.0.0.1:{port}{path}", additional_headers=headers or {},
                       subprotocols=protocols, open_timeout=10, compression=None)
    except InvalidStatus as e:
        return {"handshake": e.response.status_code}
    out["subprotocol"] = conn.subprotocol

    def drain(t):
        while True:
            try:
                m = conn.recv(timeout=t)
            except TimeoutError:
                return True
            except ConnectionClosed as e:
                out["close"] = e.rcvd.code if e.rcvd else None
                return False
            try:
                out["frames"].append(json.loads(m))
            except (ValueError, TypeError):
                out["frames"].append(m if isinstance(m, str) else repr(m))

    alive = True
    for item in script:
        if not alive:
            break
        if isinstance(item, tuple) and item[0] == "sleep":
            time.sleep(item[1])
            continue
        if isinstance(item, tuple) and item[0] == "redis":
            REDIS.cmd("PUBLISH", item[1], item[2])
        else:
            try:
                conn.send(item)
            except ConnectionClosed:
                break
        alive = drain(0.5)
    if alive:
        drain(wait)
    out.setdefault("close", None)
    conn.close()
    return out


REDIS = None


# ─── profiles ─────────────────────────────────────────────────────────────────

def edge_steps(up):
    K = {"x-api-key": "k-bot"}
    big = b"x" * (1024 * 1024 + 10)
    return [
        ("health", lambda p: call(p.port, "GET", "/health")),
        ("health HEAD", lambda p: call(p.port, "HEAD", "/health")),
        ("health 405", lambda p: call(p.port, "DELETE", "/health")),
        ("not found", lambda p: call(p.port, "GET", "/nope")),
        ("redirect slash", lambda p: call(p.port, "GET", "/meetings/?a=1")),
        ("auth/me missing", lambda p: call(p.port, "GET", "/auth/me")),
        ("auth/me invalid", lambda p: call(p.port, "GET", "/auth/me", {"x-api-key": "nope"})),
        ("auth/me", lambda p: call(p.port, "GET", "/auth/me", K)),
        ("auth/me admin", lambda p: call(p.port, "GET", "/auth/me", {"x-api-key": "k-admin"})),
        ("auth/me delegated", lambda p: call(p.port, "GET", "/auth/me", {"x-api-key": "vxd_worker"})),
        ("meetings list", lambda p: call(p.port, "GET", "/meetings?limit=5&a=1&a=2&q=x+y%2F", {**K, "x-trace-id": "t-given", "x-custom": "c", "x-user-id": "999", "x-internal-secret": "forged"})),
        ("meetings 401", lambda p: call(p.port, "GET", "/meetings")),
        ("meetings 403 scope", lambda p: call(p.port, "GET", "/meetings", {"x-api-key": "k-browser"})),
        ("meetings HEAD 403", lambda p: call(p.port, "HEAD", "/meetings", K)),
        ("delegated route 403", lambda p: call(p.port, "GET", "/meetings", {"x-api-key": "vxd_worker"})),
        ("transcript", lambda p: call(p.port, "GET", "/transcripts/zoom/123", K)),
        ("transcript 422", lambda p: call(p.port, "GET", "/transcripts/skype/123", K)),
        ("meeting int 422", lambda p: call(p.port, "GET", "/meetings/abc", K)),
        ("meeting int lax", lambda p: call(p.port, "GET", "/meetings/%2B1_0", K)),
        ("encoded separator", lambda p: call(p.port, "GET", "/transcripts/zoom/a%2Fb", K)),
        ("bots POST", lambda p: call(p.port, "POST", "/bots", K, body={"platform": "zoom", "native_meeting_id": "1"})),
        ("bots DELETE", lambda p: call(p.port, "DELETE", "/bots/zoom/123", K)),
        ("put empty", lambda p: call(p.port, "PUT", "/user/settings", K, raw_body=b"")),
        ("too large declared", lambda p: call(p.port, "POST", "/bots", {**K, "content-type": "application/json"}, raw_body=big)),
        ("binary body not capped", lambda p: call(p.port, "PUT", "/user/photo", {**K, "content-type": "image/png"}, raw_body=b"\x89PNG" * 10)),
        ("admin row", lambda p: call(p.port, "GET", "/user/webhook", K)),
        ("directory handle dots", lambda p: call(p.port, "GET", "/user/directory/profiles/..", K)),
        ("calendar id", lambda p: call(p.port, "PATCH", "/user/calendars/c%201", K, body={"a": 1})),
        ("bundle export", lambda p: call(p.port, "GET", "/meetings/5/export", K)),
        ("bundle import", lambda p: call(p.port, "POST", "/meetings/import", {**K, "content-type": "application/zip"}, raw_body=b"PK" * 100)),
        ("upstream error passthrough", lambda p: call(p.port, "GET", "/bots/status", K)),
        ("mcp POST bearer", lambda p: call(p.port, "POST", "/mcp", {"authorization": "Bearer k-bot", "mcp-session-id": "s1"}, body={"jsonrpc": "2.0", "id": 1, "method": "initialize"})),
        ("mcp POST raw auth", lambda p: call(p.port, "POST", "/mcp/sub/x", {"authorization": "k-bot"}, body={"a": 1})),
        ("mcp GET stream", lambda p: call(p.port, "GET", "/mcp", {"x-api-key": "k-bot"})),
        ("mcp taint not delegated", lambda p: call(p.port, "POST", "/internal/mcp/taint", K, body={"sources": ["a"]})),
        ("agent stream", lambda p: call(p.port, "POST", "/agent/chat", {"x-api-key": "k-sess"}, body={"message": "hi"})),
        ("agent stream non-sse", lambda p: call(p.port, "POST", "/agent/chat", {"x-api-key": "k-sess"}, body={"message": "json"})),
        ("agent tail", lambda p: call(p.port, "GET", "/agent/some/where?x=1", {"x-api-key": "k-sess"})),
        ("agent tier", lambda p: call(p.port, "GET", "/agent/chat/folders", {"x-api-key": "k-tx"})),
        ("crm tail", lambda p: call(p.port, "GET", "/crm/records/1", K)),
        ("ws unknown path", lambda p: ws(p.port, "/ws/nope")),
        ("ws missing key", lambda p: ws(p.port, "/ws")),
        ("ws invalid key", lambda p: ws(p.port, "/ws", {"x-api-key": "nope"})),
        ("ws browser scope", lambda p: ws(p.port, "/ws", {"x-api-key": "k-browser"})),
        ("ws flow", lambda p: ws(p.port, "/ws", protocols=["vexa.v1", "vexa.key.k-bot"], script=[
            json.dumps({"action": "ping"}), "not json", json.dumps({"action": "what"}),
            json.dumps({"action": "subscribe", "meetings": []}),
            json.dumps({"action": "subscribe", "meetings": [{"platform": "zoom", "native_id": "123"}, {"platform": "zoom", "native_id": "denied"}]}),
            ("sleep", 0.3), ("redis", "tc:meeting:55:mutable", '{"type":"transcript","n":1}'),
            ("redis", "u:7:meetings", '{"type":"meeting.status"}'),
            json.dumps({"action": "unsubscribe", "meetings": [{"platform": "zoom", "native_id": "123"}, {"platform": "x", "native_id": "y"}]}),
            ("redis", "tc:meeting:55:mutable", '{"type":"after"}'),
        ])),
        ("ws query key", lambda p: ws(p.port, "/ws?api_key=k-bot", script=[json.dumps({"action": "ping"})])),
        ("vnc query key refused", lambda p: ws(p.port, "/bot-accounts/sessions/" + "a" * 32 + "/vnc?api_key=k-bot")),
        ("vnc bad id", lambda p: ws(p.port, "/bot-accounts/sessions/zz/vnc", {"x-api-key": "k-bot"})),
        ("voice missing key", lambda p: ws(p.port, "/voice-notes/abc/stream")),
        ("voice browser scope", lambda p: ws(p.port, "/voice-notes/abc/stream", {"x-api-key": "k-browser"})),
    ]


def edge_routes(up):
    up["meeting"].routes[("GET", "/bots/status")] = (418, b"teapot", {"content-type": "text/plain"})
    up["meeting"].routes[("GET", "/meetings/5/export")] = (200, b"zipdata", {"content-type": "application/zip", "content-disposition": "attachment; filename=m.zip"})
    up["mcp"].routes[("GET", "/mcp")] = sse([b"event: message\ndata: {}\n\n", b"data: 2\n\n"], extra={"mcp-session-id": "s1"})
    up["mcp"].routes[("POST", "/mcp")] = (200, {"jsonrpc": "2.0", "id": 1, "result": {}}, {"mcp-session-id": "s1", "mcp-protocol-version": "2025-06-18"})

    def chat(h, raw):
        if b"json" in raw:
            return 409, {"detail": "busy"}, {}
        return sse([b"data: a\n\n", b"data: b\n\n"])(h, raw)
    up["agent"].routes[("POST", "/api/chat")] = chat


def door_steps(up):
    D = {"x-vexa-service-key": FLOWS_KEY}

    def with_ticket(p):
        c = http.client.HTTPConnection("127.0.0.1", p.door_port, timeout=30)
        c.request("POST", "/identity/internal/validate", body=json.dumps({"token": "k-bot"}), headers={**D, "content-type": "application/json"})
        r = c.getresponse()
        r.read()
        ticket = r.getheader("x-vexa-subject-ticket")
        return call(p.door_port, "DELETE", "/meetings/bots/zoom/123", {**D, "x-user-id": "7", "x-vexa-subject-ticket": f"junk,{ticket}"})

    return [
        ("door health", lambda p: call(p.door_port, "GET", "/health")),
        ("door 405", lambda p: call(p.door_port, "PATCH", "/identity/x")),
        ("door redirect", lambda p: call(p.door_port, "GET", "/identity")),
        ("door no key", lambda p: call(p.door_port, "GET", "/identity/internal/users/5/email")),
        ("door unknown domain", lambda p: call(p.door_port, "GET", "/nope/x", D)),
        ("door not listed", lambda p: call(p.door_port, "GET", "/identity/internal/secret", D)),
        ("door identity", lambda p: call(p.door_port, "GET", "/identity/internal/users/5/email?a=1", {**D, "x-user-id": "5", "x-user-scopes": "admin", "x-trace-id": "t1"})),
        ("door crm", lambda p: call(p.door_port, "POST", "/crm/internal/references", D, body={})),
        ("door meetings unbound", lambda p: call(p.door_port, "GET", "/meetings/meetings", {**D, "x-user-id": "7"})),
        ("door meetings no subject", lambda p: call(p.door_port, "GET", "/meetings/meetings", D)),
        ("door bound no ticket", lambda p: call(p.door_port, "GET", "/meetings/transcripts/zoom/123", {**D, "x-user-id": "7"})),
        ("door bound junk ticket", lambda p: call(p.door_port, "GET", "/meetings/transcripts/zoom/123", {**D, "x-user-id": "7", "x-vexa-subject-ticket": "st1.a.b"})),
        ("door bills_to disagrees", lambda p: call(p.door_port, "POST", "/identity/internal/principals/workspace", {**D, "x-user-id": "7"}, body={"bills_to": "8"})),
        ("door validate mints", lambda p: call(p.door_port, "POST", "/identity/internal/validate", {**D, "x-vexa-ticket-grant": "user:7/daily"}, body={"token": "k-sess"})),
        ("door ticket admits", with_ticket),
        ("door inbound no secret", lambda p: call(p.door_port, "POST", "/to-flows/events/signal", body={})),
        ("door inbound", lambda p: call(p.door_port, "POST", "/to-flows/events/signal", {"x-internal-secret": SECRET, "x-vexa-service": "signals"}, body={"e": 1})),
        ("door inbound not listed", lambda p: call(p.door_port, "GET", "/to-flows/events/signal", {"x-internal-secret": SECRET})),
    ]


def guard_steps(up):
    return [(f"guard {i}", lambda p: call(p.port, "GET", "/health")) for i in range(5)]


def down_steps(up):
    return [("auth unavailable", lambda p: call(p.port, "GET", "/auth/me", {"x-api-key": "k-bot"})),
            ("ws auth unavailable", lambda p: ws(p.port, "/ws", {"x-api-key": "k-bot"}, wait=5))]


PROFILES = {
    "edge": (edge_steps, edge_routes, {}),
    "door": (door_steps, None, {"VEXA_FLOWS_SERVICE_KEY": FLOWS_KEY}),
    "guard": (guard_steps, None, {"GUARD_RATE_LIMIT_RPM": "3"}),
    "admin-down": (down_steps, None, {"ADMIN_API_URL": "http://127.0.0.1:9"}),
}


def run_profile(name, rust_bin, tmp, verbose, only=None):
    global REDIS
    steps_of, routes_of, extra = PROFILES[name]
    REDIS = Redis(tmp)
    roles = ["admin", "meeting", "mcp", "agent", "crm", "flows"]
    records, rss = {}, {}
    key_dir = tmp / "keys"
    key_dir.mkdir(exist_ok=True)
    sign, pub = key_dir / "signing.pem", key_dir / "public.pem"
    if not sign.exists():
        subprocess.run([str(rust_bin), "keygen", str(sign), str(pub)], check=True, stdout=subprocess.DEVNULL)
    try:
        for kind in ("py", "rs"):
            REDIS.cmd("FLUSHALL")
            up = {r: Upstream(r).start() for r in roles}
            if routes_of:
                routes_of(up)
            env = {"INTERNAL_API_SECRET": SECRET, "VEXA_GATEWAY_IDENTITY_SIGNING_KEY_FILE": str(sign),
                   "ADMIN_API_URL": up["admin"].url, "MEETING_API_URL": up["meeting"].url,
                   "MCP_URL": up["mcp"].url, "AGENT_API_URL": up["agent"].url, "CRM_API_URL": up["crm"].url,
                   "FLOWS_API_URL": up["flows"].url, "REDIS_URL": f"redis://127.0.0.1:{REDIS.port}/0",
                   "VEXA_AGENT_ALLOW": "7"}
            env.update(extra)
            svc = Service(kind, env, rust_bin, tmp)
            out = []
            try:
                for label, fn in steps_of(up):
                    if only and not any(o in label for o in only):
                        continue
                    for u in up.values():
                        u.log.clear()
                    got = fn(svc)
                    upstream = sorted((e for u in up.values() for e in u.log), key=lambda e: json.dumps(e, sort_keys=True))
                    text = json.dumps([got, upstream, svc.events()])
                    for u in up.values():
                        text = text.replace(f"127.0.0.1:{u.port}", f"<{u.role}>")
                    text = text.replace(f"127.0.0.1:{svc.port}", "<edge>").replace(f"127.0.0.1:{svc.door_port}", "<door>")
                    got, upstream, events = json.loads(text)
                    out.append((label, got, upstream, events))
                rss[kind] = svc.rss_kb()
            finally:
                svc.stop()
                for u in up.values():
                    u.stop()
            records[kind] = out
    finally:
        REDIS.stop()
    rows = []
    for (label, a, ua, la), (_, b, ub, lb) in zip(records["py"], records["rs"]):
        diffs = [part for part, x, y in (("answer", a, b), ("upstream", ua, ub), ("logs", la, lb)) if x != y]
        rows.append((label, diffs))
        if diffs and verbose:
            for part, x, y in (("answer", a, b), ("upstream", ua, ub), ("logs", la, lb)):
                if x != y:
                    print(f"--- {name} / {label} / {part}\n  py: {json.dumps(x, sort_keys=True)[:4000]}\n  rs: {json.dumps(y, sort_keys=True)[:4000]}")
    return rows, rss


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", action="append")
    ap.add_argument("--only", action="append", help="run only the steps whose label holds this text")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--rust-bin", default=str(HERE / "target" / "release" / "vexa-gateway"))
    a = ap.parse_args()
    total = same = 0
    with tempfile.TemporaryDirectory() as t:
        tmp = pathlib.Path(t)
        for name in a.profile or list(PROFILES):
            rows, rss = run_profile(name, pathlib.Path(a.rust_bin), tmp, a.verbose, a.only)
            for label, diffs in rows:
                total += 1
                same += not diffs
                print(f"{'same' if not diffs else 'DIFF':4}  {name:10} {label}" + (f"  ({', '.join(diffs)})" if diffs else ""))
            print(f"      {name:10} RSS after the steps: py {rss.get('py')} KiB, rs {rss.get('rs')} KiB")
    print(f"{same}/{total} steps the same")
    sys.exit(0 if same == total else 1)


if __name__ == "__main__":
    main()
