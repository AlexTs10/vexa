#!/usr/bin/env python3
"""parity.py — the same requests against the Python mcp and the Rust mcp, side by side.

Each profile boots both services with the same environment against the same fake upstreams
(gateway, the five domains, a ticket sink), sends every step to both, and compares the status,
the answer headers that carry meaning, the body, and every upstream request the step caused.
Random values (session ids, minted trace ids, timestamps) become placeholders before the compare.

    cargo build --release --manifest-path apps/vexa-mcp/Cargo.toml
    cd core/gateway/services/mcp
    uv run --frozen python ../../../../apps/vexa-mcp/parity.py [--only py|rs] [--profile NAME] [-v]

The domain documents are the repository's: meetings, identity and agent from their committed
``mcp.tools.v1*.json`` files; flows and crm from their FastAPI apps' ``openapi()``, generated with
``uv run`` in each project.
"""
from __future__ import annotations

import argparse
import copy
import http.server
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MCP_DIR = ROOT / "core" / "gateway" / "services" / "mcp"
KEY = "parity-key-0123"
FLOWS_KEY = "parity-flows-operator-key-7f3a"


# ─── domain documents ─────────────────────────────────────────────────────────

def _generated_openapi(project: pathlib.Path, code: str, out: pathlib.Path) -> dict:
    subprocess.run(["uv", "run", "--frozen", "--quiet", "python", "-c", code, str(out)], cwd=project,
                   env={**os.environ, "PYTHONPATH": "src"}, check=True, stdout=subprocess.DEVNULL)
    return json.loads(out.read_text())


def domain_documents(tmp: pathlib.Path) -> dict:
    def read(p):
        return json.loads((ROOT / p).read_text())
    docs = {
        "meetings": (read("core/meetings/mcp.tools.v1.json"), read("core/meetings/mcp.tools.v1.openapi.json")),
        "identity": (read("core/identity/services/admin-api/src/admin_api/mcp.tools.v1.json"),
                     read("core/identity/services/admin-api/src/admin_api/mcp.tools.v1.openapi.json")),
        "agent": (read("core/agent/mcp.tools.v1.json"), read("core/agent/mcp.tools.v1.openapi.json")),
    }
    flows = _generated_openapi(ROOT / "core" / "flows", (
        "import json,sys\nfrom flows_integrations import flows_api\n"
        "json.dump(flows_api.app.openapi(), open(sys.argv[1], 'w'))"), tmp / "flows.json")
    docs["flows"] = (read("core/flows/mcp.tools.v1.json"), flows)
    crm = _generated_openapi(ROOT / "core" / "crm", (
        "import json,sys\nfrom crm.api import create_app\n"
        "json.dump(create_app(None, None, 'org').openapi(), open(sys.argv[1], 'w'))"), tmp / "crm.json")
    docs["crm"] = (read("core/crm/mcp.tools.v1.json"), crm)
    return docs


# ─── fake upstreams ───────────────────────────────────────────────────────────

KEPT_HEADERS = ("x-api-key", "x-vexa-internal-mcp-identity", "x-trace-id", "x-flows-operator-key",
                "x-vexa-taint", "content-type", "authorization", "accept", "x-github-api-version")


import itertools
_SEQ = itertools.count()


class Upstream:
    """One fake service on 127.0.0.1. `routes[(method, path)] = (status, body[, headers])`; a body
    that is bytes is sent as is, anything else as JSON."""

    def __init__(self, role: str, manifest=None, openapi=None):
        self.role, self.manifest, self.openapi = role, manifest, openapi
        self.routes: dict = {}
        self.log: list = []
        self.server = None
        self.port = _free_port()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        upstream = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _any(self):
                upstream._serve(self)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _any

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
        length = int(h.headers.get("content-length") or 0)
        raw = h.rfile.read(length) if length else b""
        path, _, query = h.path.partition("?")
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = raw.decode("utf-8", "replace")
        if not (path in ("/.well-known/mcp-tools.json", "/openapi.json") and self.manifest is not None):
            self.log.append({"seq": next(_SEQ), "role": self.role, "method": h.command, "path": path, "query": _query(query),
                             "headers": {k: h.headers[k] for k in KEPT_HEADERS if h.headers.get(k) is not None},
                             "json": parsed})
        status, body, headers = self._answer(h.command, path)
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h.send_response(status)
        sent = {k.lower() for k in headers}
        if "content-type" not in sent and not isinstance(body, bytes):
            h.send_header("content-type", "application/json")
        for k, v in headers.items():
            h.send_header(k, v)
        h.send_header("content-length", str(len(data)))
        h.end_headers()
        h.wfile.write(data)

    def _answer(self, method, path):
        if (method, path) in self.routes:
            got = self.routes[(method, path)]
            return got if len(got) == 3 else (got[0], got[1], {})
        if self.manifest is not None and path == "/.well-known/mcp-tools.json":
            return 200, self.manifest, {}
        if self.manifest is not None and path == "/openapi.json":
            return 200, self.openapi, {}
        if self.role == "gateway" and path == "/internal/mcp/taint":
            return 200, {"state": "none"}, {}
        return 200, {"ok": True, "role": self.role, "path": path}, {}


def _query(q: str) -> list:
    from urllib.parse import parse_qsl
    return parse_qsl(q, keep_blank_values=True)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ─── the two services ─────────────────────────────────────────────────────────

class Service:
    def __init__(self, kind: str, env: dict, rust_bin: pathlib.Path, logdir: pathlib.Path):
        self.kind, self.port = kind, _free_port()
        self.env = {**_base_env(), **env, "PORT": str(self.port), "HOST": "127.0.0.1"}
        self.log_path = logdir / f"{kind}-{self.port}.log"
        self.rust_bin = rust_bin
        self.proc = None
        self.boot_s = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self, wait=True):
        out = open(self.log_path, "wb")
        if self.kind == "py":
            cmd = [str(MCP_DIR / ".venv" / "bin" / "python"), "-m", "vexa_mcp"]
            env = {**self.env, "PYTHONPATH": str(MCP_DIR / "src")}
            cwd = MCP_DIR
        else:
            cmd, env, cwd = [str(self.rust_bin)], self.env, ROOT
        self.started = time.monotonic()
        self.proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT)
        if wait:
            self.wait_ready()
        return self

    def wait_ready(self, timeout=90):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.kind} exited {self.proc.returncode}: {self.log_tail()}")
            try:
                with urllib.request.urlopen(self.url + "/health", timeout=1) as r:
                    if r.status == 200:
                        self.boot_s = time.monotonic() - self.started
                        return
            except Exception:  # noqa: BLE001
                time.sleep(0.05)
        raise RuntimeError(f"{self.kind} did not answer /health: {self.log_tail()}")

    def exit_code(self, timeout=60):
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    def log_tail(self, n=4000):
        try:
            return self.log_path.read_text(errors="replace")[-n:]
        except OSError:
            return ""

    def rss_kib(self):
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(self.proc.pid)], capture_output=True, text=True).stdout
        return int(out.strip() or 0)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _base_env() -> dict:
    keep = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "LANG", "USER") if k in os.environ}
    return {**keep, "VEXA_MCP_BOOT_PROBE_PAUSE_SECONDS": "0", "LOG_LEVEL": "warning"}


# ─── one exchange ─────────────────────────────────────────────────────────────

ANSWER_HEADERS = ("content-type", "www-authenticate", "allow", "location", "mcp-session-id", "x-trace-id")


def exchange(base: str, method: str, path: str, headers: dict, body=None, raw=None,
             stream_seconds: float = 0.0) -> dict:
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        r = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as e:
        r = e
    status = r.status if hasattr(r, "status") else r.code
    got_headers = {k.lower(): v for k, v in r.headers.items()}
    if stream_seconds:
        deadline = time.monotonic() + stream_seconds
        sock = r.fp.raw._sock
        chunks = b""
        while time.monotonic() < deadline:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                piece = r.read1(65536)
            except Exception:  # noqa: BLE001 -- the stream stays open until we stop reading
                break
            if not piece:
                break
            chunks += piece
        r.close()
        text = chunks.decode("utf-8", "replace")
    else:
        text = r.read().decode("utf-8", "replace")
    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        parsed = None
    return {"status": status, "headers": {k: got_headers[k] for k in ANSWER_HEADERS if k in got_headers},
            "text": text, "json": parsed}


# ─── normalisation ────────────────────────────────────────────────────────────

_ISO = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(\+00:00|Z)")
_HEX32 = re.compile(r"\b[0-9a-f]{32}\b")


def normalise(value):
    if isinstance(value, dict):
        out = {k: normalise(v) for k, v in value.items()}
        # fastapi-mcp types a union argument with next(iter(set_of_branch_types)): a Python set of
        # strings, so which branch wins is per-process (hash seed). Either answer is the library's.
        kinds = {b.get("type") for b in out.get("anyOf") or [] if isinstance(b, dict) and b.get("type")} - {"null"}
        if len(kinds) > 1 and out.get("type") in kinds:
            out["type"] = "<one of " + ", ".join(sorted(kinds)) + ">"
        return out
    if isinstance(value, list):
        return [normalise(v) for v in value]
    if isinstance(value, str):
        value = _ISO.sub("<time>", value)
        value = _HEX32.sub("<hex32>", value)
        value = re.sub(r"ping - [^\r\n]+", "ping - <time>", value)
    return value


def record(ex: dict, ups: list, sent_trace=None) -> dict:
    headers = dict(ex["headers"])
    if "mcp-session-id" in headers:
        headers["mcp-session-id"] = "<sid>"
    if "x-trace-id" in headers and headers["x-trace-id"] != sent_trace:
        headers["x-trace-id"] = "<minted>"
    if "allow" in headers:
        # Starlette joins the route's methods from a Python set, so the order is per-process.
        headers["allow"] = ", ".join(sorted(m.strip() for m in headers["allow"].split(",")))
    upstream = []
    for u in ups:
        u = copy.deepcopy(u)
        t = u["headers"].get("x-trace-id")
        if t is not None and t != sent_trace:
            u["headers"]["x-trace-id"] = "<minted>"
        upstream.append(u)
    return normalise({"status": ex["status"], "headers": headers, "json": ex["json"],
                      "text": ex["text"] if ex["json"] is None else None, "upstream": upstream})


# ─── steps ────────────────────────────────────────────────────────────────────

INIT_PARAMS = {"protocolVersion": "2025-03-26", "capabilities": {},
               "clientInfo": {"name": "parity", "version": "0"}}
ACCEPT = "application/json, text/event-stream"


def rpc(method, params=None, *, rid=True, session="sid", headers=None, name=None, setup=None, raw=None,
        capture=False, path="/mcp", http="POST"):
    body = {"jsonrpc": "2.0", "method": method}
    if rid is True:
        body["id"] = "auto"
    elif rid is not None:
        body["id"] = rid
    if params is not None:
        body["params"] = params
    return {"name": name or method, "method": http, "path": path, "body": None if raw is not None else body,
            "raw": raw, "session": session, "headers": headers or {}, "setup": setup, "capture": capture}


def call(tool, arguments=None, *, name=None, setup=None, headers=None):
    params = {"name": tool}
    if arguments is not None:
        params["arguments"] = arguments
    return rpc("tools/call", params, name=name or f"call {tool}", setup=setup, headers=headers)


def rest(method, path, body=None, *, name=None, headers=None, auth=True, setup=None, raw=None):
    h = {"authorization": f"Bearer {KEY}"} if auth else {}
    h.update(headers or {})
    if body is not None or raw is not None:
        h.setdefault("content-type", "application/json")
    return {"name": name or f"{method} {path}", "method": method, "path": path, "body": body, "raw": raw,
            "session": None, "headers": h, "setup": setup, "capture": False, "rest": True}


def opening(capture=True):
    return [rpc("initialize", INIT_PARAMS, session=None, capture=capture, name="initialize"),
            rpc("notifications/initialized", rid=None, name="initialized notification")]


def route(role, method, path, status, body, headers=None):
    def setup(ups):
        ups[role].routes[(method, path)] = (status, body, headers or {})
    return setup


def both(*setups):
    def setup(ups):
        for s in setups:
            s(ups)
    return setup


MEETINGS = {"meetings": [{"id": 7, "platform": "google_meet", "native_meeting_id": "abc-defg-hij",
                          "status": "completed"},
                         {"id": 8, "platform": "teams", "native_meeting_id": "9361792952021", "ref": "kept"}]}
NOTICES = route("flows", "GET", "/queue/notices", 200, {"notices": ["Your trial ends Friday.", " ",
                                                                    "Your trial ends Friday.", 5]})
TRANSCRIPT = {"platform": "google_meet", "native_meeting_id": "abc-defg-hij",
              "segments": [{"text": f"s{i}", "start": i * 1.5} for i in range(7)]}


def protocol_steps():
    return [
        rest("GET", "/health", auth=False),
        rpc("tools/list", session=None, name="tools/list without a session"),
        rpc("initialize", {**INIT_PARAMS, "protocolVersion": "1999-01-01"}, session=None,
            name="initialize with an unknown version"),
        rpc("initialize", {**INIT_PARAMS, "protocolVersion": "2024-11-05"}, session=None,
            name="initialize 2024-11-05"),
        *opening(),
        rpc("ping"),
        rpc("tools/list", name="tools/list"),
        rpc("prompts/list"),
        rpc("prompts/get", {"name": "vexa.meeting_prep", "arguments": {"meeting_url": " https://x ", "notes": "n"}}),
        rpc("prompts/get", {"name": "vexa.during_meeting", "arguments": {"platform": "teams", "native_meeting_id": "1"}}),
        rpc("prompts/get", {"name": "vexa.post_meeting", "arguments": {"platform": "zoom", "native_meeting_id": "2"}}),
        rpc("prompts/get", {"name": "vexa.teams_link_help"}),
        rpc("prompts/get", {"name": "nope"}, name="prompts/get unknown"),
        rpc("resources/list", name="unsupported method"),
        rpc("no/such/method", name="unknown method"),
        rpc("tools/call", {"arguments": {}}, name="tools/call without a name"),
        rpc("ping", rid=None, name="ping as a notification"),
        rpc("ping", rid=7, name="ping with an integer id"),
        rpc("ping", rid=None, raw=b"{not json", name="parse error"),
        rpc("ping", rid=None, raw=b"[1, 2]", name="batch body"),
        rpc("ping", rid=None, raw=b'{"jsonrpc": "2.0", "id": 1}', name="no method"),
        rpc("ping", session="bogus", name="unknown session"),
        rpc("ping", headers={"content-type": "text/plain"}, name="wrong content type"),
        rpc("ping", headers={"accept": "text/event-stream"}, name="accept without json"),
        rpc("ping", headers={"mcp-protocol-version": "1.0"}, name="bad protocol version header"),
        rpc("ping", headers={"mcp-protocol-version": "2025-06-18"}, name="good protocol version header"),
        rpc("ping", path="/mcp?x=1", name="unknown query argument on /mcp"),
        {**rpc("ping"), "name": "GET /mcp without text/event-stream", "method": "GET", "body": None,
         "headers": {"accept": "application/json"}},
        {**rpc("ping"), "name": "GET /mcp stream", "method": "GET", "body": None,
         "headers": {"accept": "text/event-stream"}, "stream": 1.5},
        {**rpc("ping"), "name": "PUT /mcp", "method": "PUT"},
        rest("GET", "/mcp/extra", name="GET /mcp/extra", auth=False),
        {**rpc("ping"), "name": "DELETE /mcp", "method": "DELETE", "body": None},
        rpc("ping", name="ping after DELETE"),
        *opening(),
        rpc("initialize", INIT_PARAMS, name="initialize again on a session"),
        rpc("tools/list", session=None, headers={"authorization": ""}, name="tools/list, no session, no key"),
        rpc("initialize", INIT_PARAMS, session=None, capture=True, name="initialize, no initialized notification"),
        rpc("tools/list", name="tools/list before the initialized notification"),
        rpc("ping", name="ping before the initialized notification"),
        rpc("initialize", {"protocolVersion": "2025-06-18"}, session=None, name="initialize without clientInfo"),
        rpc("notifications/initialized", rid=None, session=None, name="notification without a session"),
        {**rpc("ping"), "name": "DELETE without a session", "method": "DELETE", "body": None, "session": None},
        {**rpc("ping"), "name": "GET without a session", "method": "GET", "body": None, "session": None,
         "headers": {"accept": "text/event-stream"}},
        rpc("ping", headers={"content-type": "application/json-seq"}, name="content type json-seq"),
        rpc("ping", headers={"content-type": "Application/JSON; charset=utf-8"}, name="content type with charset"),
        rpc("tasks/list", name="tasks/list"),
        rpc("tools/call", {"name": "list_meetings", "arguments": "x"}, name="tools/call arguments not an object"),
        rpc("prompts/get", {"name": "vexa.during_meeting", "arguments": {"platform": 5}}, name="prompts/get non-text argument"),
        {**rpc("ping"), "name": "jsonrpc response from the client", "body": {"jsonrpc": "2.0", "id": 99, "result": {}}},
        rpc("ping", rid="text-id", name="ping with a text id"),
        rpc("ping", rid=None, raw=b'{"jsonrpc": "2.0", "id": 1, "method": "ping"} x', name="extra data"),
        rpc("ping", rid=None, raw=b'', name="empty body"),
    ]


def builtin_steps():
    return [
        *opening(),
        call("parse_meeting_link", {"meeting_url": "https://meet.google.com/abc-defg-hij"}),
        call("parse_meeting_link", {"meeting_url": "https://teams.live.com/meet/9361792952021?p=IXw5"},
             name="parse teams live"),
        call("parse_meeting_link", {"meeting_url": "https://teams.microsoft.com/v2/?meetingjoin=true#/meet/9361792952021?p=a"},
             name="parse teams deep link"),
        call("parse_meeting_link", {"meeting_url": "https://teams.microsoft.com/l/meetup-join/19%3ameeting_x/0"},
             name="parse teams legacy"),
        call("parse_meeting_link", {"meeting_url": "https://us05web.zoom.us/j/12345678901?pwd=abc"}, name="parse zoom"),
        call("parse_meeting_link", {"meeting_url": "https://zoom-lfx.platform.linuxfoundation.org/meeting/1234567890?password=u"},
             name="parse hosted zoom"),
        call("parse_meeting_link", {"meeting_url": "https://meet.jit.si/Room1"}, name="parse jitsi"),
        call("parse_meeting_link", {"meeting_url": "https://meet.example.org/Room2"}, name="parse inferred jitsi"),
        call("parse_meeting_link", {"meeting_url": "https://evil.example/zoom.us/j/1"}, name="parse unknown"),
        call("parse_meeting_link", {"meeting_url": "  "}, name="parse empty"),
        call("parse_meeting_link", {"meeting_url": "https://zoom.us/my/room"}, name="parse zoom personal"),
        call("parse_meeting_link", {"meeting_url": "https://meet.google.com/lookup/x"}, name="parse meet lookup"),
        call("parse_meeting_link", {}, name="parse without url"),
        call("parse_meeting_link", {"meeting_url": 5}, name="parse wrong type"),
        call("parse_meeting_link", {"meeting_url": "x", "zzz": 1, "aaa": 2}, name="parse extra arguments"),
        call("request_meeting_bot", {"meeting_url": "https://us05web.zoom.us/j/12345678901?pwd=abc", "bot_name": "N"},
             setup=NOTICES),
        call("request_meeting_bot", {"native_meeting_id": "abc-defg-hij", "allowed_languages": ["de", "en"]},
             name="request bot by id"),
        call("request_meeting_bot", {"meeting_url": "https://meet.google.com/abc-defg-hij", "native_meeting_id": "x"},
             name="request bot both ids"),
        call("request_meeting_bot", {}, name="request bot no id"),
        call("request_meeting_bot", {"native_meeting_id": "abc-defg-hij", "bot_account": "zz"},
             name="request bot bad account"),
        call("request_meeting_bot", {"native_meeting_id": "abc-defg-hij", "allowed_languages": '["de"]'},
             name="request bot stringified list"),
        call("request_meeting_bot", {"native_meeting_id": "abc-defg-hij"}, name="request bot 409",
             setup=both(route("gateway", "POST", "/bots", 409, {"detail": "exists"}),
                        route("gateway", "GET", "/meetings", 200, [{"platform": "google_meet",
                                                                   "native_meeting_id": "abc-defg-hij", "id": 3}]))),
        call("request_meeting_bot", {"native_meeting_id": "abc-defg-hij"}, name="request bot 403 with notices",
             setup=both(NOTICES, route("gateway", "POST", "/bots", 403, {"detail": {"detail": {
                 "code": "quota", "reason": "limit", "message": "Out of minutes.", "action_url": "https://x/billing"}}}))),
        call("request_meeting_bot", {"native_meeting_id": "abc-defg-hij"}, name="request bot 500 text",
             setup=route("gateway", "POST", "/bots", 500, b"boom")),
        call("update_bot_config", {"native_meeting_id": "a/b", "platform": "teams", "language": "de"}),
        call("update_bot_config", {"meeting_id": "..", "meeting_platform": "zoom"}, name="update bot legacy names"),
        call("update_bot_config", {"platform": "webex", "native_meeting_id": "x"}, name="update bot bad platform"),
        call("stop_bot", {"native_meeting_id": "abc-defg-hij"}, setup=NOTICES),
        call("stop_bot", {}, name="stop bot no id"),
        call("list_meetings", {}, setup=route("gateway", "GET", "/meetings", 200, MEETINGS)),
        call("list_meetings", {"limit": 5, "offset": 2, "status": "active", "platform": "zoom",
                               "metadata_filter": '{"crm": "a"}'}, name="list meetings filtered"),
        call("list_meetings", {"metadata_filter": "[1]"}, name="list meetings array filter"),
        call("list_meetings", {"metadata_filter": "{x"}, name="list meetings bad filter"),
        call("list_meetings", {"limit": 0}, name="list meetings limit 0"),
        call("list_meetings", {"limit": "5"}, name="list meetings limit as text"),
        call("list_meetings", {"platform": "webex"}, name="list meetings bad platform"),
        call("get_meeting_transcript", {"native_meeting_id": "abc-defg-hij", "limit": 3},
             setup=route("gateway", "GET", "/transcripts/google_meet/abc-defg-hij", 200, TRANSCRIPT)),
        call("get_meeting_transcript", {"native_meeting_id": "abc-defg-hij", "since_index": 2, "until_index": 6, "limit": 2},
             name="transcript range", setup=route("gateway", "GET", "/transcripts/google_meet/abc-defg-hij", 200, TRANSCRIPT)),
        call("get_meeting_transcript", {"native_meeting_id": "abc-defg-hij", "since_index": 5},
             name="transcript since", setup=route("gateway", "GET", "/transcripts/google_meet/abc-defg-hij", 200, TRANSCRIPT)),
        call("get_meeting_transcript", {"meeting_db_id": 7}, name="transcript by db id"),
        call("get_meeting_transcript", {"since_index": 5, "until_index": 2, "native_meeting_id": "x"},
             name="transcript bad range"),
        call("get_meeting_transcript", {}, name="transcript no id"),
        call("search_transcripts", {"q": "renewal", "meeting_db_id": 7, "platform": "teams", "native_meeting_id": "n"}),
        call("search_transcripts", {"q": ""}, name="search empty q"),
        call("search_transcripts", {}, name="search no q"),
        call("annotate_meeting", {"meeting_db_id": 7, "title": "T", "metadata": {"a": None}},
             setup=route("gateway", "POST", "/meetings/7/annotate", 200,
                         {"id": 7, "platform": "zoom", "status": "active", "data": {"title": "T", "metadata": {"b": 1}}})),
        call("annotate_meeting", {"native_meeting_id": "abc-defg-hij"}, name="annotate nothing"),
        call("annotate_meeting", {"native_meeting_id": "abc-defg-hij", "title": "x"}, name="annotate by room",
             setup=route("gateway", "POST", "/meetings/google_meet/abc-defg-hij/annotate", 200, [1, 2])),
        call("speak_in_meeting", {"native_meeting_id": "abc-defg-hij", "text": "hi", "asked_by_a_human": True}),
        call("speak_in_meeting", {"native_meeting_id": "abc-defg-hij", "text": "hi", "asked_by_a_human": False},
             name="speak not asked"),
        call("speak_in_meeting", {"native_meeting_id": "abc-defg-hij", "text": "hi"}, name="speak missing flag"),
        call("get_meeting_chat", {"native_meeting_id": "abc-defg-hij", "platform": "jitsi"}),
        call("get_meeting", {"meeting_db_id": 7}),
        call("get_meeting", {"meeting_db_id": 0}, name="get meeting 0"),
        call("delete_meeting", {"meeting_db_id": 7, "asked_by_a_human": True}),
        call("delete_meeting", {"meeting_db_id": 7, "asked_by_a_human": True}, name="delete scheduled",
             setup=route("gateway", "DELETE", "/meetings/7", 200, {"status": "deletion_scheduled", "detail": "bot leaving"})),
        call("delete_meeting", {"meeting_db_id": 7, "asked_by_a_human": False}, name="delete not asked"),
        call("get_meeting_participants", {"native_meeting_id": "abc-defg-hij"}),
        call("list_recordings", {"meeting_db_id": 7, "limit": 10}),
        call("browser_session_open", {"platform": "google", "display_name": "Sales"}),
        call("browser_session_open", {"platform": "x"}, name="browser session bad platform"),
        call("bot_accounts_list", {}),
        call("bot_account_verify", {"account_id": "0123456789abcdef0123456789abcdef"}),
        call("bot_account_verify", {"account_id": "nope"}, name="verify bad id"),
        call("report_issue", {"what_i_tried": "list", "what_happened": "It broke\nbadly", "deployment": "cloud",
                              "native_meeting_id": "abc-defg-hij", "severity": 2, "logs": "x" * 5000},
             setup=both(route("gateway", "GET", "/meetings", 200, MEETINGS),
                        route("sink", "POST", "/tickets", 201, {"id": "T-1", "url": "https://t/1"}))),
        call("report_issue", {"what_i_tried": " ", "what_happened": "x", "deployment": "c"}, name="report empty field"),
        call("report_issue", {"what_i_tried": "a", "what_happened": "b", "deployment": "c", "severity": 9},
             name="report bad severity"),
        call("report_issue", {"what_i_tried": "a", "what_happened": "b", "deployment": "c"}, name="report bad key",
             setup=route("gateway", "GET", "/meetings", 401, {"detail": "no"})),
        call("report_issue", {"what_i_tried": "a", "what_happened": "b", "deployment": "c"}, name="report sink refuses",
             setup=route("sink", "POST", "/tickets", 500, {"detail": "no"})),
        call("no_such_tool", {}, name="unknown tool"),
        call("list_meetings", None, name="call without arguments"),
        call("list_meetings", {}, name="call without a key", headers={"authorization": ""}),
        call("list_meetings", {}, name="call with x-api-key", headers={"authorization": "", "x-api-key": "k2"}),
        call("list_meetings", {}, name="call with raw authorization", headers={"authorization": "rawkey"}),
        call("list_meetings", {}, name="call with trace and identity",
             headers={"x-trace-id": "trace-abc", "x-vexa-identity": "signed-identity"}),
    ]


def assembled_steps():
    return [
        *opening(),
        call("get_bot_status", {}, setup=NOTICES),
        call("get_recording", {"recording_id": "r/1"}),
        call("reactions_list", {}),
        call("reaction_signal", {"reaction_id": "..", "verb": "stop"}),
        call("reaction_signal", {"reaction_id": "r1"}, name="reaction signal missing verb"),
        call("reaction_signal", {"reaction_id": "", "verb": "x"}, name="reaction signal empty id"),
        call("whats_waiting", {}),
        call("flows_submit", {"name": "n", "steps": ["agent_run"], "trigger": {"kind": "event", "event": "e"}},
             setup=route("gateway", "GET", "/auth/me", 200, {"admin_account": True})),
        call("flows_submit", {"name": "n", "steps": ["agent_run"]}, name="flows submit not admin"),
        call("flows_submit", {"name": "n", "steps": '["agent_run"]'}, name="flows submit stringified steps",
             setup=route("gateway", "GET", "/auth/me", 200, {"admin_account": True})),
        call("flows_submit", {"name": "n", "steps": []}, name="flows submit empty steps"),
        call("crm_describe", {"object_type": "Person"},
             setup=route("crm", "POST", "/describe", 200, {"types": []}, {"x-vexa-privacy": "private; class=crm"})),
        call("crm_describe", {}, name="crm describe behind the gateway",
             headers={"x-vexa-identity": "signed"},
             setup=route("crm", "POST", "/describe", 200, {"types": []}, {"x-vexa-privacy": "private; class=crm,People"})),
        call("crm_describe", {}, name="crm describe taint unavailable", headers={"x-vexa-identity": "signed"},
             setup=both(route("crm", "POST", "/describe", 200, {"t": 1}, {"x-vexa-privacy": "private"}),
                        route("gateway", "POST", "/internal/mcp/taint", 500, {"detail": "down"}))),
        call("entity_upsert", {"name": "Acme", "facts": "one fact"}, name="entity upsert one fact"),
        call("entity_upsert", {"name": "Acme", "facts": '["a", "b"]'}, name="entity upsert stringified facts"),
        call("report_friction", {"what_i_tried": "x", "what_happened": "y", "kind": "broke"}),
        call("timeline", {"limit": "3"}, name="timeline limit as text"),
        call("settings", {}, setup=route("gateway", "GET", "/user/settings", 403, {"detail": {"reason": "nope"}})),
        call("workspace_read", {"path": "a/b.md"}),
        call("crm_search", {"object_type": "Person", "query": "a", "zzz": 1}, name="crm search extra argument"),
    ]


def rest_steps():
    return [
        rest("GET", "/health", auth=False),
        rest("GET", "/meetings", auth=False, name="REST without a key"),
        rest("GET", "/meetings?limitt=5", name="REST unknown argument near miss"),
        rest("GET", "/meetings?limit=abc&zzz=1", name="REST unknown argument and bad value"),
        rest("GET", "/meetings?limit=0", name="REST bad limit"),
        rest("GET", "/meeting", name="REST missing required"),
        rest("GET", "/meeting?meeting_db_id=x", name="REST int parsing"),
        rest("DELETE", "/meeting?meeting_db_id=3&asked_by_a_human=maybe", name="REST bool parsing"),
        rest("POST", "/request-meeting-bot", {}, name="REST model validator"),
        rest("POST", "/request-meeting-bot", {"native_meeting_id": 5, "bot_account": "zz", "allowed_languages": "de"},
             name="REST body type errors"),
        rest("POST", "/request-meeting-bot", raw=b"notjson", name="REST body not json"),
        rest("POST", "/request-meeting-bot", name="REST body missing"),
        rest("POST", "/browser-session", {"platform": "x", "display_name": ""}, name="REST literal and length"),
        rest("POST", "/report-issue", {"what_i_tried": " ", "what_happened": "x", "deployment": "c", "severity": 9},
             name="REST report validation"),
        rest("GET", "/transcript-search?q=", name="REST min length"),
        rest("GET", "/nope", name="REST unknown path"),
        rest("PUT", "/meetings", name="REST wrong method"),
        rest("GET", "/meetings", name="REST list meetings", setup=route("gateway", "GET", "/meetings", 200, MEETINGS)),
        rest("GET", "/meetings", headers={"authorization": "Basic abc"}, name="REST raw authorization"),
        rest("GET", "/tools/get_bot_status", name="REST assembled route"),
        rest("POST", "/tools/reaction_signal?reaction_id=a&verb=b", {"extra": 1}, name="REST assembled raw body"),
        rest("POST", "/tools/reaction_signal?reaction_id=a", name="REST assembled missing path param"),
    ]


PROFILES = {}


def profile(name):
    def deco(fn):
        PROFILES[name] = fn
        return fn
    return deco


def _domain_env(ups, roles):
    keys = {"identity": "ADMIN_API_URL", "meetings": "MEETING_API_URL", "agent": "AGENT_API_URL",
            "flows": "FLOWS_API_URL", "crm": "CRM_API_URL"}
    return {keys[r]: ups[r].url for r in roles}


@profile("all")
def p_all(ups):
    env = {"GATEWAY_URL": ups["gateway"].url, **_domain_env(ups, ["identity", "meetings", "agent", "flows", "crm"]),
           "VEXA_FLOWS_API_KEY": FLOWS_KEY, "VEXA_FEATURES": "all",
           "VEXA_TICKET_SINK_URL": ups["sink"].url + "/tickets", "VEXA_TICKET_SINK_TOKEN": "sink-token"}
    return env, protocol_steps() + builtin_steps() + assembled_steps() + rest_steps()


@profile("release")
def p_release(ups):
    env = {"GATEWAY_URL": ups["gateway"].url, **_domain_env(ups, ["identity", "meetings"]),
           "VEXA_MCP_TOOLS_DENY": "list_recordings", "VEXA_MCP_TOOLS_ALLOW": "parse_meeting_link,list_meetings,get_bot_status,stop_bot",
           "VEXA_MCP_TOOLS_COHORT": "u-7,@team.example"}
    cohort = {"x-user-id": "U-7"}
    return env, [
        *opening(),
        rpc("tools/list", name="tools/list ordinary"),
        rpc("tools/list", headers=cohort, name="tools/list cohort by id"),
        rpc("tools/list", headers={"x-user-email": "a@TEAM.example"}, name="tools/list cohort by domain"),
        rpc("tools/list", headers={"x-user-delegation-shared": "1", "x-user-id": "u-7"}, name="tools/list shared caller"),
        call("list_recordings", {}, headers=cohort, name="denied tool for the cohort"),
        call("get_meeting", {"meeting_db_id": 1}, name="hidden tool"),
        call("get_meeting", {"meeting_db_id": 1}, headers=cohort, name="hidden tool for the cohort"),
        call("list_meetings", {}, headers={"x-user-delegation-shared": "1"}, name="shared caller call"),
        call("report_issue", {"what_i_tried": "a", "what_happened": "b", "deployment": "c"}, headers=cohort,
             name="report without a sink"),
        call("browser_session_open", {"platform": "google"}, headers=cohort, name="switched-off feature tool"),
        rest("GET", "/health", auth=False),
    ]


@profile("github-sink")
def p_github(ups):
    env = {"GATEWAY_URL": ups["gateway"].url, "VEXA_MCP_ASSEMBLY_OFF": "1",
           "VEXA_TICKET_SINK_URL": ups["sink"].url + "/repos/o/r/issues", "VEXA_TICKET_SINK_FORMAT": "GitHub",
           "VEXA_TICKET_SINK_LABELS": " a, ,b ", "VEXA_TICKET_FINGERPRINT_SALT": "salt-1"}
    sink = route("sink", "POST", "/repos/o/r/issues", 201, {"id": 99, "number": 12, "html_url": "https://gh/12"})
    return env, [
        *opening(),
        rpc("tools/list"),
        call("report_issue", {"what_i_tried": "a", "what_happened": "b" * 80, "deployment": "self-hosted",
                              "version": "0.12.3", "platform": "zoom", "native_meeting_id": "nope", "logs": "trace"},
             setup=both(sink, route("gateway", "GET", "/meetings", 200, [{"native_meeting_id": "x"}]))),
        call("report_issue", {"what_i_tried": "a", "what_happened": "b", "deployment": "c"}, name="report gateway down",
             setup=route("gateway", "GET", "/meetings", 502, {"detail": "down"})),
    ]


@profile("late")
def p_late(ups):
    # agent is down at boot (its port answers nothing) and joins on the next refresh.
    env = {"GATEWAY_URL": ups["gateway"].url, **_domain_env(ups, ["identity", "meetings", "agent"]),
           "VEXA_MCP_REFRESH_SECONDS": "1"}
    ups["agent"].stop()
    return env, [
        *opening(),
        {**rpc("tools/list"), "name": "tools/list before agent answers"},
        call("workspace_read", {"path": "a"}, name="late tool before it joins"),
        {**rpc("tools/list"), "name": "tools/list after agent answers", "before": lambda: ups["agent"].start(),
         "wait": 3.0},
        call("workspace_read", {"path": "a"}, name="late tool call"),
    ]


#: Environments that must not boot, by both services.
BOOT_REFUSALS = {
    "identity silent": lambda ups: {"GATEWAY_URL": ups["gateway"].url, "ADMIN_API_URL": "http://127.0.0.1:9",
                                    "VEXA_MCP_BOOT_PROBE_ATTEMPTS": "2"},
    "admin tool without its key": lambda ups: {"GATEWAY_URL": ups["gateway"].url,
                                               **_domain_env(ups, ["identity", "flows"])},
    "placeholder admin key": lambda ups: {"GATEWAY_URL": ups["gateway"].url, **_domain_env(ups, ["identity", "flows"]),
                                          "VEXA_FLOWS_API_KEY": "changeme"},
    "mounted manifest without its URL": lambda ups: {"GATEWAY_URL": ups["gateway"].url,
                                                     "VEXA_MCP_MANIFEST_DIR": str(_mount_dir())},
}


def _mount_dir() -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "billing.mcp.tools.v1.json").write_text(json.dumps(
        {"contract": "mcp.tools.v1", "domain": "billing", "source": "mounted", "depends_on": [], "tools": []}))
    return d


# ─── the run ──────────────────────────────────────────────────────────────────

class Session:
    def __init__(self):
        self.sid = None
        self.next_id = 1


def send(svc: Service, sess: Session, step: dict, all_ups: list) -> dict:
    headers = {}
    if not step.get("rest"):
        headers = {"content-type": "application/json", "accept": ACCEPT, "authorization": f"Bearer {KEY}"}
    headers.update(step.get("headers") or {})
    headers = {k: v for k, v in headers.items() if v != ""}
    mode = step.get("session")
    if mode == "sid" and sess.sid:
        headers["mcp-session-id"] = sess.sid
    elif mode == "bogus":
        headers["mcp-session-id"] = "0" * 32
    body = copy.deepcopy(step.get("body"))
    if isinstance(body, dict) and body.get("id") == "auto":
        body["id"] = sess.next_id
        sess.next_id += 1
    for u in all_ups:
        u.log.clear()
    sent_trace = headers.get("x-trace-id")
    ex = exchange(svc.url, step["method"], step["path"], headers, body=body, raw=step.get("raw"),
                  stream_seconds=step.get("stream", 0.0))
    time.sleep(0.05)
    if step.get("capture") and ex["headers"].get("mcp-session-id"):
        sess.sid = ex["headers"]["mcp-session-id"]
    ups_log = sorted((e for u in all_ups for e in u.log), key=lambda e: e["seq"])
    for e in ups_log:
        e.pop("seq", None)
    return record(ex, ups_log, sent_trace)


def diff(a, b, path="$"):
    if type(a) is not type(b):
        return [f"{path}: {json.dumps(a)[:300]} != {json.dumps(b)[:300]}"]
    if isinstance(a, dict):
        out = []
        for k in list(a) + [k for k in b if k not in a]:
            if k not in a or k not in b:
                out.append(f"{path}.{k}: only in {'py' if k in a else 'rs'}: {json.dumps(a.get(k, b.get(k)))[:300]}")
            else:
                out += diff(a[k], b[k], f"{path}.{k}")
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            return [f"{path}: length {len(a)} != {len(b)}: {json.dumps(a)[:400]} != {json.dumps(b)[:400]}"]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, f"{path}[{i}]")
        return out
    if a != b:
        return [f"{path}: {json.dumps(a)[:600]} != {json.dumps(b)[:600]}"]
    return []


def run_profile(name, docs, rust_bin, logdir, only, verbose, results):
    ups = {r: Upstream(r, *docs[r]).start() for r in docs}
    ups["gateway"] = Upstream("gateway").start()
    ups["sink"] = Upstream("sink").start()
    env, steps = PROFILES[name](ups)
    kinds = [k for k in ("py", "rs") if only in (None, k)]
    services = {k: Service(k, env, rust_bin, logdir).start() for k in kinds}
    sessions = {k: Session() for k in kinds}
    failures = 0
    try:
        for step in steps:
            if step.get("before"):
                step["before"]()
            if step.get("wait"):
                time.sleep(step["wait"])
            got = {}
            for k in kinds:
                for u in ups.values():
                    u.routes.clear()
                if step.get("setup"):
                    step["setup"](ups)
                got[k] = send(services[k], sessions[k], step, list(ups.values()))
            results.append({"profile": name, "step": step["name"], **got})
            if len(kinds) == 2:
                d = diff(got["py"], got["rs"])
                if d:
                    failures += 1
                    print(f"DIFF [{name}] {step['name']}")
                    for line in d[:12]:
                        print("   ", line)
                elif verbose:
                    print(f"ok   [{name}] {step['name']}")
        for k, svc in services.items():
            results.append({"profile": name, "step": "rss", k: svc.rss_kib(), f"{k}_boot_s": svc.boot_s})
    finally:
        for svc in services.values():
            svc.stop()
        for u in ups.values():
            u.stop()
    return failures, len(steps)


def run_refusals(docs, rust_bin, logdir, only):
    failures = 0
    for name, make in BOOT_REFUSALS.items():
        ups = {r: Upstream(r, *docs[r]).start() for r in docs}
        ups["gateway"] = Upstream("gateway").start()
        env = make(ups)
        codes = {}
        for k in ("py", "rs"):
            if only not in (None, k):
                continue
            svc = Service(k, env, rust_bin, logdir).start(wait=False)
            codes[k] = svc.exit_code(timeout=60)
            if codes[k] is None:
                svc.stop()
        for u in ups.values():
            u.stop()
        refused = {k: (c is not None and c != 0) for k, c in codes.items()}
        if not all(refused.values()):
            failures += 1
            print(f"DIFF [boot] {name}: exit codes {codes}")
        else:
            print(f"ok   [boot] {name}: refused by {sorted(refused)}")
    return failures, len(BOOT_REFUSALS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["py", "rs"])
    ap.add_argument("--profile", action="append")
    ap.add_argument("--rust-bin", default=str(ROOT / "apps" / "vexa-mcp" / "target" / "release" / "vexa-mcp"))
    ap.add_argument("--dump", help="write every recorded answer to this JSON file")
    ap.add_argument("--no-boot", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="mcp-parity-"))
    docs = domain_documents(tmp)
    results, failures, steps = [], 0, 0
    for name in args.profile or list(PROFILES):
        f, n = run_profile(name, docs, pathlib.Path(args.rust_bin), tmp, args.only, args.verbose, results)
        failures, steps = failures + f, steps + n
    if not args.no_boot and not args.profile:
        f, n = run_refusals(docs, pathlib.Path(args.rust_bin), tmp, args.only)
        failures, steps = failures + f, steps + n
    for r in results:
        if r["step"] == "rss":
            print("RSS", r["profile"], {k: v for k, v in r.items() if k not in ("profile", "step")})
    if args.dump:
        pathlib.Path(args.dump).write_text(json.dumps(results, indent=1, ensure_ascii=False))
    print(f"logs: {tmp}")
    if failures:
        print(f"PARITY FAILED: {failures} of {steps} steps differ")
        sys.exit(1)
    print(f"PARITY OK: {steps} steps" + (f" (only {args.only})" if args.only else ""))


if __name__ == "__main__":
    main()
