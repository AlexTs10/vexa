"""pytest_rust.py — run the Python mcp's own test suite against the Rust binary.

    cargo build --release --manifest-path apps/vexa-mcp/Cargo.toml
    cd core/gateway/services/mcp
    PYTHONPATH=../../../../apps/vexa-mcp .venv/bin/python -m pytest -p pytest_rust -p no:cacheprovider tests

The suite builds its service with `create_app(gateway_url, transport=..., assembly_env=..., ...)` and
drives it in process. This plugin replaces `create_app` with one that starts the Rust binary instead:

* every upstream URL the app would reach (the gateway, each domain, the ticket sink) is rewritten
  to a local relay, `http://127.0.0.1:<port>/__h/<scheme>/<host>/<path>`, and the relay hands each
  request to the test's own `httpx` transport with its original URL — the fake gateway records it
  exactly as it records the Python service's hops;
* the returned object is an ASGI app that forwards every request to the binary over HTTP, so
  `TestClient(app)` and the suite's `client` fixture work unchanged;
* a boot the binary refuses is raised as `ManifestError` with the binary's own message.

What cannot carry over fails, and is counted as such: tests that read `app.state`, the
`FastApiMCP` object or the log sink (`obs.capture`), and tests that call Python modules directly
(they still pass, but they test the Python code, not the binary).
"""
from __future__ import annotations

import asyncio
import atexit
import http.server
import os
import pathlib
import socket
import subprocess
import threading
import time
import urllib.parse

import httpx

HERE = pathlib.Path(__file__).resolve().parent
BINARY = pathlib.Path(os.environ.get("VEXA_MCP_RUST_BIN") or HERE / "target" / "release" / "vexa-mcp")
URL_KEYS = ("GATEWAY_URL", "ADMIN_API_URL", "MEETING_API_URL", "FLOWS_API_URL", "AGENT_API_URL", "CRM_API_URL",
            "VEXA_TICKET_SINK_URL")
ASSEMBLY_KEYS = ("ADMIN_API_URL", "MEETING_API_URL", "FLOWS_API_URL", "AGENT_API_URL", "CRM_API_URL",
                 "VEXA_FLOWS_API_KEY", "VEXA_MCP_MANIFEST_DIR", "VEXA_MCP_ASSEMBLY_OFF", "VEXA_MCP_BOOT_PROBE_ATTEMPTS",
                 "VEXA_MCP_BOOT_PROBE_PAUSE_SECONDS", "VEXA_MCP_REFRESH_SECONDS")
VISIBILITY_KEYS = ("VEXA_MCP_TOOLS_ALLOW", "VEXA_MCP_TOOLS_DENY", "VEXA_MCP_TOOLS_COHORT")
_RUNNING: list = []


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _answer(transport, request: httpx.Request) -> httpx.Response:
    handler = getattr(transport, "handler", None)
    if transport is None:
        return httpx.Response(502, text="no transport for this hop")
    if handler is not None and asyncio.iscoroutinefunction(handler):
        async def run():
            r = await transport.handle_async_request(request)
            await r.aread()
            return r
        return asyncio.run(run())
    if hasattr(transport, "handle_request"):
        r = transport.handle_request(request)
        r.read()
        return r

    async def run_async():
        r = await transport.handle_async_request(request)
        await r.aread()
        return r
    return asyncio.run(run_async())


class Relay:
    """127.0.0.1 -> the test's transports, each request with its original URL."""

    def __init__(self, transport, assembly_transport):
        self.transport, self.assembly_transport = transport, assembly_transport
        self.port = _free_port()
        relay = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _any(self):
                relay.serve(self)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _any

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def url(self, original: str) -> str:
        u = urllib.parse.urlsplit(original.strip())
        if not u.scheme or not u.netloc:
            return original
        return f"http://127.0.0.1:{self.port}/__h/{u.scheme}/{u.netloc}{u.path.rstrip('/')}"

    def serve(self, h):
        length = int(h.headers.get("content-length") or 0)
        body = h.rfile.read(length) if length else b""
        path, _, query = h.path.partition("?")
        _, _, scheme, netloc, *rest = path.split("/", 4) + [""]
        original = f"{scheme}://{netloc}/{rest[0] if rest else ''}" + (f"?{query}" if query else "")
        headers = [(k, v) for k, v in h.headers.items() if k.lower() not in ("host", "connection", "content-length")]
        request = httpx.Request(h.command, original, headers=headers, content=body)
        is_discovery = request.url.path in ("/.well-known/mcp-tools.json", "/openapi.json")
        transport = self.assembly_transport if is_discovery and self.assembly_transport is not None else self.transport
        try:
            r = _answer(transport, request)
            status, out, rh = r.status_code, r.content, list(r.headers.items())
        except httpx.TimeoutException:
            time.sleep(40)
            status, out, rh = 504, b"", []
        except httpx.HTTPError:
            h.connection.close()
            return
        h.send_response(status)
        for k, v in rh:
            if k.lower() not in ("content-length", "transfer-encoding", "connection", "content-encoding"):
                h.send_header(k, v)
        h.send_header("content-length", str(len(out)))
        h.end_headers()
        h.wfile.write(out)

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


#: Read per call by the Python service, once at boot by the binary. A test that sets one after the
#: app is built (monkeypatch.setenv) gets the binary booted again with the new value.
PER_CALL_KEYS = ("VEXA_TICKET_SINK_URL", "VEXA_TICKET_SINK_TOKEN", "VEXA_TICKET_SINK_FORMAT",
                 "VEXA_TICKET_SINK_LABELS", "VEXA_TICKET_FINGERPRINT_SALT", "VEXA_JITSI_HOSTS")


def _per_call() -> dict:
    return {k: os.environ.get(k) for k in PER_CALL_KEYS}


class RustApp:
    """An ASGI app that is the binary, reached over HTTP."""

    def __init__(self, env: dict, relay: Relay):
        self.relay, self.env = relay, env
        self.boot()

    def boot(self):
        env, relay = dict(self.env), self.relay
        self.seen = _per_call()
        for k, v in self.seen.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = relay.url(v) if k == "VEXA_TICKET_SINK_URL" else v
        self.port = _free_port()
        env = {**env, "PORT": str(self.port), "HOST": "127.0.0.1"}
        self.proc = subprocess.Popen([str(BINARY)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if self not in _RUNNING:
            _RUNNING.append(self)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                err = self.proc.stderr.read().decode("utf-8", "replace")
                self.relay.stop()
                from vexa_mcp.manifest import ManifestError
                raise ManifestError(err.split("refusing to boot: ", 1)[-1].strip())
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.02)
        self.client = httpx.Client(base_url=f"http://127.0.0.1:{self.port}", timeout=60)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                m = await receive()
                if m["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif m["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if _per_call() != self.seen:
            self.kill()
            self.boot()
        body = b""
        while True:
            m = await receive()
            body += m.get("body", b"")
            if not m.get("more_body"):
                break
        headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope["headers"]
                   if k.lower() not in (b"host", b"content-length", b"connection")]
        target = scope["path"] + (("?" + scope["query_string"].decode("latin-1")) if scope.get("query_string") else "")

        def go():
            return self.client.request(scope["method"], target, headers=headers, content=body)

        r = await asyncio.get_running_loop().run_in_executor(None, go)
        await send({"type": "http.response.start", "status": r.status_code,
                    "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in r.headers.items()
                                if k.lower() not in ("content-length", "transfer-encoding", "connection")]
                    + [(b"content-length", str(len(r.content)).encode())]})
        await send({"type": "http.response.body", "body": r.content})

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.client.close()

    def stop(self):
        self.kill()
        self.relay.stop()

    def __del__(self):
        try:
            self.stop()
        except Exception:  # noqa: BLE001
            pass


def rust_create_app(gateway_url=None, *, transport=None, assembly_env=None, assembly_transport=None,
                    features_env=None, visibility_env=None):
    env = dict(os.environ)
    if assembly_env is not None:
        for k in ASSEMBLY_KEYS:
            env.pop(k, None)
        env.update({k: str(v) for k, v in assembly_env.items()})
    if features_env is not None:
        env["VEXA_FEATURES"] = str(features_env.get("VEXA_FEATURES") or "")
    if visibility_env is not None:
        for k in VISIBILITY_KEYS:
            env[k] = str(visibility_env.get(k) or "")
    env["GATEWAY_URL"] = gateway_url or env.get("GATEWAY_URL") or "http://gateway:8000"
    relay = Relay(transport, assembly_transport)
    for k in URL_KEYS:
        if env.get(k) and k not in PER_CALL_KEYS:
            env[k] = relay.url(env[k])
    return RustApp(env, relay)


# At import (-p loads this before the suite's conftest), so every `from vexa_mcp import create_app`
# binds the binary.
import vexa_mcp  # noqa: E402
import vexa_mcp.app  # noqa: E402

vexa_mcp.create_app = rust_create_app
vexa_mcp.app.create_app = rust_create_app


@atexit.register
def _stop_all():
    for app in _RUNNING:
        try:
            app.stop()
        except Exception:  # noqa: BLE001
            pass
