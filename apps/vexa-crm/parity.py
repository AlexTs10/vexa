#!/usr/bin/env python3
"""parity.py — the same requests against the Python crm-api and the Rust vexa-crm, side by side.

Each profile copies a freshly initialised CRM database (one template, made with
python -m crm.migrate init), boots one service at a time on it with the same environment and the same
fake upstreams (identity, flows-api, agent-api), sends every step, and records the status, the headers
that carry meaning, the body, and per step the row counts of every crm_* table. At the end of a run it
waits for the outbox, then records every row of every crm_* table, every request flows received and
the crm log lines. Then the other service runs the same steps on a fresh copy, and the two records are
compared. Random values (uuid4 ids, times, nonces, the seal's time and signature) become placeholders
before the compare; uuid5 ids (idempotent creates, the sign-in Person) are compared as they are.

    cargo build --release --manifest-path apps/vexa-crm/Cargo.toml
    cd core/crm && .venv/bin/python ../../apps/vexa-crm/parity.py [--profile NAME] [--only TEXT] [-v]

PARITY_PG_ADMIN is a PostgreSQL superuser URL (default
postgresql://postgres:adminpw@127.0.0.1:55432/postgres): a native server, never a container.
"""
from __future__ import annotations

import argparse
import http.client
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
from urllib.parse import urlsplit

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CRM_DIR = ROOT / "core" / "crm"
LAUNCH = ROOT / "apps" / "vexa-daemon" / "python" / "native_launch.py"
SECRET = "parity-internal-secret-5d1e"
FLOWS_KEY = "parity-flows-publisher-key-91c4"
RUNTIME_PW = "crmpassword0123456789abcdef"
ORG = "one"
BASE_DB, RUN_DB = "crm_parity_base", "crm_parity"
UUID4 = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b")
ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\+00:00|Z)?")
RANDOM_KEYS = {"nonce", "sig", "exp", "iat", "content_hash", "used_at", "expires_at"}
#: a published profile's handle is secrets.token_urlsafe(16)
RANDOM_HANDLE = re.compile(r"^[A-Za-z0-9_-]{22}$")
ADMIN_URL = os.environ.get("PARITY_PG_ADMIN", "postgresql://postgres:adminpw@127.0.0.1:55432/postgres")


def deleg(**kw):
    d = {"session_id": "s-1", "unit": "unit-1", "regime": "human", "grants": []}
    d.update(kw)
    return d


USERS = {
    "t-admin": {"user_id": 1, "email": "admin@example.org", "email_verified": True, "is_admin": True,
                "workspaces": ["w1"], "writable_workspaces": ["w1"], "credential_class": "session"},
    "t-member": {"user_id": 8, "email": "member@example.org", "email_verified": True,
                 "workspaces": ["w1"], "writable_workspaces": [], "credential_class": "session"},
    "t-key": {"user_id": 8, "email": "member@example.org", "email_verified": True, "workspaces": ["w1"],
              "credential_class": "key"},
    "t-other": {"user_id": 9, "email": "other@example.org", "email_verified": False, "credential_class": "session"},
    "vxd_agent": {"user_id": 1, "email": "admin@example.org", "email_verified": True, "person_is_admin": True,
                  "workspaces": ["w1"], "delegation": deleg()},
    "vxd_unwatched": {"user_id": 1, "email": "admin@example.org", "person_is_admin": True,
                      "delegation": deleg(regime="scheduled")},
    "vxd_shared": {"user_id": 1, "email": "admin@example.org", "person_is_admin": True, "workspaces": ["w1"],
                   "delegation": deleg(shared=True)},
    "vxd_cross": {"user_id": 1, "email": "admin@example.org", "workspaces": ["w1"],
                  "delegation": deleg(shared=True, audience="cross_org")},
    "vxd_room": {"user_id": "ws:w1", "workspaces": ["w1"],
                 "delegation": deleg(principal_kind="workspace", principal_workspace="w1", shared=True)},
}


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Upstream:
    def __init__(self, role):
        self.role, self.port, self.log, self.server = role, _free_port(), [], None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        up = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _any(self):
                n = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(n) if n else b""
                path, _, query = self.path.partition("?")
                kept = {k: self.headers.get(k) for k in ("x-internal-secret", "x-flows-publisher-key", "content-type",
                                                          "x-vexa-internal-accepts-delegation", "x-user-id")
                        if self.headers.get(k) is not None}
                up.log.append({"role": up.role, "method": self.command, "path": path, "query": query,
                               "headers": kept, "body": raw.decode("utf-8", "replace")})
                status, body = up.answer(self.command, path, raw)
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _any

        http.server.ThreadingHTTPServer.allow_reuse_address = True
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def answer(self, method, path, raw):
        if self.role == "identity":
            if path == "/internal/validate":
                tok = json.loads(raw or b"{}").get("token")
                return (200, USERS[tok]) if tok in USERS else (401, {"detail": "bad"})
            m = re.fullmatch(r"/internal/users/([^/]+)/org", path)
            if m:
                return 200, {"org": {"id": f"p-{m[1]}", "kind": "personal"}}
            return 404, {"detail": "Not Found"}
        if self.role == "flows":
            return 202, {"accepted": True}
        return 404, {"detail": "no file"}


# ── the database ──────────────────────────────────────────────────────────────

def _pg():
    import pg8000.native
    u = urlsplit(ADMIN_URL)
    return pg8000.native, dict(user=u.username, password=u.password, host=u.hostname, port=u.port or 5432)


def _admin(sql, db="postgres"):
    native, kw = _pg()
    con = native.Connection(database=db, **kw)
    try:
        return con.run(sql)
    finally:
        con.close()


def prepare_base(keydir):
    _admin(f"DROP DATABASE IF EXISTS {RUN_DB} WITH (FORCE)")
    _admin(f"DROP DATABASE IF EXISTS {BASE_DB} WITH (FORCE)")
    _admin(f"CREATE DATABASE {BASE_DB}")
    u = urlsplit(ADMIN_URL)
    env = dict(os.environ, DB_HOST=u.hostname, DB_PORT=str(u.port or 5432), DB_NAME=BASE_DB, DB_USER=u.username,
               DB_PASSWORD=u.password, CRM_DB_USER="vexa_crm", CRM_DB_PASSWORD=RUNTIME_PW, CRM_ORG_ID=ORG,
               CRM_ORG_NAME="One", PYTHONPATH=str(CRM_DIR / "src"))
    subprocess.run([sys.executable, "-m", "crm.migrate", "init"], cwd=CRM_DIR, env=env, check=True,
                   stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable, "-m", "crm.fact_keys", "keygen", str(keydir / "crm.pem"), str(keydir / "crm.pub.pem")],
                   cwd=CRM_DIR, env=env, check=True, stdout=subprocess.DEVNULL)


def fresh_db():
    _admin(f"DROP DATABASE IF EXISTS {RUN_DB} WITH (FORCE)")
    _admin(f"CREATE DATABASE {RUN_DB} TEMPLATE {BASE_DB}")


def _con():
    native, kw = _pg()
    return native.Connection(database=RUN_DB, **kw)


def tables(con):
    return [r[0] for r in con.run("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' "
                                  "AND table_name LIKE 'crm_%' ORDER BY table_name")]


def counts():
    con = _con()
    try:
        return {t: con.run(f'SELECT count(*) FROM "{t}"')[0][0] for t in tables(con)}
    finally:
        con.close()


def dump():
    con = _con()
    try:
        return {t: [json.loads(r[0]) for r in con.run(f'SELECT row_to_json(x)::text FROM "{t}" x')] for t in tables(con)}
    finally:
        con.close()


def pending_outbox():
    return _admin("SELECT count(*) FROM crm_outbox WHERE delivered = false", RUN_DB)[0][0]


# ── the services ──────────────────────────────────────────────────────────────

def service_env(port, ups, keydir, features):
    u = urlsplit(ADMIN_URL)
    return {
        "PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""),
        "VEXA_CRM_PORT": str(port),
        "CRM_DATABASE_URL": f"postgresql+pg8000://vexa_crm:{RUNTIME_PW}@{u.hostname}:{u.port or 5432}/{RUN_DB}",
        "ADMIN_API_URL": ups["identity"].url, "INTERNAL_API_SECRET": SECRET,
        "CRM_AGENT_API_URL": ups["agent"].url, "CRM_ORG_ID": ORG,
        "VEXA_CRM_OUTBOX_ENABLED": "true", "FLOWS_API_URL": ups["flows"].url, "FLOWS_PUBLISH_KEY": FLOWS_KEY,
        "VEXA_FACT_SEAL_KEY_FILE": str(keydir / "crm.pem"), "VEXA_FEATURES": features,
        "PYTHONPATH": str(CRM_DIR / "src"),
    }


def start(kind, env, binary):
    cmd = [binary] if kind == "rust" else [sys.executable, str(LAUNCH), "crm"]
    log = tempfile.TemporaryFile()
    proc = subprocess.Popen(cmd, env=env, cwd=CRM_DIR, stdout=log, stderr=subprocess.STDOUT)
    port = int(env["VEXA_CRM_PORT"])
    for _ in range(300):
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            c.request("GET", "/health")
            c.getresponse().read()
            return proc, log
        except OSError:
            if proc.poll() is not None:
                log.seek(0)
                raise SystemExit(f"{kind} exited: {log.read().decode()[-3000:]}")
            time.sleep(0.1)
    raise SystemExit(f"{kind} did not start")


def rss_kb(pid):
    try:
        return int(subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip())
    except ValueError:
        return 0


# ── steps ─────────────────────────────────────────────────────────────────────

def S(name, path, body=None, token=None, method="POST", headers=None, save=None, raw=None):
    return {"name": name, "path": path, "body": body, "token": token, "method": method,
            "headers": headers or {}, "save": save or {}, "raw": raw}


R = {"reason": "parity"}
LAYOUT = {"title_field": "Name", "sections": [{"title": "Overview", "fields": [{"field": "Domain", "label": "Web"}]}]}
IN = {"x-internal-secret": SECRET}
CLEAN = {"x-vexa-taint": "none"}

CORE = [
    S("health", "/health", method="GET"),
    S("manifest", "/.well-known/mcp-tools.json", method="GET"),
    S("openapi", "/openapi.json", method="GET"),
    S("not found", "/nope", {}),
    S("method", "/describe", method="GET"),
    S("no credential", "/describe", {}),
    S("bad credential", "/describe", {}, token="t-nobody"),
    S("binding mismatch", "/describe", {}, token="t-admin", headers={"x-crm-org": "two"}),
    S("binding ok", "/describe", {"object_type": "Company"}, token="t-admin", headers={"x-crm-org": ORG}),
    S("describe all", "/describe", {}, token="t-admin"),
    S("describe member", "/describe", {}, token="t-member"),
    S("422 empty change", "/change", {}, token="t-admin"),
    S("422 bad action", "/change", {"action": "drop", "reason": "x"}, token="t-admin"),
    S("422 extra", "/search", {"object_type": "Company", "x": 1}, token="t-admin"),
    S("422 type", "/search", {"object_type": 1, "limit": "a"}, token="t-admin"),
    S("422 range", "/search", {"object_type": "Company", "limit": 0, "offset": -1}, token="t-admin"),
    S("422 json", "/search", token="t-admin", raw=b'{"object_type": '),
    S("422 not object", "/search", ["x"], token="t-admin"),
    S("422 resolve", "/resolve", {"name": ""}, token="t-admin"),
    S("create company", "/change", {"action": "create", "object_type": "Company", "idempotency_key": "k1",
                                    "fields": {"Name": "Acme", "Domain": "acme.com"}, "match": ["domain:Acme.com"], **R},
      token="t-admin", save={"acme": "record_id"}),
    S("replay", "/change", {"action": "create", "object_type": "Company", "idempotency_key": "k1",
                            "fields": {"Name": "Acme", "Domain": "acme.com"}, **R}, token="t-admin"),
    S("replay differs", "/change", {"action": "create", "object_type": "Company", "idempotency_key": "k1",
                                    "fields": {"Name": "Other"}, **R}, token="t-admin"),
    S("match clash", "/change", {"action": "create", "object_type": "Company", "idempotency_key": "m1", "fields": {"Name": "Dup"},
                                 "match": ["domain:acme.com"], **R}, token="t-admin"),
    S("bad match", "/change", {"action": "create", "object_type": "Company", "idempotency_key": "m2", "fields": {"Name": "Dup"},
                               "match": ["phone:1"], **R}, token="t-admin"),
    S("no key", "/change", {"action": "create", "object_type": "Deal", "fields": {"Name": "D"}, **R}, token="t-admin"),
    S("invalid fields", "/change", {"action": "create", "object_type": "Deal", "idempotency_key": "m3", "fields": {"Name": "D", "Currency": "usd"}, **R},
      token="t-admin"),
    S("unknown type", "/change", {"action": "create", "object_type": "Nope", "idempotency_key": "m4", "fields": {}, **R}, token="t-admin"),
    S("create person", "/change", {"action": "create", "object_type": "Person", "idempotency_key": "p1",
                                   "fields": {"Name": "Ada Lovelace", "Company": "{acme}", "LastContact": "2026-01-02"},
                                   "narrative": "Works at [Acme](/crm?record={acme}). \x60[x](/crm?record={acme})\x60", **R},
      token="t-admin", save={"ada": "record_id"}),
    S("read company", "/read", {"record_id": "{acme}"}, token="t-admin"),
    S("read person", "/read", {"record_id": "{ada}"}, token="t-admin"),
    S("read missing", "/read", {"record_id": "00000000-0000-4000-8000-000000000000"}, token="t-admin"),
    S("search", "/search", {"object_type": "Company", "filters": {"Name": "Acme"}}, token="t-admin"),
    S("search page", "/search", {"object_type": "Person", "limit": 1}, token="t-admin"),
    S("search filter forbidden", "/search", {"object_type": "Company", "filters": {"Nope": 1}}, token="t-admin"),
    S("search filter invalid", "/search", {"object_type": "Deal", "filters": {"Amount": "x"}}, token="t-admin"),
    S("search bad type", "/search", {"object_type": "Nope"}, token="t-admin"),
    S("resolve", "/resolve", {"name": "acm"}, token="t-admin"),
    S("resolve exact", "/resolve", {"name": "ada lovelace"}, token="t-admin"),
    S("update", "/change", {"action": "update", "record_id": "{acme}", "expected_revision": 1,
                            "fields": {"Stage": "Customer"}, **R}, token="t-admin"),
    S("update stale", "/change", {"action": "update", "record_id": "{acme}", "expected_revision": 1,
                                  "fields": {"Stage": "Lost"}, **R}, token="t-admin"),
    S("update narrative", "/change", {"action": "update", "record_id": "{acme}", "expected_revision": 2,
                                      "narrative": "Customer since 2026.", **R}, token="t-admin"),
    S("history", "/history", {"record_id": "{acme}"}, token="t-admin"),
    S("member reads admin record", "/read", {"record_id": "{acme}"}, token="t-member"),
    S("member creates", "/change", {"action": "create", "object_type": "Deal", "idempotency_key": "d1",
                                    "fields": {"Name": "Big deal", "Amount": 10.5, "Company": "{acme}"}, **R},
      token="t-member", save={"deal": "record_id"}),
    S("member reads own", "/read", {"record_id": "{deal}"}, token="t-member"),
    S("member search", "/search", {"object_type": "Deal"}, token="t-member"),
    S("member configure", "/configure", {"object_type": "Company"}, token="t-member"),
    S("agent proposes", "/change", {"action": "update", "record_id": "{acme}", "expected_revision": 3,
                                    "fields": {"Stage": "Partner"}, **R}, token="vxd_agent", headers=CLEAN,
      save={"prop": "proposal_id"}),
    S("agent held", "/change", {"action": "update", "record_id": "{acme}", "expected_revision": 3,
                                "fields": {"Stage": "Partner"}, **R}, token="vxd_agent"),
    S("agent held sources", "/change", {"action": "update", "record_id": "{acme}", "expected_revision": 3,
                                        "fields": {"Stage": "Partner"}, **R}, token="vxd_agent",
      headers={"x-vexa-taint": "gmail,calendar"}),
    S("agent reads", "/read", {"record_id": "{acme}"}, token="vxd_agent"),
    S("agent review refused", "/review", {"proposal_id": "{prop}", "accept": True}, token="vxd_agent"),
    S("review accept", "/review", {"proposal_id": "{prop}", "accept": True}, token="t-admin"),
    S("review again", "/review", {"proposal_id": "{prop}", "accept": True}, token="t-admin"),
    S("unwatched create", "/change", {"action": "create", "object_type": "Company", "idempotency_key": "u1", "fields": {"Name": "U"}, **R},
      token="vxd_unwatched", headers=CLEAN),
    S("shared read unbound", "/read", {"record_id": "{acme}"}, token="vxd_shared"),
    S("configure read", "/configure", {"object_type": "Company"}, token="t-admin"),
    S("configure set", "/configure", {"object_type": "Company", "layout": LAYOUT, "expected_version": 0, "reason": "parity"},
      token="t-admin"),
    S("configure stale", "/configure", {"object_type": "Company", "layout": LAYOUT, "expected_version": 0, "reason": "parity"},
      token="t-admin"),
    S("configure bad layout", "/configure", {"object_type": "Company", "expected_version": 1, "reason": "x",
                                             "layout": {"sections": [{"fields": [{"field": "", "format": "nope"}]}], "x": 1}},
      token="t-admin"),
    S("configure unknown field", "/configure", {"object_type": "Company", "expected_version": 1, "reason": "x",
                                                "layout": {"sections": [{"fields": [{"field": "Nope"}]}]}}, token="t-admin"),
    S("read with card", "/read", {"record_id": "{acme}"}, token="t-admin"),
    S("bind", "/bind", {"workspace": "w1", "record_id": "{acme}"}, token="t-admin"),
    S("bind bad slug", "/bind", {"workspace": "../x", "record_id": "{acme}"}, token="t-admin"),
    S("bind member", "/bind", {"workspace": "w1", "record_id": "{acme}"}, token="t-member"),
    S("shared read bound", "/read", {"record_id": "{acme}"}, token="vxd_shared"),
    S("cross-org read", "/read", {"record_id": "{acme}"}, token="vxd_cross"),
    S("cross-org search", "/search", {"object_type": "Company"}, token="vxd_cross"),
    S("room read", "/read", {"record_id": "{acme}"}, token="vxd_room"),
    S("member reads bound", "/read", {"record_id": "{acme}"}, token="t-member"),
    S("snapshot no secret", "/internal/references", {"workspace": "w1", "commit": "c1",
                                                     "committed_at": "2026-11-20T00:00:00+00:00"}),
    S("snapshot", "/internal/references", {"workspace": "w1", "commit": "c1", "committed_at": "2026-11-20T00:00:00+00:00",
                                          "references": [{"page": "notes.md", "record": "{acme}"}],
                                          "members": [{"subject": "8", "role": "viewer"}, {"subject": "1", "role": "Owner"}]},
      headers=IN),
    S("snapshot stale", "/internal/references", {"workspace": "w1", "commit": "c0",
                                                 "committed_at": "2026-01-01T00:00:00+00:00"}, headers=IN),
    S("read mentioned", "/read", {"record_id": "{acme}"}, token="t-admin"),
    S("create second", "/change", {"action": "create", "object_type": "Company", "idempotency_key": "k2",
                                   "fields": {"Name": "Acme Inc"}, **R}, token="t-admin", save={"acme2": "record_id"}),
    S("merge no reason", "/change", {"action": "merge", "record_id": "{acme2}", "into": "{acme}", "reason": " "},
      token="t-admin"),
    S("merge", "/change", {"action": "merge", "record_id": "{acme2}", "into": "{acme}", **R}, token="t-admin"),
    S("read merged", "/read", {"record_id": "{acme2}"}, token="t-admin"),
    S("person me", "/person/me", {}, token="t-member"),
    S("person me admin", "/person/me", {}, token="t-admin"),
    S("internal accounts", "/internal/accounts", {"subject": "12", "email": "x@example.org", "email_verified": True},
      headers=IN),
    S("internal persons", "/internal/persons", {"accounts": [{"subject": "1"}, {"subject": "8"}]}, headers=IN),
    S("desk read", "/desk/read", {}, token="t-admin"),
    S("desk arrange", "/desk/arrange", {"ops": [{"op": "hide", "section": "files"}], "base_version": 0}, token="t-admin"),
    S("desk arrange stale", "/desk/arrange", {"ops": [{"op": "show", "section": "files"}], "base_version": 0},
      token="t-admin"),
    S("desk bad op", "/desk/arrange", {"ops": [{"op": "fly"}], "base_version": 1}, token="t-admin"),
    S("desk propose", "/desk/arrange/propose", {"ops": [{"op": "show", "section": "files"}], "reason": "tidy"},
      token="vxd_agent", save={"dprop": "proposal_id"}),
    S("desk read again", "/desk/read", {}, token="t-admin"),
    S("desk undo", "/desk/undo", {"version": 0, "base_version": 1}, token="t-admin"),
    S("settings read", "/desk/workspaces/read", {}, token="t-admin"),
    S("settings set", "/desk/workspaces/set", {"workspace": "w1", "settings": {"pinned": True, "level": 3}},
      token="t-admin"),
    S("settings strict", "/desk/workspaces/set", {"workspace": "w1", "settings": {"pinned": 1, "level": "3"}},
      token="t-admin"),
    S("settings notify", "/desk/workspaces/set", {"workspace": "w1", "settings": {"notify": "all"}}, token="t-admin"),
    S("card create", "/card/create", {"title": "Ship it", "workspace": "w1", "fields": {"Next": "write"}},
      token="t-admin", save={"card": "card.id"}),
    S("card list", "/card/list", {}, token="t-admin"),
    S("card list board", "/card/list", {"workspace": "w1"}, token="t-admin"),
    S("card read", "/card/read", {"card": "{card}"}, token="t-admin"),
    S("card inbox", "/card/inbox", {}, token="t-admin"),
    S("card propose", "/card/propose", {"title": "Ask Ada", "reason": "follow up",
                                        "fields": {"Kind": "question", "NextActor": "8"}}, token="vxd_agent", headers=CLEAN,
      save={"q": "card.id"}),
    S("card propose plain", "/card/propose", {"title": "Tidy", "reason": "later", "workspace": "w1"}, token="vxd_agent",
      headers=CLEAN, save={"pc": "proposal_id"}),
    S("member inbox", "/card/inbox", {}, token="t-member"),
    S("member nonce q", "/card/nonce", {"card": "{q}"}, token="t-member", save={"qn": "nonce", "qh": "content_hash"}),
    S("member answers", "/card/decide", {"card": "{q}", "action": "answer", "nonce": "{qn}", "content_hash": "{qh}",
                                         "answer": "Tuesday"}, token="t-member"),
    S("nonce reuse", "/card/decide", {"card": "{q}", "action": "answer", "nonce": "{qn}", "content_hash": "{qh}",
                                      "answer": "Again"}, token="t-member"),
    S("admin nonce q", "/card/nonce", {"card": "{q}"}, token="t-admin", save={"an": "nonce", "ah": "content_hash"}),
    S("admin uses", "/card/decide", {"card": "{q}", "action": "use", "nonce": "{an}", "content_hash": "{ah}"},
      token="t-admin"),
    S("card read q", "/card/read", {"card": "{q}"}, token="t-admin"),
    S("card update propose", "/card/update/propose", {"card": "{q}", "expected_revision": 1, "fields": {"Summary": "x"},
                                                      "reason": "note"}, token="vxd_agent", headers=CLEAN),
    S("meeting offer", "/internal/cards/offer", {"principal": "ws:w1", "workspace": "w1", "on_behalf_of": "1",
                                                 "session": "s-9", "origin": "session:s-9", "reason": "from the call",
                                                 "cards": [{"title": "Send deck", "kind": "commitment", "next_actor": "8",
                                                            "due": "2026-12-01"}]}, headers=IN),
    S("meeting offer bad", "/internal/cards/offer", {"principal": "ws:w1", "on_behalf_of": "1", "session": "s",
                                                     "origin": "o", "reason": "r", "cards": []}, headers=IN),
    S("desk proposal apply", "/desk/proposal", {"proposal_id": "{dprop}", "apply": True, "base_version": 2},
      token="t-admin"),
    S("desk read after", "/desk/read", {}, token="t-admin"),
    S("profile read", "/person/profile", {"action": "read"}, token="t-member"),
    S("profile edit", "/person/profile", {"action": "edit", "fields": {"headline": "Builder", "links": ["https://x.example"]}},
      token="t-member"),
    S("profile publish", "/person/profile", {"action": "publish", "public": True, "public_fields": ["headline"]},
      token="t-member"),
    S("profile import", "/person/profile", {"action": "import", "source": "linkedin"}, token="t-member"),
    S("profile by key", "/person/profile", {"action": "read"}, token="t-key"),
    S("merge offer", "/person/merge", {"action": "offer", "address": "member@work.example"}, token="t-member"),
    S("merge offer bad", "/person/merge", {"action": "confirm", "card": "nope"}, token="t-member"),
    S("profiles directory", "/internal/profiles", {"accounts": [{"subject": "8"}, {"subject": "1"}]}, headers=IN),
    S("profiles public", "/internal/profiles/public", {"handle": "nobody-handle-0000"}, headers=IN),
    S("card members", "/card/members", {"card": "{card}", "subject": "8"}, token="t-admin"),
    S("card membership", "/card/membership", {"card": "{card}", "accept": True}, token="t-member"),
    S("card read member", "/card/read", {"card": "{card}"}, token="t-member"),
    S("card seen key", "/card/seen", {"card": "{card}"}, token="t-key"),
    S("card nonce", "/card/nonce", {"card": "{card}"}, token="t-admin"),
    S("card update", "/card/update", {"card": "{card}", "expected_revision": 1, "fields": {"Summary": "s"}},
      token="t-admin"),
    S("card decide bad", "/card/decide", {"card": "{card}", "action": "fly", "nonce": "x", "content_hash": "y"},
      token="t-admin"),
    S("blocks company", "/blocks/read", {"view": "company", "args": {"company": "{acme}"}}, token="t-admin"),
    S("blocks people", "/blocks/read", {"view": "people", "args": {}}, token="t-admin"),
    S("erase install org", "/internal/orgs/one/erase", {}, headers=IN),
    S("history after", "/history", {"record_id": "{acme}"}, token="t-admin"),
]

PROFILES = {
    "core": ("all", CORE),
    "off": ("", [
        S("health", "/health", method="GET"),
        S("manifest", "/.well-known/mcp-tools.json", method="GET"),
        S("describe refused", "/describe", {}, token="t-admin"),
        S("desk refused", "/desk/read", {}, token="t-admin"),
        S("card refused", "/card/list", {}, token="t-admin"),
        S("binding first", "/describe", {}, token="t-admin", headers={"x-crm-org": "two"}),
        S("erase served", "/internal/orgs/p-5/erase", {}, headers=IN),
    ]),
    "crm-only": ("crm", [
        S("manifest", "/.well-known/mcp-tools.json", method="GET"),
        S("desk refused", "/desk/read", {}, token="t-admin"),
        S("card refused", "/card/list", {}, token="t-admin"),
        S("profile refused", "/profile/read", {"record_id": "x"}, token="t-admin"),
        S("describe", "/describe", {}, token="t-admin"),
    ]),
    "profiles": ("all,public_profiles", [
        S("create contact", "/change", {"action": "create", "object_type": "Person", "idempotency_key": "c1",
                                        "fields": {"Name": "Grace"}, **R}, token="t-admin", save={"g": "record_id"}),
        S("link bad handle", "/profile/link", {"record_id": "{g}", "handle": "short"}, token="t-admin"),
        S("link", "/profile/link", {"record_id": "{g}", "handle": "abcdefghijklmnop1234"}, token="t-admin"),
        S("profile read", "/profile/read", {"record_id": "{g}"}, token="t-admin"),
        S("unlink", "/profile/link", {"record_id": "{g}", "linked": False}, token="t-admin"),
    ]),
    "personal": ("crm,personal_crm,desktop", [
        S("describe personal", "/describe", {}, token="t-member"),
        S("create personal", "/change", {"action": "create", "object_type": "Company", "idempotency_key": "pk",
                                         "fields": {"Name": "Mine"}, **R}, token="t-member"),
        S("person me", "/person/me", {}, token="t-member"),
        S("erase personal", "/internal/orgs/p-8/erase", {}, headers=IN),
    ]),
}


def fill(value, saved):
    if isinstance(value, str):
        return re.sub(r"\{(\w+)\}", lambda m: saved.get(m[1], m[0]), value)
    if isinstance(value, list):
        return [fill(v, saved) for v in value]
    if isinstance(value, dict):
        return {k: fill(v, saved) for k, v in value.items()}
    return value


def pick(body, dotted):
    for part in dotted.split("."):
        body = body.get(part) if isinstance(body, dict) else None
    return body


def send(port, step, saved):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = dict(step["headers"])
    if step["token"]:
        headers["authorization"] = f"Bearer {step['token']}"
    data = step["raw"]
    if data is None and step["body"] is not None:
        data = json.dumps(fill(step["body"], saved)).encode()
    if data is not None:
        headers["content-type"] = "application/json"
    c.request(step["method"], step["path"], body=data, headers=headers)
    r = c.getresponse()
    raw = r.read()
    out = {"status": r.status, "content-type": r.getheader("content-type"),
           "x-vexa-privacy": r.getheader("x-vexa-privacy"), "body": raw.decode("utf-8", "replace")}
    try:
        body = json.loads(raw)
    except ValueError:
        body = None
    for name, dotted in step["save"].items():
        got = pick(body, dotted)
        if got is not None:
            saved[name] = str(got)
    return out


def run(kind, binary, profile, ups, keydir, only, verbose):
    features, steps = PROFILES[profile]
    fresh_db()
    for u in ups.values():
        u.log.clear()
    port = _free_port()
    proc, log = start(kind, service_env(port, ups, keydir, features), binary)
    rec, saved = [], {}
    try:
        for step in steps:
            if only and only not in step["name"]:
                continue
            got = send(port, step, saved)
            got["counts"] = counts()
            rec.append((step["name"], got))
            if verbose:
                print(f"  {kind} {step['name']}: {got['status']} {got['body'][:300]}")
        for _ in range(200):
            if pending_outbox() == 0:
                break
            time.sleep(0.1)
        rss = rss_kb(proc.pid)
        rows = dump()
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.seek(0)
        text = log.read().decode("utf-8", "replace")
    lines = [ln for ln in text.splitlines() if re.match(r"^(WARNING|ERROR|CRITICAL):(crm|config)", ln)]
    upstream = [dict(e) for u in ("identity", "agent") for e in ups[u].log]
    return {"steps": rec, "rows": rows, "flows": list(ups["flows"].log), "logs": lines, "rss_kb": rss,
            "upstream": upstream}


class Norm:
    """uuid4 ids and times as placeholders, numbered in order of first appearance."""

    def __init__(self):
        self.ids = {}
        self.frozen = False

    def _id(self, m):
        if self.frozen:
            return self.ids.get(m[0], "<U*>")
        return self.ids.setdefault(m[0], f"<U{len(self.ids) + 1}>")

    def text(self, s):
        return ISO.sub("<T>", UUID4.sub(self._id, s))

    def value(self, v):
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, list):
            return [self.value(x) for x in v]
        if isinstance(v, dict):
            return {k: ("<R>" if (k in RANDOM_KEYS and x is not None)
                        or (k == "handle" and isinstance(x, str) and RANDOM_HANDLE.match(x)) else self.value(x))
                    for k, x in v.items()}
        return v


def normalise(record):
    n = Norm()
    steps = []
    for name, got in record["steps"]:
        g = dict(got)
        try:
            body = json.loads(g["body"])
            # the exact text (compact separators, escapes, key order), with values normalised
            g["body"] = n.text(json.dumps(n.value(body), ensure_ascii=False, separators=(",", ":")))
            g["text_equal_shape"] = len(got["body"]) - len(json.dumps(body, ensure_ascii=False, separators=(",", ":")))
        except ValueError:
            g["body"] = n.text(g["body"])
        steps.append((name, g))
    # ids that no answer named (outbox event ids, audit ids) have no stable order: one placeholder
    n.frozen = True
    rows = {t: sorted(json.dumps(n.value(r), sort_keys=True) for r in rs) for t, rs in record["rows"].items()}
    flows = sorted(json.dumps({"path": e["path"], "headers": e["headers"], "body": n.value(json.loads(e["body"] or "{}"))},
                              sort_keys=True) for e in record["flows"])
    other = sorted(json.dumps(n.value(e), sort_keys=True) for e in record["upstream"])
    return {"steps": steps, "rows": rows, "flows": flows, "logs": [n.text(x) for x in record["logs"]], "upstream": other}


def compare(py, rs):
    a, b = normalise(py), normalise(rs)
    same, diffs = 0, []
    for (name, x), (_, y) in zip(a["steps"], b["steps"]):
        keys = [k for k in x if x.get(k) != y.get(k)]
        if keys:
            diffs.append((name, {k: (x.get(k), y.get(k)) for k in keys}))
        else:
            same += 1
    for t in sorted(set(a["rows"]) | set(b["rows"])):
        if a["rows"].get(t) != b["rows"].get(t):
            diffs.append((f"rows {t}", {"rows": (a["rows"].get(t), b["rows"].get(t))}))
    for key in ("flows", "logs", "upstream"):
        if a[key] != b[key]:
            diffs.append((key, {key: (a[key], b[key])}))
    return same, len(a["steps"]), diffs


#: start-up refusals: each environment change against the full one, run by both
BOOT = {
    "superuser": lambda kd: {"CRM_DATABASE_URL": "postgresql+pg8000://" + urlsplit(ADMIN_URL).netloc + "/" + RUN_DB},
    "no org": lambda kd: {"CRM_ORG_ID": ""},
    "no secret": lambda kd: {"INTERNAL_API_SECRET": ""},
    "no flows key": lambda kd: {"FLOWS_PUBLISH_KEY": ""},
    "placeholder key": lambda kd: {"FLOWS_PUBLISH_KEY": "changeme"},
    "no seal key": lambda kd: {"VEXA_FACT_SEAL_KEY_FILE": str(kd / "missing.pem")},
    "bad password": lambda kd: {"CRM_DATABASE_URL": f"postgresql+pg8000://vexa_crm:wrong@{urlsplit(ADMIN_URL).hostname}:{urlsplit(ADMIN_URL).port or 5432}/{RUN_DB}"},
}
REFUSAL = re.compile(r"^(ERROR:crm\.api:|SystemExit: |[\w.]+(Error|NotReady): )")


def boot(kind, binary, ups, keydir, over):
    env = service_env(_free_port(), ups, keydir, "all")
    env.update(over)
    cmd = [binary] if kind == "rust" else [sys.executable, str(LAUNCH), "crm"]
    try:
        r = subprocess.run(cmd, env=env, cwd=CRM_DIR, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return ("running", "")
    said = [REFUSAL.sub("", ln) for ln in (r.stdout + r.stderr).splitlines() if REFUSAL.match(ln)]
    return (r.returncode, said[0] if said else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", action="append")
    ap.add_argument("--only")
    ap.add_argument("-v", action="store_true")
    ap.add_argument("--binary", default=str(HERE / "target" / "release" / "vexa-crm"))
    args = ap.parse_args()
    ups = {r: Upstream(r).start() for r in ("identity", "flows", "agent")}
    keydir = pathlib.Path(tempfile.mkdtemp(prefix="crm-parity-"))
    prepare_base(keydir)
    total_same = total = 0
    failed = False
    try:
        for profile in args.profile or list(PROFILES):
            py = run("python", args.binary, profile, ups, keydir, args.only, args.v)
            rs = run("rust", args.binary, profile, ups, keydir, args.only, args.v)
            same, n, diffs = compare(py, rs)
            total_same += same
            total += n
            print(f"{profile}: {same}/{n} steps the same, {len(diffs)} difference(s); "
                  f"rows {sum(len(v) for v in rs['rows'].values())}, events {len(rs['flows'])}; "
                  f"RSS python {py['rss_kb'] / 1024:.1f} MB, rust {rs['rss_kb'] / 1024:.1f} MB")
            for name, d in diffs:
                failed = True
                print(f"  DIFF {name}")
                for k, (x, y) in d.items():
                    print(f"    {k}:\n      python: {str(x)[:2000]}\n      rust:   {str(y)[:2000]}")
        if not args.only:
            fresh_db()
            agree = 0
            for name, over in BOOT.items():
                py = boot("python", args.binary, ups, keydir, over(keydir))
                rs = boot("rust", args.binary, ups, keydir, over(keydir))
                if py == rs:
                    agree += 1
                else:
                    failed = True
                    print(f"  DIFF boot {name}\n      python: {py}\n      rust:   {rs}")
            print(f"boot: {agree}/{len(BOOT)} refusals agree (exit status and message)")
    finally:
        for u in ups.values():
            u.stop()
        _admin(f"DROP DATABASE IF EXISTS {RUN_DB} WITH (FORCE)")
        _admin(f"DROP DATABASE IF EXISTS {BASE_DB} WITH (FORCE)")
    print(f"{total_same}/{total} steps the same")
    print("PARITY OK" if not failed else "PARITY DIFFERS")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
