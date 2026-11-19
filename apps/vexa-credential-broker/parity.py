#!/usr/bin/env python3
"""Differential parity check: the Python broker and the Rust broker, booted with the same keys and
configuration over two empty state directories, answer the same signed requests the same way.

    uv run --project core/agent/services/credential-broker --frozen \
        python apps/vexa-credential-broker/parity.py [path/to/vexa-credential-broker]

Every step sends one request to each broker (signed afresh: nonces are single-use) and compares the
status, the JSON body (ids replaced by their order of first appearance on that side, timestamps by
"<t>", OAuth state and PKCE values by placeholders) and the security headers. After the scenario it
compares the two audit trails, then boots the Rust broker over a COPY of the Python broker's state
directory and checks it lists the same connections and reads the same stored credential (the schema
and the store format are shared).

Some steps reach the network on purpose with dummy credentials (Google's token and Gmail/Calendar
endpoints answer 401; api.github.com/zen answers 401): they prove the TLS client and the refusal
mapping, never a real account. The script prints one line per step and exits 1 on any difference.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "core/agent/services/credential-broker"
sys.path.insert(0, str(SERVICE / "src"))

from credential_broker import assertion, identity_token  # noqa: E402
from credential_broker.store import LocalEncryptedStore, load_store_key  # noqa: E402

RUST = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "apps/vexa-credential-broker/target/release/vexa-credential-broker"
ROLES = ("agent", "human", "git", "bots", "sensors", "signals")
ACTOR = "42"
SESSION = "browser-session"
GATEWAY = identity_token.generate_signing_key()


def free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Side:
    def __init__(self, name: str, root: Path, env: dict, command: list, cwd: Path):
        self.name, self.root, self.env, self.command, self.cwd = name, root, env, command, cwd
        self.ids: dict = {}
        self.vars: dict = {}
        self.proc = None
        self.port = 0

    def start(self, state: Path):
        self.port = free_port()
        env = dict(self.env, VEXA_CONNECTIONS_STATE_DIR=str(state))
        cmd = [c.replace("{port}", str(self.port)) for c in self.command]
        self.log = open(self.root / f"{self.name}.log", "ab")
        self.proc = subprocess.Popen(cmd, cwd=self.cwd, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(300):
            try:
                if self.raw("GET", "/health", b"", {})[0] == 200:
                    return
            except OSError:
                pass
            time.sleep(0.05)
        raise SystemExit(f"{self.name} did not start; see {self.root / (self.name + '.log')}")

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(10)
            self.proc = None

    def raw(self, method, target, body, headers):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        c.request(method, target, body=body, headers=headers)
        r = c.getresponse()
        data = r.read()
        out = (r.status, {k.lower(): v for k, v in r.getheaders()}, data)
        c.close()
        return out


def write_keys(root: Path) -> dict:
    env = {}
    for role in ROLES:
        p = root / f"{role}.key"
        p.write_text(secrets.token_hex(32) + "\n")
        env[f"VEXA_CONNECTIONS_{role.upper()}_KEY_FILE"] = str(p)
    store = root / "store.key"
    store.write_text(secrets.token_hex(32))
    pub = root / "identity-public.pem"
    pub.write_bytes(identity_token.public_key_pem(GATEWAY))
    env.update(VEXA_CONNECTIONS_STORE_KEY_FILE=str(store), VEXA_GATEWAY_IDENTITY_PUBLIC_KEY_FILE=str(pub),
               VEXA_CONNECTIONS_STORE="local", VEXA_CONNECTIONS_GOOGLE_CLIENT_ID="fixture-client.apps.googleusercontent.com",
               VEXA_CONNECTIONS_GOOGLE_CLIENT_SECRET="fixture-client-secret",
               VEXA_CONNECTIONS_PRODUCT_REDIRECT="https://app.example.test/api/auth/callback/google")
    return env


HEX = re.compile(r"^[0-9a-f]{32}$")


def normalise(side: Side, value):
    if isinstance(value, dict):
        # A permission_required answer rotates setup_request to a random token (secrets.token_urlsafe).
        return {k: "<token>" if k == "setup_request" and isinstance(v, str) and not HEX.match(v) else normalise(side, v)
                for k, v in value.items()}
    if isinstance(value, list):
        return [normalise(side, v) for v in value]
    if isinstance(value, float) and value > 1e9:
        return "<t>"
    if isinstance(value, str):
        if HEX.match(value):
            return side.ids.setdefault(value, f"<id{len(side.ids)}>")
        value = re.sub(r"\b[0-9a-f]{32}\b", lambda m: side.ids.setdefault(m.group(0), f"<id{len(side.ids)}>"), value)
        value = re.sub(r"state=vxc_[A-Za-z0-9_-]+", "state=<state>", value)
        value = re.sub(r"code_challenge=[A-Za-z0-9_-]+", "code_challenge=<challenge>", value)
    return value


def request(side: Side, role, method, path, body=None, *, actor=ACTOR, session=SESSION, identity=True,
            delegation=None, workspaces=None, raw=None, assertion_header=None, key_role=None, at=None,
            nonce=None, sub=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
    key = Path(side.env[f"VEXA_CONNECTIONS_{(key_role or role).upper()}_KEY_FILE"]).read_bytes().strip()
    headers = {"Content-Type": "application/json"}
    if assertion_header is not False:
        headers[assertion.HEADER] = assertion_header or assertion.sign(
            key, role=role, actor=actor, session=session, method=method, path=path, body=data, at=at, nonce=nonce)
    if role in ("agent", "git") and identity:
        claims = {"sub": sub or actor, "scopes": ["bot", "tx"]}
        if workspaces:
            claims["workspaces"] = workspaces
        if delegation:
            claims["delegation"] = delegation
        headers[identity_token.HEADER] = identity_token.sign(GATEWAY, claims)
    status, h, out = side.raw(method, path, data, headers)
    try:
        parsed = json.loads(out)
    except ValueError:
        parsed = out.decode(errors="replace")
    return status, h, parsed


FAILURES: list = []


def step(name, sides, make, check_headers=True):
    """make(side) -> request kwargs; compares the two answers; returns them."""
    answers = []
    for s in sides:
        args = make(s)
        if callable(args):
            args = args()
        answers.append(request(s, *args[0], **args[1]))
    (ps, ph, pb), (rs, rh, rb) = answers
    pn, rn = normalise(sides[0], pb), normalise(sides[1], rb)
    keys = ("cache-control", "x-content-type-options", "content-type")
    pheads = {k: ph.get(k) for k in keys} | {"x-trace-id": "x-trace-id" in ph}
    rheads = {k: rh.get(k) for k in keys} | {"x-trace-id": "x-trace-id" in rh}
    same = ps == rs and pn == rn and (not check_headers or pheads == rheads)
    print(("ok   " if same else "DIFF ") + f"{name}: {ps}" + ("" if same else f"\n   python {ps} {json.dumps(pn)} {pheads}\n   rust   {rs} {json.dumps(rn)} {rheads}"))
    if not same:
        FAILURES.append(name)
    return answers


def seed_credential(side: Side, state: Path, cid: str, value: dict, owner=ACTOR):
    """A ready connection with this stored credential, written as the broker writes one."""
    store = LocalEncryptedStore(state / "secrets.sqlite", load_store_key(side.env["VEXA_CONNECTIONS_STORE_KEY_FILE"]))
    saved = store.put(cid, {"value": value, "owner": owner})
    db = sqlite3.connect(state / "metadata.sqlite")
    db.execute("UPDATE connections SET status='ready', version=? WHERE id=?", (saved.version, cid))
    db.commit()
    db.close()


def scenario(py: Side, rs: Side, states: dict):
    S = (py, rs)
    a = lambda *x, **k: (x, k)  # noqa: E731
    step("health", S, lambda s: a("human", "GET", "/health", assertion_header=False))
    step("ready", S, lambda s: a("human", "GET", "/ready", assertion_header=False))
    step("no assertion", S, lambda s: a("human", "GET", "/api/connections", assertion_header=False))
    step("bad signature", S, lambda s: a("human", "GET", "/api/connections", key_role="agent"))
    step("expired", S, lambda s: a("human", "GET", "/api/connections", at=int(time.time()) - 120))
    step("future", S, lambda s: a("human", "GET", "/api/connections", at=int(time.time()) + 60))
    step("binding", S, lambda s: a("human", "GET", "/api/connections", assertion_header=assertion.sign(
        Path(s.env["VEXA_CONNECTIONS_HUMAN_KEY_FILE"]).read_bytes().strip(), role="human", actor=ACTOR,
        session=SESSION, method="GET", path="/api/preferences")))
    nonce = "fixed-nonce-" + secrets.token_hex(4)
    step("first use of a nonce", S, lambda s: a("human", "GET", "/api/connections", nonce=nonce + s.name))
    step("replay", S, lambda s: a("human", "GET", "/api/connections", nonce=nonce + s.name))
    step("agent without identity", S, lambda s: a("agent", "GET", "/api/connections", identity=False))
    step("agent identity for another", S, lambda s: a("agent", "GET", "/api/connections", sub="43"))
    step("session mismatch", S, lambda s: a("agent", "GET", "/api/connections", delegation={"regime": "human", "unit": "other-unit"}))
    step("unknown route", S, lambda s: a("human", "GET", "/api/nothing"))
    step("wrong method", S, lambda s: a("human", "POST", "/api/connections", {}))
    step("role refused", S, lambda s: a("sensors", "GET", "/api/connections"))
    step("list empty", S, lambda s: a("human", "GET", "/api/connections"))
    step("shared refused", S, lambda s: a("agent", "GET", "/api/connections", delegation={"regime": "human", "unit": SESSION, "shared": True}))
    step("unwatched list ok", S, lambda s: a("agent", "GET", "/api/connections", delegation={"regime": "unattended", "unit": SESSION}))
    step("unwatched setup refused", S, lambda s: a("agent", "POST", "/api/setup", {"provider": "custom_secret", "label": "X"}, delegation={"regime": "unattended", "unit": SESSION}))
    step("setup extra field", S, lambda s: a("human", "POST", "/api/setup", {"provider": "custom_secret", "colour": 1}))
    step("setup missing provider", S, lambda s: a("human", "POST", "/api/setup", {"label": "X"}))
    step("setup not json", S, lambda s: a("human", "POST", "/api/setup", raw=b"{nope"))
    step("setup empty body", S, lambda s: a("human", "POST", "/api/setup", raw=b""))
    step("setup long label", S, lambda s: a("human", "POST", "/api/setup", {"provider": "custom_secret", "label": "x" * 81}))

    def keep(name, answers):
        for s, (_, _, body) in zip(S, answers):
            s.vars[name] = body.get("connection_id") if isinstance(body, dict) else None

    keep("svc", step("setup custom", S, lambda s: a("agent", "POST", "/api/setup", {"provider": "custom_secret", "label": "GitHub Zen"})))
    step("setup again reuses", S, lambda s: a("agent", "POST", "/api/setup", {"provider": "custom_secret", "label": "  github   zen "}))
    keep("gmail", step("setup gmail", S, lambda s: a("human", "POST", "/api/setup", {"provider": "google_email", "label": "Gmail"})))
    keep("cal", step("setup calendar", S, lambda s: a("agent", "POST", "/api/setup", {"provider": "google_calendar"})))
    c = lambda s, k, tail: f"/api/connections/{s.vars[k]}/{tail}"  # noqa: E731
    step("request again", S, lambda s: a("agent", "POST", c(s, "svc", "request")))
    step("request someone else's", S, lambda s: a("agent", "POST", c(s, "svc", "request"), actor="43"))
    step("request unknown", S, lambda s: a("agent", "POST", "/api/connections/" + "0" * 32 + "/request"))
    for label, spec in [
        ("prepare shape errors", {"endpoint": 5, "scheme": "basic", "colour": "x", "fields": [{"name": "1a"}]}),
        ("prepare nested errors", {"oauth": {"authorization_url": "https://a.example/x", "scopes": [], "extra": 1}, "fields": "x"}),
        ("prepare oauth not a dict", {"oauth": "yes", "secret_label": ""}),
        ("prepare too many fields", {"endpoint": "https://api.example.com/x", "fields": [{"name": f"f{i}", "label": "L", "location": "query"} for i in range(11)]}),
        ("prepare bad scope item", {"oauth": {"authorization_url": "https://a.example/x", "token_url": "https://a.example/t", "scopes": ["", 5, "x" * 301]}}),
        ("prepare http endpoint", {"endpoint": "http://api.example.com/x"}),
        ("prepare no endpoint", {}),
        ("prepare bad header", {"endpoint": "https://api.example.com/x", "header": "Cookie"}),
        ("prepare prefix without scheme", {"endpoint": "https://api.example.com/x", "prefix": "Bot"}),
        ("prepare telegram", {"endpoint": "https://api.telegram.org/bot{secret}/sendMessage", "scheme": "telegram", "method": "POST"}),
        ("prepare get with body field", {"endpoint": "https://api.example.com/x", "fields": [{"name": "a", "label": "A"}]}),
        ("prepare duplicate fields", {"endpoint": "https://api.example.com/x", "method": "POST", "fields": [{"name": "a", "label": "A"}, {"name": "a", "label": "B"}]}),
    ]:
        step(label, S, lambda s, spec=spec: a("agent", "POST", c(s, "svc", "prepare"), {"setup": spec}))
    step("prepare body not dict", S, lambda s: a("agent", "POST", c(s, "svc", "prepare"), {"setup": []}))
    step("prepare google", S, lambda s: a("agent", "POST", c(s, "gmail", "prepare"), {"setup": {"endpoint": "https://api.github.com/zen"}}))
    zen = {"endpoint": "https://api.github.com/zen", "documentation_url": "https://docs.github.com"}
    step("prepare valid", S, lambda s: a("agent", "POST", c(s, "svc", "prepare"), {"setup": zen}))
    step("prepare same again", S, lambda s: a("agent", "POST", c(s, "svc", "prepare"), {"setup": dict(zen)}))
    step("list after prepare", S, lambda s: a("human", "GET", "/api/connections"))
    step("save without host confirmation", S, lambda s: a("human", "POST", c(s, "svc", "custom-secret"), {"value": "dummy-token-not-a-secret"}))
    step("save as agent", S, lambda s: a("agent", "POST", c(s, "svc", "custom-secret"), {"value": "x"}))

    def setup_request_of(s, key):
        db = sqlite3.connect(states[s.name] / "metadata.sqlite")
        row = db.execute("SELECT setup_request FROM connections WHERE id=?", (s.vars[key],)).fetchone()
        db.close()
        return row[0]

    step("save stale setup", S, lambda s: a("human", "POST", c(s, "svc", "custom-secret"), {"value": "dummy-token-not-a-secret", "confirmed_host": "api.github.com", "setup_request": "old"}))
    step("save missing value", S, lambda s: a("human", "POST", c(s, "svc", "custom-secret"), {"confirmed_host": "api.github.com", "setup_request": setup_request_of(s, "svc")}))
    step("save confirmed", S, lambda s: a("human", "POST", c(s, "svc", "custom-secret"), {"value": "dummy-token-not-a-secret", "confirmed_host": "API.github.com ", "setup_request": setup_request_of(s, "svc")}))
    step("list after save", S, lambda s: a("agent", "GET", "/api/connections"))
    keep("oauth", step("setup custom oauth", S, lambda s: a("agent", "POST", "/api/setup", {"provider": "custom_secret", "label": "Acme OAuth"})))
    step("call the service (live, dummy token)", S, lambda s: a("agent", "POST", c(s, "svc", "call"), {"parameters": {}}))
    step("call with a body on GET", S, lambda s: a("agent", "POST", c(s, "svc", "call"), {"body": {"a": 1}}))
    step("call not ready", S, lambda s: a("agent", "POST", c(s, "gmail", "call"), {}))
    step("authorize custom without oauth", S, lambda s: a("human", "POST", c(s, "svc", "authorize")))
    step("authorize gmail", S, lambda s: a("human", "POST", c(s, "gmail", "authorize")))
    step("authorize gmail with calendar grant", S, lambda s: a("human", "POST", c(s, "gmail", "authorize"), {"grant": "calendar_write"}))
    step("authorize calendar with grant", S, lambda s: a("human", "POST", c(s, "cal", "authorize"), {"grant": "calendar_write"}))
    step("authorize bad grant", S, lambda s: a("human", "POST", c(s, "cal", "authorize"), {"grant": "all"}))
    answers = step("authorize gmail again", S, lambda s: a("human", "POST", c(s, "gmail", "authorize"), raw=b"null"))
    for s, (_, _, body) in zip(S, answers):
        s.vars["state"] = parse_qs(urlsplit(body["authorize_url"]).query)["state"][0]
    step("callback unknown state", S, lambda s: a("human", "GET", "/api/auth/callback/google?state=vxc_nope&code=x"))
    step("callback other session", S, lambda s: a("human", "GET", f"/api/auth/callback/google?state={s.vars['state']}&error=access_denied", session="another"))
    step("callback refused by person", S, lambda s: a("human", "GET", f"/api/auth/callback/google?state={s.vars['state']}&error=access_denied"))
    answers = step("authorize calendar", S, lambda s: a("human", "POST", c(s, "cal", "authorize")))
    for s, (_, _, body) in zip(S, answers):
        s.vars["state"] = parse_qs(urlsplit(body["authorize_url"]).query)["state"][0]
    step("callback code exchange (live, fixture client)", S, lambda s: a("human", "GET", f"/api/auth/callback/google?state={s.vars['state']}&code=fixture-code"))
    oauth_spec = {"oauth": {"authorization_url": "https://github.com/login/oauth/authorize", "token_url": "https://github.com/login/oauth/access_token", "scopes": ["read:user"]}, "endpoint": "https://api.github.com/user"}
    step("prepare custom oauth", S, lambda s: a("agent", "POST", c(s, "oauth", "prepare"), {"setup": oauth_spec}))
    step("prepare oauth dropped", S, lambda s: a("agent", "POST", c(s, "oauth", "prepare"), {"setup": {"endpoint": "https://api.github.com/user"}}))
    step("authorize before application", S, lambda s: a("human", "POST", c(s, "oauth", "authorize")))
    step("oauth application unconfirmed", S, lambda s: a("human", "POST", c(s, "oauth", "oauth-application"), {"client_id": "cid", "client_secret": "csecret", "setup_request": setup_request_of(s, "oauth")}))
    step("oauth application saved", S, lambda s: a("human", "POST", c(s, "oauth", "oauth-application"), {"client_id": "cid", "client_secret": "csecret", "setup_request": setup_request_of(s, "oauth"), "confirmed_hosts": ["github.com", "api.github.com"]}))
    step("authorize custom oauth", S, lambda s: a("human", "POST", c(s, "oauth", "authorize")))
    step("custom secret on oauth", S, lambda s: a("human", "POST", c(s, "oauth", "custom-secret"), {"value": "x"}))

    # Preferences.
    step("preferences empty", S, lambda s: a("agent", "GET", "/api/preferences"))
    step("preferences invalid", S, lambda s: a("human", "POST", "/api/preferences", {"calendar_ids": "all"}))
    step("preferences by a worker", S, lambda s: a("agent", "POST", "/api/preferences", {"draft_attachments": True}, delegation={"regime": "human", "unit": SESSION}))
    step("preferences saved", S, lambda s: a("human", "POST", "/api/preferences", {"draft_attachments": "yes", "calendar_ids": ["primary", "team@example.com"], "connection_actions": ["gmail.read"], "draft_attachment_max_kb": "512"}))
    step("preferences read", S, lambda s: a("agent", "GET", "/api/preferences"))

    # Reads and writes on Google connections, credentials seeded as a consent stores them.
    step("read not ready", S, lambda s: a("agent", "POST", c(s, "gmail", "read"), {"action": "gmail.search"}))
    for s in S:
        far = time.time() + 3600
        seed_credential(s, states[s.name], s.vars["gmail"], {"access_token": "dummy-access", "refresh_token": "dummy-refresh", "expires_at": far, "scope": "https://www.googleapis.com/auth/gmail.readonly"})
        seed_credential(s, states[s.name], s.vars["cal"], {"access_token": "dummy-access", "refresh_token": "dummy-refresh", "expires_at": far, "scope": "https://www.googleapis.com/auth/calendar.events.readonly"})
    step("read wrong action", S, lambda s: a("agent", "POST", c(s, "gmail", "read"), {"action": "calendar.events"}))
    step("read bad limit", S, lambda s: a("agent", "POST", c(s, "gmail", "read"), {"action": "gmail.search", "limit": 21}))
    step("read unwatched without policy", S, lambda s: a("agent", "POST", c(s, "gmail", "read"), {"action": "gmail.search"}, delegation={"regime": "unattended", "unit": SESSION}))
    step("read bad message id", S, lambda s: a("agent", "POST", c(s, "gmail", "read"), {"action": "gmail.read", "message_id": "a/b"}))
    step("read bad thread offset", S, lambda s: a("agent", "POST", c(s, "gmail", "read"), {"action": "gmail.thread", "message_id": "t1", "page_token": "x"}))
    step("read calendar bad range", S, lambda s: a("agent", "POST", c(s, "cal", "read"), {"action": "calendar.events", "time_min": "2026-01-01T00:00:00", "time_max": "2026-02-01T00:00:00Z"}))
    step("gmail search (live, dummy token)", S, lambda s: a("agent", "POST", c(s, "gmail", "read"), {"action": "gmail.search", "query": "from:me", "limit": "3"}, delegation={"regime": "unattended", "unit": SESSION} if False else None))
    step("calendar read (live, dummy token)", S, lambda s: a("agent", "POST", c(s, "cal", "read"), {"action": "calendar.events", "time_min": "2026-11-01T00:00:00Z", "time_max": "2026-11-30T00:00:00+01:00"}))
    draft = {"request_id": "req-0000-0001", "recipient": "someone@example.com", "subject": "Hi", "body": "Hello"}
    step("draft by an unwatched worker", S, lambda s: a("agent", "POST", c(s, "gmail", "draft"), draft, delegation={"regime": "unattended", "unit": SESSION}))
    step("draft recipient outside policy", S, lambda s: a("agent", "POST", c(s, "gmail", "draft"), dict(draft, request_id="req-0000-0002", policy={"recipient_domains": ["vexa.ai"]})))
    step("draft attachments refused", S, lambda s: a("agent", "POST", c(s, "gmail", "draft"), dict(draft, request_id="req-0000-0003", attachments=[{"filename": "a.txt", "content_type": "text/plain", "data": "aGk="}])))
    step("draft attachment not base64", S, lambda s: a("agent", "POST", c(s, "gmail", "draft"), dict(draft, request_id="req-0000-0004", attachments=[{"filename": "a.txt", "content_type": "text/plain", "data": "!!"}], policy={"attachments": True, "attachment_max_bytes": 10})))
    step("draft without the drafts permission", S, lambda s: a("agent", "POST", c(s, "gmail", "draft"), draft))
    step("draft retry, same request", S, lambda s: a("agent", "POST", c(s, "gmail", "draft"), draft))
    step("draft update of a person's draft", S, lambda s: a("agent", "POST", c(s, "gmail", "draft-update"), dict(draft, request_id="req-0000-0005", draft_id="r123")))
    step("draft on the calendar connection", S, lambda s: a("agent", "POST", c(s, "cal", "draft"), draft))
    event = {"request_id": "req-cal-00001", "action": "calendar.event.create", "title": "Sync", "start": {"date_time": "2026-11-20T10:00:00Z"}, "end": {"date_time": "2026-11-20T11:00:00Z"}}
    step("event create with event_id", S, lambda s: a("agent", "POST", c(s, "cal", "calendar-event"), dict(event, event_id="abcde12345")))
    step("event on another calendar", S, lambda s: a("agent", "POST", c(s, "cal", "calendar-event"), dict(event, request_id="req-cal-00002", calendar_id="team@example.com")))
    step("event notify refused", S, lambda s: a("agent", "POST", c(s, "cal", "calendar-event"), dict(event, request_id="req-cal-00003", notify=True)))
    step("event without the write permission", S, lambda s: a("agent", "POST", c(s, "cal", "calendar-event"), event))
    step("event request id reused", S, lambda s: a("agent", "POST", c(s, "cal", "calendar-event"), dict(event, title="Other")))

    # Sensor grants and the sensor read.
    step("sensor owner mismatch", S, lambda s: a("sensors", "POST", "/api/internal/sensor/calendar-changes", {"owner": "43"}))
    step("sensor without a grant", S, lambda s: a("sensors", "POST", "/api/internal/sensor/calendar-changes", {"owner": ACTOR}))
    answers = step("grant issue", S, lambda s: a("agent", "POST", "/api/sensor-grants", {"days": "30"}))
    for s, (_, _, body) in zip(S, answers):
        s.vars["grant"] = body.get("grant_id")
    step("grant list", S, lambda s: a("human", "GET", "/api/sensor-grants"))
    step("sensor read (live, dummy token)", S, lambda s: a("sensors", "POST", "/api/internal/sensor/calendar-changes", {"owner": ACTOR, "cursor": "sync-token"}))
    step("grant revoke", S, lambda s: a("human", "POST", f"/api/sensor-grants/{s.vars['grant']}/revoke"))
    step("grant revoke unknown", S, lambda s: a("human", "POST", "/api/sensor-grants/" + "1" * 32 + "/revoke"))
    step("sensor after revoke", S, lambda s: a("sensors", "POST", "/api/internal/sensor/calendar-changes", {"owner": ACTOR}))
    step("grant on no calendar", S, lambda s: a("human", "POST", "/api/sensor-grants", {"connection_id": s.vars["gmail"]}))

    # Git credentials.
    step("git put", S, lambda s: a("git", "POST", "/api/internal/git-secret", {"name": "pat/42", "action": "put", "value": "ghp_dummy"}))
    step("git get", S, lambda s: a("git", "POST", "/api/internal/git-secret", {"name": "pat/42", "action": "get"}))
    step("git migrate kept", S, lambda s: a("git", "POST", "/api/internal/git-secret", {"name": "pat/42", "action": "migrate", "value": "other"}))
    step("git ws key", S, lambda s: a("git", "POST", "/api/internal/git-secret", {"name": "deploy/ws-7.pub", "action": "migrate", "value": "ssh-ed25519 AAAA"}, workspaces=["7"]))
    step("git ws not a member", S, lambda s: a("git", "POST", "/api/internal/git-secret", {"name": "deploy/ws-8.pub", "action": "get"}, workspaces=["7"]))
    step("git another person", S, lambda s: a("git", "POST", "/api/internal/git-secret", {"name": "pat/43", "action": "get"}))
    step("git bad name", S, lambda s: a("git", "POST", "/api/internal/git-secret", {"name": "token/42", "action": "get"}))
    step("git by agent role", S, lambda s: a("agent", "POST", "/api/internal/git-secret", {"name": "pat/42", "action": "get"}))

    # Bot accounts.
    bot = "b" * 32
    acct = {"owner": "user:42", "platform": "google", "display_name": "Bot", "created_by": "user:42"}
    step("bot list empty", S, lambda s: a("bots", "POST", "/api/internal/bot-account", {"action": "list", "owners": ["user:42"]}))
    step("bot put", S, lambda s: a("bots", "POST", "/api/internal/bot-account", {"action": "put", "id": bot, "account": acct, "files": [{"path": "Default/Cookies", "data": "aGVsbG8="}]}))
    step("bot get", S, lambda s: a("bots", "POST", "/api/internal/bot-account", {"action": "get", "id": bot}))
    step("bot state", S, lambda s: a("bots", "POST", "/api/internal/bot-account", {"action": "state", "id": bot, "state": "signed_out"}))
    step("bot put other owner", S, lambda s: a("bots", "POST", "/api/internal/bot-account", {"action": "put", "id": bot, "account": dict(acct, owner="company"), "files": []}))
    step("bot list", S, lambda s: a("bots", "POST", "/api/internal/bot-account", {"action": "list", "owners": ["user:42", "company"]}))
    step("bot bad file path", S, lambda s: a("bots", "POST", "/api/internal/bot-account", {"action": "put", "id": bot, "account": acct, "files": [{"path": "../x", "data": ""}]}))
    step("bot delete", S, lambda s: a("bots", "POST", "/api/internal/bot-account", {"action": "delete", "id": bot}))
    step("bot get deleted", S, lambda s: a("bots", "POST", "/api/internal/bot-account", {"action": "get", "id": bot}))
    step("bot delete again", S, lambda s: a("bots", "POST", "/api/internal/bot-account", {"action": "delete", "id": bot}))

    # Company secrets: missing, then stored by each implementation's operator command.
    step("signals key missing", S, lambda s: a("signals", "POST", "/api/internal/signals/model-key", {"name": "jev"}))
    step("mail credential missing", S, lambda s: a("sensors", "POST", "/api/internal/mail/smtp-credential", {"name": "relay"}))
    step("signals key bad name", S, lambda s: a("signals", "POST", "/api/internal/signals/model-key", {"name": "Jev/x"}))
    for s in S:
        env = dict(s.env, VEXA_CONNECTIONS_STATE_DIR=str(states[s.name]))
        if s.name == "python":
            cmds = [[sys.executable, "-m", "credential_broker.signals_key", "put", "jev"], [sys.executable, "-m", "credential_broker.mail_secret", "put", "relay"]]
        else:
            cmds = [[str(RUST), "signals-key", "put", "jev"], [str(RUST), "mail-secret", "put", "relay"]]
        for cmd in cmds:
            done = subprocess.run(cmd, input=b"secret-value-for-parity\n", cwd=s.cwd, env=env, capture_output=True)
            print(f"     {s.name} {' '.join(cmd[-3:])}: exit {done.returncode} {done.stdout.decode().strip()}")
    step("signals key read", S, lambda s: a("signals", "POST", "/api/internal/signals/model-key", {"name": "jev"}))
    step("mail credential read", S, lambda s: a("sensors", "POST", "/api/internal/mail/smtp-credential", {"name": "relay"}))
    step("mail credential by signals role", S, lambda s: a("signals", "POST", "/api/internal/mail/smtp-credential", {"name": "relay"}))

    # Disconnect, delete, and the answers a deleted connection gives.
    step("disconnect as agent", S, lambda s: a("agent", "POST", c(s, "svc", "disconnect")))
    step("disconnect", S, lambda s: a("human", "POST", c(s, "svc", "disconnect")))
    step("call after disconnect", S, lambda s: a("agent", "POST", c(s, "svc", "call"), {}))
    step("delete", S, lambda s: a("human", "POST", c(s, "svc", "delete")))
    step("request deleted", S, lambda s: a("agent", "POST", c(s, "svc", "request")))
    step("setup successor", S, lambda s: a("agent", "POST", "/api/setup", {"provider": "custom_secret", "label": "GitHub Zen"}))
    step("request deleted, successor named", S, lambda s: a("agent", "POST", c(s, "svc", "request")))
    step("list at the end", S, lambda s: a("human", "GET", "/api/connections"))


def audit_trail(state: Path, ids: dict) -> list:
    db = sqlite3.connect(state / "metadata.sqlite")
    rows = db.execute("SELECT actor, session, connection, action, outcome, version FROM audit ORDER BY seq").fetchall()
    db.close()
    norm = lambda v: ids.get(v, "<new>") if isinstance(v, str) and HEX.match(v or "") else v  # noqa: E731
    return [tuple(norm(v) for v in r) for r in rows]


def main() -> int:
    if not RUST.exists():
        raise SystemExit(f"build the Rust broker first: {RUST}")
    root = Path(tempfile.mkdtemp(prefix="broker-parity-"))
    env = dict(os.environ, **write_keys(root))
    env.pop("VEXA_CONNECTIONS_OPENBAO_ADDR", None)
    states = {"python": root / "python-state", "rust": root / "rust-state"}
    py = Side("python", root, env, [sys.executable, "-m", "uvicorn", "credential_broker.main:app", "--host", "127.0.0.1", "--port", "{port}", "--no-access-log"], SERVICE / "src")
    rs = Side("rust", root, env, [str(RUST), "--port", "{port}"], root)
    os.umask(0o077)
    for s in (py, rs):
        states[s.name].mkdir()
        s.start(states[s.name])
    try:
        scenario(py, rs, states)
    finally:
        for s in (py, rs):
            s.stop()
    pa, ra = audit_trail(states["python"], py.ids), audit_trail(states["rust"], rs.ids)
    same = pa == ra
    print(("ok   " if same else "DIFF ") + f"audit trail: {len(pa)} rows python, {len(ra)} rows rust")
    if not same:
        FAILURES.append("audit trail")
        for i, (x, y) in enumerate(zip(pa, ra)):
            if x != y:
                print(f"   first difference at row {i}: python {x} rust {y}")
                break
    # The Rust broker over a copy of the Python broker's state: the same rows, the same store.
    copy = root / "python-state-copy"
    shutil.copytree(states["python"], copy)
    py.ids, rs.ids = {}, {}
    py.start(states["python"])
    rs.start(copy)
    try:
        step("rust reads python's state: list", (py, rs), lambda s: (("human", "GET", "/api/connections"), {}))
        step("rust reads python's state: git", (py, rs), lambda s: (("git", "POST", "/api/internal/git-secret"), {"body": {"name": "pat/42", "action": "get"}}))
        step("rust reads python's state: grants", (py, rs), lambda s: (("human", "GET", "/api/sensor-grants"), {}))
    finally:
        py.stop()
        rs.stop()
    print(f"\n{'PARITY OK' if not FAILURES else 'DIFFERENCES: ' + ', '.join(FAILURES)} ({root})")
    if not FAILURES:
        shutil.rmtree(root, ignore_errors=True)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
