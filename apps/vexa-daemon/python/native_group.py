"""Run several Vexa services in one Python process (a native process group).

Each service keeps its own app builder, routes, lifespan and port. The
services share one interpreter and one event loop, so their common libraries
load once. This lowers the memory of the native Mac stack.

    python native_group.py core    # admin-api, meeting-api, gateway (+ door), mcp,
                                   # credential-broker, crm, flows (+ worker)
    python native_group.py agent   # agent-api, model-proxy

Ports come from ``VEXA_<SERVICE>_PORT``. All listeners use 127.0.0.1.
mcp asks every domain for its tools when it is built, so the core group
builds it last, after each URL in ``VEXA_NATIVE_MCP_WAIT_URLS`` answers 200.
The flows worker loop runs on its own thread in the core group.

The process stops all listeners on SIGINT or SIGTERM, and exits with code 1
when one listener stops by itself, so the daemon restarts the whole group.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
import threading
import urllib.request
from typing import Any, Callable, Coroutine

import uvicorn

log = logging.getLogger("vexa.native_group")
HOST = "127.0.0.1"


class Listener(uvicorn.Server):
    """A uvicorn server that leaves signal handling to the group."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield

    def install_signal_handlers(self) -> None:  # uvicorn < 0.29
        return None


def port(name: str) -> int:
    return int(os.environ[f"VEXA_{name}_PORT"])


def listener(app, port_number: int) -> Listener:
    level = os.getenv("LOG_LEVEL", "info").lower()
    return Listener(uvicorn.Config(app, host=HOST, port=port_number, log_level=level))


# ─── gateway side ──────────────────────────────────────────────────────────────────


def gateway_side_now() -> list[tuple[str, Listener]]:
    from admin_api.__main__ import build_production_app as admin_app
    from gateway.adapters import build_production_app as gateway_app
    from gateway.adapters import load_signing_key
    from gateway.service_door import build_door_app, door_port
    from meeting_api.__main__ import build_production_app as meeting_app

    door = build_door_app(identity_key=load_signing_key(os.getenv("VEXA_GATEWAY_IDENTITY_SIGNING_KEY_FILE", "")))
    return [
        ("admin-api", listener(admin_app(), port("ADMIN_API"))),
        ("meeting-api", listener(meeting_app(), port("MEETING_API"))),
        ("gateway", listener(gateway_app(), port("GATEWAY"))),
        ("gateway-door", listener(door, door_port())),
    ]


def _answers(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.status == 200
    except Exception:  # noqa: BLE001 -- any failure means "not yet"
        return False


async def mcp_later() -> list[tuple[str, Listener]]:
    urls = [u for u in os.getenv("VEXA_NATIVE_MCP_WAIT_URLS", "").split(",") if u]
    loop = asyncio.get_running_loop()
    while True:
        waiting = [u for u in urls if not await loop.run_in_executor(None, _answers, u)]
        if not waiting:
            break
        log.info("mcp waits for %s", ", ".join(waiting))
        await asyncio.sleep(2)
    from vexa_mcp.app import create_app

    for attempt in range(1, 21):
        try:
            app = await loop.run_in_executor(None, create_app)
            return [("mcp", listener(app, port("MCP")))]
        except Exception as error:  # noqa: BLE001 -- a domain may still be starting
            log.warning("mcp build attempt %d failed: %s", attempt, error)
            await asyncio.sleep(3)
    raise RuntimeError("mcp could not assemble its tools")


# ─── agent ─────────────────────────────────────────────────────────────────


def agent_now() -> list[tuple[str, Listener]]:
    import redis
    from control_plane import api as agent_api
    from control_plane import model_proxy as proxy
    from shared.config import load_settings

    settings = load_settings()
    client = redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=5)
    proxy_app = proxy.create_app(proxy.Grants(client, settings.model_proxy_secret.get_secret_value()))
    return [
        ("agent-api", listener(agent_api.app, port("AGENT_API"))),
        ("model-proxy", listener(proxy_app, port("MODEL_PROXY"))),
    ]


async def nothing_later() -> list[tuple[str, Listener]]:
    return []

# ─── core ──────────────────────────────────────────────────────────────────


def broker_now() -> list[tuple[str, Listener]]:
    # build_app sets umask 077 for the whole process: every file the group writes is private.
    from credential_broker.main import build_app

    return [("credential-broker", listener(build_app(), port("CREDENTIAL_BROKER")))]


def crm_now() -> list[tuple[str, Listener]]:
    from crm.api import configured_app
    from crm.config_preflight import preflight

    preflight()
    return [("crm", listener(configured_app(), port("CRM")))]


def flows_now() -> list[tuple[str, Listener]]:
    from flows_integrations import flows_api

    flows_api.boot()
    return [("flows", listener(flows_api.app, int(os.environ["VEXA_FLOWS_API_PORT"])))]


def core_now() -> list[tuple[str, Listener]]:
    return broker_now() + gateway_side_now() + crm_now() + flows_now()


def flows_worker() -> asyncio.Future:
    """The flows worker loop on a daemon thread; the future ends when the loop ends."""
    from flows_worker import __main__ as worker

    loop = asyncio.get_running_loop()
    ended: asyncio.Future = loop.create_future()

    def run() -> None:
        try:
            code = worker.main()
            error = RuntimeError(f"flows worker returned {code}")
        except BaseException as exc:  # noqa: BLE001 -- the group reports any end of the loop
            error = exc
        loop.call_soon_threadsafe(lambda: ended.done() or ended.set_exception(error))

    threading.Thread(target=run, name="flows-worker", daemon=True).start()
    return ended


WORKERS: dict[str, Callable[[], list]] = {
    "core": lambda: [("flows-worker", flows_worker())],
}


GROUPS: dict[str, tuple[Callable[[], list], Callable[[], Coroutine[Any, Any, list]]]] = {
    "core": (core_now, mcp_later),
    "agent": (agent_now, nothing_later),
}


async def run(group: str) -> int:
    build_now, build_later = GROUPS[group]
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    servers: list[tuple[str, Listener]] = []
    tasks: dict[asyncio.Task, str] = {}

    def start(named: list[tuple[str, Listener]]) -> None:
        for name, server in named:
            servers.append((name, server))
            tasks[asyncio.create_task(server.serve(), name=name)] = name
            log.info("%s listens on %s:%s", name, HOST, server.config.port)

    start(build_now())
    workers = {future: name for name, future in (WORKERS.get(group, lambda: [])())}
    later = asyncio.create_task(build_later(), name="later")
    stopper = asyncio.create_task(stop.wait(), name="stop")
    code = 0
    while True:
        done, _ = await asyncio.wait([*tasks, *workers, later, stopper], return_when=asyncio.FIRST_COMPLETED)
        if stopper in done:
            break
        if later in done:
            if later.exception() is not None:
                log.error("%s group: %s", group, later.exception())
                code = 1
                break
            start(later.result())
            later = asyncio.create_task(asyncio.Event().wait(), name="idle")
            continue
        ended = [tasks.get(t) or workers.get(t) for t in done if t in tasks or t in workers]
        for future in done:
            if future in workers and future.exception() is not None:
                log.error("%s: %r", workers[future], future.exception())
        log.error("%s stopped by itself; stopping the %s group", ", ".join(ended), group)
        code = 1
        break
    for _, server in servers:
        server.should_exit = True
    later.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    return code


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in GROUPS:
        print(__doc__, file=sys.stderr)
        return 2
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return asyncio.run(run(argv[1]))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
