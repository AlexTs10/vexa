"""Host launchers for the native Vexa stack (run by vexa-daemon).

Two services choose a fixed port and all interfaces in their image entry
point (crm-api: 8300, model-proxy: 8102). On the host each service needs its
own port and must listen on loopback only, so these launchers run the same
entry code on 127.0.0.1 and the port the daemon gives.

    python native_launch.py crm          # VEXA_CRM_PORT
    python native_launch.py model-proxy  # VEXA_MODEL_PROXY_PORT
    python native_launch.py connections-keys DIR

Each command runs in the service's own environment and PYTHONPATH.
"""
from __future__ import annotations

import os
import pathlib
import secrets
import sys

CONNECTION_ROLES = ("agent", "human", "git", "bots", "sensors", "signals", "store")


def crm() -> None:
    import logging

    import uvicorn
    from crm.config_preflight import preflight

    logging.basicConfig(level=logging.INFO)
    preflight()
    uvicorn.run(
        "crm.api:configured_app",
        factory=True,
        host="127.0.0.1",
        port=int(os.environ["VEXA_CRM_PORT"]),
    )


def model_proxy() -> None:
    """``control_plane.model_proxy.main`` on a loopback address and the given port."""
    import redis
    import uvicorn
    from control_plane import model_proxy as proxy
    from shared.config import load_settings

    settings = load_settings()
    client = redis.from_url(
        settings.redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=5
    )
    app = proxy.create_app(proxy.Grants(client, settings.model_proxy_secret.get_secret_value()))
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(os.environ["VEXA_MODEL_PROXY_PORT"]),
        log_level=(settings.log_level or "info").lower(),
    )


def connections_keys(root: str) -> None:
    """The Compose connections-keys job: one random key per broker role.

    Existing keys are kept. On the host every process runs as the same user,
    so each key file is readable by that user only.
    """
    for role in CONNECTION_ROLES:
        key = pathlib.Path(root, role, "key")
        key.parent.mkdir(parents=True, exist_ok=True)
        if not key.exists():
            key.write_text(secrets.token_hex(32) + "\n")
        key.chmod(0o600)


def main(argv: list[str]) -> int:
    command = argv[1] if len(argv) > 1 else ""
    if command == "crm":
        crm()
    elif command == "model-proxy":
        model_proxy()
    elif command == "connections-keys" and len(argv) == 3:
        connections_keys(argv[2])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
