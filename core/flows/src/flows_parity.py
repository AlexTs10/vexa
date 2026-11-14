"""Read-only parity probe for the desktop combined Flows API."""
from __future__ import annotations

import json
import sys
from urllib.request import urlopen

import flows_config as cfg


PATHS = ("/health", "/.well-known/mcp-tools.json")


def read_json(base_url: str, path: str) -> object:
    with urlopen(f"{base_url.rstrip('/')}{path}", timeout=3) as response:  # nosec B310: local compose URLs
        if response.status != 200:
            raise RuntimeError(f"{base_url}{path} returned HTTP {response.status}")
        return json.loads(response.read())


def compare(old_url: str, new_url: str) -> list[str]:
    failures: list[str] = []
    for path in PATHS:
        old = read_json(old_url, path)
        new = read_json(new_url, path)
        if old != new:
            failures.append(path)
    return failures


def main() -> int:
    old_url = cfg.get("VEXA_FLOWS_LEGACY_URL")
    new_url = cfg.get("VEXA_FLOWS_SHADOW_URL")
    failures = compare(old_url, new_url)
    if failures:
        print(f"flows parity failed: {', '.join(failures)}", file=sys.stderr)
        return 1
    print("flows parity passed: health and MCP manifest match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
