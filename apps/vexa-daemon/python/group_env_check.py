"""List the settings that one core group member sets and another member's code names.

In a process group every member reads the union of the members' settings. A
setting that only one member sets can change another member that reads the
same name. This check finds those names for a review:

    vexa-daemon specs | python group_env_check.py

The input is one JSON object per line (``{"name": ..., "env": {...}}``). Each
member's code is its image layout under
``~/Library/Application Support/Vexa/runtime/apps``. The match is by name in
the source text, so a result can be a comment; read each one.
"""
from __future__ import annotations

import json
import os
import re
import sys

APPS = os.path.expanduser("~/Library/Application Support/Vexa/runtime/apps")
#: Settings that each member sets for itself; the group sets its own values.
PER_PROCESS = {"HOST", "PORT", "PATH", "PYTHONPATH"}
NAME = re.compile(r"[A-Z][A-Z0-9_]{2,}")


def names_in(tree: str) -> set[str]:
    found: set[str] = set()
    for root, dirs, files in os.walk(os.path.join(APPS, tree, "app"), followlinks=True):
        dirs[:] = [d for d in dirs if d not in {"tests", "__pycache__", ".venv", "node_modules"}]
        for file in files:
            if file.endswith(".py"):
                with open(os.path.join(root, file), errors="ignore") as handle:
                    found |= set(NAME.findall(handle.read()))
    return found


def main() -> int:
    members = [json.loads(line) for line in sys.stdin if line.strip()]
    setters: dict[str, list[str]] = {}
    for member in members:
        for key in member["env"]:
            setters.setdefault(key, []).append(member["name"])
    leaks = 0
    for member in members:
        names = names_in(member["name"])
        for key in sorted(names & setters.keys()):
            if key in PER_PROCESS or key in member["env"] or (key.startswith("VEXA_") and key.endswith("_PORT")):
                continue
            print(f"{key}: set by {', '.join(setters[key])}; named by {member['name']}")
            leaks += 1
    print(f"{leaks} setting(s) to review", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
