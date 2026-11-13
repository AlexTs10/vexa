#!/usr/bin/env python3
"""Report the memory cost of a local Vexa desktop run.

The report has three parts:

* containers: the memory that ``docker stats`` shows for each Vexa container;
* docker host: the physical footprint of the Docker Desktop processes and its
  VM on macOS (the real host cost of all containers; the VM keeps its memory);
* native: the physical footprint of ``vexa-daemon`` and every process below it.

Physical footprint is the "Memory" value in Activity Monitor. Resident size
hides the compressed memory of the Docker VM, so it is not used.

The host total is ``docker host + native``. Container memory is inside the VM,
so it is not added again. The script is read-only.

Set ``VEXA_DESKTOP_MEM_BUDGET_MB`` to fail (exit 1) when the host total is
above a budget. Use ``--json`` for a machine-readable report.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

DEFAULT_PROJECTS = ("vexa-v012", "transcription")
NATIVE_ROOT_NAMES = ("vexa-daemon",)
DOCKER_HOST_MARKERS = (
    "com.apple.Virtualization.VirtualMachine",
    "/Applications/Docker.app/",
)
UNITS = {"B": 1, "KIB": 1024, "MIB": 1024**2, "GIB": 1024**3, "KB": 1000, "MB": 1000**2, "GB": 1000**3}


def mib(value: float) -> float:
    return round(value / 1024**2, 1)


def parse_size(text: str) -> float:
    text = text.strip().upper()
    for unit in sorted(UNITS, key=len, reverse=True):
        if text.endswith(unit):
            return float(text[: -len(unit)]) * UNITS[unit]
    return float(text or 0)


def footprints(pids: list[int]) -> dict[int, int]:
    """Physical footprint in bytes for each pid, from the macOS footprint tool."""
    if not pids or not shutil.which("footprint"):
        return {}
    args = ["footprint", "--noCategories", "-f", "bytes"]
    for pid in pids:
        args += ["-p", str(pid)]
    out = subprocess.run(args, capture_output=True, text=True).stdout
    result: dict[int, int] = {}
    current = None
    for line in out.splitlines():
        line = line.strip()
        if "[" in line and "]:" in line and "Footprint:" in line:
            current = int(line.split("[", 1)[1].split("]", 1)[0])
        elif line.startswith("phys_footprint:") and current is not None:
            result[current] = int(line.split(":", 1)[1].strip().split()[0])
            current = None
    return result


def with_footprint(rows: list[dict]) -> list[dict]:
    sizes = footprints([row["pid"] for row in rows])
    for row in rows:
        row["rss"] = sizes.get(row["pid"], row["rss"])
    return sorted(rows, key=lambda row: -row["rss"])


def processes() -> list[dict]:
    out = subprocess.run(
        ["ps", "-Ao", "pid=,ppid=,rss=,command="], capture_output=True, text=True, check=True
    ).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "rss": int(parts[2]) * 1024, "command": parts[3]})
    return rows


def native_tree(rows: list[dict]) -> list[dict]:
    roots = {
        row["pid"]
        for row in rows
        if os.path.basename(row["command"].split()[0]) in NATIVE_ROOT_NAMES
    }
    children: dict[int, list[dict]] = {}
    for row in rows:
        children.setdefault(row["ppid"], []).append(row)
    seen: dict[int, dict] = {}
    stack = [row for row in rows if row["pid"] in roots]
    while stack:
        row = stack.pop()
        if row["pid"] in seen:
            continue
        seen[row["pid"]] = row
        stack.extend(children.get(row["pid"], []))
    return sorted(seen.values(), key=lambda row: -row["rss"])


def docker_host(rows: list[dict]) -> list[dict]:
    return [row for row in rows if any(marker in row["command"] for marker in DOCKER_HOST_MARKERS)]


def containers(projects: tuple[str, ...]) -> list[dict]:
    if not shutil.which("docker"):
        return []
    result = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []
    rows = []
    for line in (result.stdout or "").splitlines():
        name, _, usage = line.partition("\t")
        if not any(name.startswith(f"{project}-") for project in projects):
            continue
        rows.append({"name": name, "bytes": parse_size(usage.split("/")[0])})
    return sorted(rows, key=lambda row: -row["bytes"])


def short(command: str) -> str:
    head = command.split()[0]
    name = os.path.basename(head)
    rest = command[len(head):].strip()
    return f"{name} {rest}"[:90].strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--project", action="append", help="compose project prefix (repeatable)")
    args = parser.parse_args()
    projects = tuple(args.project) if args.project else DEFAULT_PROJECTS

    rows = processes()
    native = with_footprint(native_tree(rows))
    host = with_footprint(docker_host(rows))
    boxes = containers(projects)

    native_total = sum(row["rss"] for row in native)
    host_total = sum(row["rss"] for row in host)
    box_total = sum(row["bytes"] for row in boxes)
    total = native_total + host_total

    report = {
        "containers_mib": mib(box_total),
        "docker_host_mib": mib(host_total),
        "native_mib": mib(native_total),
        "host_total_mib": mib(total),
        "containers": [{"name": r["name"], "mib": mib(r["bytes"])} for r in boxes],
        "native": [{"pid": r["pid"], "mib": mib(r["rss"]), "command": short(r["command"])} for r in native],
    }

    budget = os.environ.get("VEXA_DESKTOP_MEM_BUDGET_MB")
    over = budget is not None and report["host_total_mib"] > float(budget)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("━━ Vexa desktop memory ━━")
        print(f"   containers (inside Docker VM): {report['containers_mib']:>8.1f} MiB  ({len(boxes)} containers)")
        for row in report["containers"]:
            print(f"      {row['mib']:>8.1f}  {row['name']}")
        print(f"   docker host (VM + Docker app): {report['docker_host_mib']:>8.1f} MiB")
        print(f"   native (vexa-daemon tree):     {report['native_mib']:>8.1f} MiB  ({len(native)} processes)")
        for row in report["native"]:
            print(f"      {row['mib']:>8.1f}  {row['command']}")
        print(f"   HOST TOTAL:                    {report['host_total_mib']:>8.1f} MiB")
        if budget is not None:
            print(f"   budget: {budget} MiB — {'OVER' if over else 'within'}")
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
