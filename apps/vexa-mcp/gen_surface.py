#!/usr/bin/env python3
"""Write src/surface.json: the Python mcp's own surface — its 18 tools as fastapi-mcp derives them,
the connect-time instructions and the four prompts.

    cd core/gateway/services/mcp
    .venv/bin/python ../../../../apps/vexa-mcp/gen_surface.py

Each entry of "tools" is one built-in route: the MCP tool (name, description, inputSchema, before the edge
closes it with additionalProperties) and the operation the tool call replays (method, path, its
parameters and its resolved JSON body schema). The Rust service compiles the file in; parity.py
and the cargo test check that the two surfaces stay one.
"""
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "core" / "gateway" / "services" / "mcp" / "src"))
os.environ["VEXA_FEATURES"] = "all"

from fastapi_mcp.openapi.utils import resolve_schema_references  # noqa: E402
from vexa_mcp.app import VEXA_INSTRUCTIONS, create_app  # noqa: E402
from vexa_mcp.prompts import PROMPTS, get_prompt_result  # noqa: E402

app = create_app("http://gateway.invalid", assembly_env={"VEXA_MCP_ASSEMBLY_OFF": "1"})
mcp = app.state.mcp
openapi = app.openapi()
out = []
for tool in mcp.tools:
    op = mcp.operation_map[tool.name]
    spec = resolve_schema_references(openapi["paths"][op["path"]][op["method"]], openapi)
    body = spec.get("requestBody")
    schema = dict(tool.inputSchema)
    schema.pop("additionalProperties", None)
    out.append({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": schema,
        "method": op["method"].upper(),
        "path": op["path"],
        "parameters": [{"name": p["name"], "in": p["in"], "required": p.get("required", False),
                        "schema": p.get("schema", {})} for p in spec.get("parameters", [])],
        "body": body["content"]["application/json"]["schema"] if body else None,
        "body_required": bool(body and body.get("required")),
    })
surface = {
    "instructions": VEXA_INSTRUCTIONS,
    "prompts": [p.model_dump(by_alias=True, exclude_none=True) for p in PROMPTS.values()],
    # Each prompt's result with every argument written as NUL<name>NUL: the Rust side puts the
    # caller's stripped value (or the prompt's own fallback) in its place.
    "prompt_results": {
        name: get_prompt_result(name, {a.name: f"\0{a.name}\0" for a in (p.arguments or [])})
        .model_dump(by_alias=True, exclude_none=True, mode="json")
        for name, p in PROMPTS.items()
    },
    "tools": out,
}
text = json.dumps(surface, indent=1, ensure_ascii=False) + "\n"
(HERE / "src" / "surface.json").write_text(text, encoding="utf-8")
print(f"{len(out)} built-in tools")
