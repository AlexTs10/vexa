from __future__ import annotations

from flows_combined import parser
from flows_parity import PATHS


def test_combined_process_has_a_read_only_shadow_mode():
    assert parser().parse_args(["--shadow"]).shadow is True
    assert parser().parse_args([]).shadow is False


def test_parity_only_reads_safe_public_routes():
    assert PATHS == ("/health", "/.well-known/mcp-tools.json")
