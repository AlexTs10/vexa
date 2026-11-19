# apps

Native macOS parts of the local Vexa desktop app, written in Rust.

- `vexa-mac`: the app launcher (`Vexa.app`). It starts the daemon and opens the local shell.
- `vexa-daemon`: the local control plane. It runs the whole Vexa stack as host processes, with no Docker,
  and serves the runtime (runtime.v1, schedule.v1) itself.
- `vexa-stt`: the transcription service on whisper.cpp with Metal.
- `vexa-credential-broker`: the Connections credential broker (credential-broker.v1).
- `vexa-mcp`: the MCP edge (mcp.tools.v1, the streamable-HTTP MCP transport at `/mcp`).
- `vexa-native-kit`: JSON, HTTP, SHA-256, id, log-line and Python-compatible JSON code that `vexa-daemon`,
  `vexa-stt`, `vexa-credential-broker` and `vexa-mcp` share.
- `vexa-automation`: a control surface for a future native automation engine. It does no work yet.

The migration plan and the behavior baseline are in `desktop/`.
