# apps

Native macOS parts of the local Vexa desktop app, written in Rust.

- `vexa-mac`: the app launcher (`Vexa.app`). It starts the daemon and opens the local shell.
- `vexa-daemon`: the local control plane. It runs the whole Vexa stack as host processes, with no Docker.
- `vexa-stt`: the transcription service on whisper.cpp with Metal.
- `vexa-automation`: a control surface for a future native automation engine. It does no work yet.

The migration plan and the behavior baseline are in `desktop/`.
