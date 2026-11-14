# apps

Native macOS parts of the local Vexa desktop app, written in Rust.

- `vexa-mac`: the app launcher (`Vexa.app`). It starts the daemon and opens the local shell.
- `vexa-daemon`: the local control plane. It runs the whole Vexa stack as host processes, with no Docker,
  and serves the runtime (runtime.v1, schedule.v1) itself.
- `vexa-stt`: the transcription service on whisper.cpp with Metal.
- `vexa-native-kit`: JSON, HTTP and SHA-256 code that `vexa-daemon` and `vexa-stt` share.
- `vexa-automation`: a control surface for a future native automation engine. It does no work yet.

The migration plan and the behavior baseline are in `desktop/`.
