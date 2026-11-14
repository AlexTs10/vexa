# vexa-stt source

- `main.rs`: the HTTP routes, auth and load rules.
- `engine.rs`: the `whisper-server` child (start on demand, idle unload, model download).
- `convert.rs`: whisper.cpp output to the Vexa transcription response.
- `http.rs`, `multipart.rs`, `json.rs`: small protocol helpers with no external crates.
