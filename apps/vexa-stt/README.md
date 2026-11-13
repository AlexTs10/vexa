# vexa-stt

`vexa-stt` is the Vexa transcription service as a native macOS process. It
serves the contract of `core/meetings/services/transcription`, so callers keep
`TRANSCRIPTION_SERVICE_URL` and `TRANSCRIPTION_SERVICE_TOKEN` unchanged:

- `POST /v1/audio/transcriptions`: OpenAI-compatible multipart (`file` and
  `model` required; `language`, `prompt`, `temperature`, `response_format`,
  `timestamp_granularities`, `task` optional). The answer has the Python
  service's shape: `text`, `language` (a code), `language_probability`,
  `duration`, and `segments` with `avg_logprob`, `compression_ratio`,
  `no_speech_prob` and `words` when word timestamps are requested.
- `GET /health`: 200 with `model` while the model file is on disk, also when
  the model is not loaded.
- `GET /`: service information.

Auth is `Authorization: Bearer <token>` or `X-API-Key`. A busy service answers
503 with `Retry-After: 1` (fail fast, `MAX_ACTIVE_REQUESTS`, default 2); a
request over `TRANSCRIPTION_TIMEOUT_S` (default 120) answers 504. Silence
answers an empty `text`, with the Python service's silence rule.

## Engine

The engine is whisper.cpp (`whisper-server`, MIT) with Metal. `vexa-stt` starts
it on the first request and stops it after `VEXA_STT_IDLE_SEC` (default 300)
without a request, so the model memory is free when there is no meeting. The
decoding settings follow the Python service: beam size 5, best of 5, no
temperature fallback, no-speech threshold 0.6, log-probability threshold -1,
Silero VAD (threshold 0.5, minimum silence 160 ms, maximum speech 15 s), and
segments split on word boundaries.

The model is `VEXA_STT_MODEL` (default `small-q8_0`, the nearest match to the
Compose CPU worker's `small` with int8). The first start downloads it and the
Silero VAD model into `VEXA_STT_MODEL_DIR`.

## Settings

| Variable | Default |
|---|---|
| `VEXA_STT_PORT` | 23083 |
| `VEXA_STT_ENGINE_PORT` | port + 1 |
| `TRANSCRIPTION_SERVICE_TOKEN` (or `API_TOKEN`) | empty: every request is allowed |
| `VEXA_STT_MODEL` | `small-q8_0` |
| `VEXA_STT_MODEL_DIR` | `~/Library/Application Support/Vexa/data/models` |
| `VEXA_STT_IDLE_SEC` | 300 |
| `VEXA_STT_THREADS` | 4 |
| `VEXA_WHISPER_SERVER` | `whisper-server` on `PATH` (`brew install whisper-cpp`) |
| `VEXA_STT_ENGINE_LOG` | none |

`vexa-daemon` runs `vexa-stt` in its `infra` group unless `native.env` sets
`TRANSCRIPTION_SERVICE_URL` (another service).

## Parity

Measured on 2026-11-13 (Apple M3) against the Compose CPU worker
(faster-whisper `small`, int8), with the same clips:

| Check | Compose | vexa-stt |
|---|---|---|
| 17.7 s English, WAV | 4.88 s | 1.15 s |
| 17.7 s English, FLAC | 8.09 s | 2.85 s (includes the model load) |
| German, no language given | `de` 0.99 | `de` 0.99, same text |
| 3 s silence | `""` | `""` |
| Wrong token / 4 parallel requests | 401 / 200, 200, 503, 503 | the same |
| Top-level and segment JSON keys | | the same |
| Memory, model loaded | 717 MiB (container) | 488 MiB (`whisper-server`) + 1 MiB |

The English texts have the same words; the punctuation can differ.
