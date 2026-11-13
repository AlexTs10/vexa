# Desktop behavior baseline

The desktop app must keep the complete local Vexa product. It is not a
meetings-only edition or a reduced feature set.

Before a component moves into the native app, its current behavior must have a
repeatable check. A replacement is ready only when the relevant checks pass
against both the current Compose stack and the desktop app.

## Required behavior

| Area | Required behavior | Current proof |
|---|---|---|
| Startup | The UI and API become available after one local start. | `scripts/desktop-baseline.sh` |
| Identity | A first user can claim the instance and sign in. | Terminal claim and sign-in tests |
| Settings | User and administrator settings persist through restart. | Identity and Terminal settings tests |
| Meetings | A bot can spawn, report lifecycle, stop, and preserve a recording. | `make probe` and meeting API tests |
| Transcription | A configured STT service sends live and durable transcript segments. | `make probe` in mock mode and transcription tests |
| Agents | A configured model can run chat, tools, and routines. | Agent API and worker tests |
| Flows | Events, schedules, mail, and effects remain durable and restart-safe. | Flows tests |
| MCP | A client can use the authenticated MCP endpoint. | MCP and gateway tests |
| Connections | Calendar, Git, and user credentials keep their access rules. | Credential broker and connection tests |
| Multi-user | Users, workspaces, and access boundaries remain isolated. | Identity, gateway, and workspace tests |

## Migration order

1. Keep the Compose stack as the behavior reference.
2. Use this baseline before and after every migration step.
3. Move durable local state into the desktop core first.
4. Move service behavior into the same core without changing its public
   contracts.
5. Replace the Compose launcher only after all required behavior passes from
   the desktop app.

## Local check

Run this from a checkout while the full Compose stack is running:

```zsh
scripts/desktop-baseline.sh
```

The checker also prints the memory report from `scripts/desktop-memory.py`.
The report uses the macOS physical footprint (the Activity Monitor "Memory"
value). Set `VEXA_DESKTOP_MEM_BUDGET_MB` to make the check fail above a
budget.

| Date | Layout | Host footprint |
|---|---|---|
| 2026-11-13 | Full Compose stack in Docker Desktop (16 containers) | 8778 MiB |
| 2026-11-14 | Native stack under vexa-daemon (`infra,services,ui`), transcription model unloaded | about 737 MiB |
| 2026-11-14 | The same, transcription model loaded | 1226 MiB |

The native stack is described in `apps/vexa-daemon/README.md`.

The checker validates only local availability and running service state. It
does not send a bot, call a model, or send email. Those actions need configured
external credentials and are tested by their existing integration suites.
