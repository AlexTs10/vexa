# vexa-daemon launchers

The runtime's process backend runs these once per workload:

- `vexa-bot-launch`: a meeting bot (Node + Playwright Chromium) with a private folder.
- `vexa-agent-worker`: an agent worker (`python -m worker`) with a private HOME and the pinned CLIs.
