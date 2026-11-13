# Terminal migration contract

The current Next.js terminal remains the production local UI until every route
below meets this contract. The Mac shell is an opt-in status page. It does not
change the current terminal.

## Route order

1. Shell: local service status and the launcher link.
2. Read-only meeting list and meeting state.
3. Transcript reader.
4. Bot start, bot state, and bot stop controls.
5. Calendar, settings, model, and account routes.
6. Agent workbench, knowledge, routines, CRM, and connections.

## Contract for each moved route

- Keep the same local user data and authorization rules.
- Use the existing gateway API until its native replacement exists.
- Keep the existing terminal route available behind a visible fallback link.
- Match loading, error, and empty states before moving the next route.
- Add a route-level test for ready, unavailable, and unauthorized states.
- Do not remove the Next.js route until the Mac route passes a full local bot
  meeting test.

## Native shell boundary

The Rust shell may only own local launch, health state, and static assets now.
It must not copy secrets into HTML, bypass gateway authorization, or call the
database directly. A later native daemon can expose a local authenticated API
on this same shell origin.
