# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this project is

A GNOME top-bar applet that lets the user sign in / sign out of Woffu in a couple
of clicks. It is a **thin front-end over the existing `woffu-cli`**. This is a
fork of `woffu-client`, and the applet lives **inside the same `woffu_client`
package** (`src/woffu_client/applet.py`, `core.py`, `status.py`) alongside the
CLI it drives. The applet does not talk to Woffu directly.

```text
woffu_client.applet → woffu-cli → Woffu backend
```

**Core principle: reuse, don't reimplement.** Auth, token caching, and HTTP all
live in `woffu_client` (the CLI/API client in this same package). The applet only
adds the GTK front-end and a thin wrapper around the CLI. Never add new HTTP
requests to Woffu, token handling, or login logic in the applet layers.

## Architecture

Three layers under `src/woffu_client/`, kept strictly separated:

- `core.py` — UI-agnostic wrapper. Exposes `sign_in()`, `sign_out()`,
  `get_status()`. Shells out to `woffu-cli` (stable contract) and parses its
  `--json` output via `status.py`. Uses synchronous `subprocess.run`; the applet
  is responsible for calling these off the main loop (see Conventions). This layer
  has no GTK imports, so it stays testable and reusable.
- `status.py` — the `WoffuStatus` model plus `parse_json()` (the `--json` path)
  and `parse_text()` (keyword-match fallback for older CLIs). Pure functions, no
  I/O. This is the main thing covered by tests.
- `applet.py` — GTK 3 + AppIndicator front-end. Builds the indicator and menu,
  reacts to user clicks, and renders state. No business logic beyond presentation.

When adding a feature, put logic in `core`/`status` and keep `applet` thin.

## Commands

```bash
# Run the applet (installed entry point, or module form)
woffu-applet
python3 -m woffu_client.applet

# One-time setup of the CLI this app drives
woffu-cli request-credentials

# Verify the CLI contracts the applet depends on
woffu-cli sign -h
woffu-cli get-status --json

# Tests (pure logic, no GTK / no network)
pytest

# Lint / format (match woffu-client's choices: PEP8 via pre-commit)
ruff check . && ruff format .
```

## Dependencies

- Runtime: Python 3, `woffu-client`, PyGObject (GTK 3), an AppIndicator binding.
- AppIndicator binding: import `AyatanaAppIndicator3` first, fall back to legacy
  `AppIndicator3`. Always keep that fallback — distros ship one or the other.
- System packages (not pip): `python3-gi` and the GIR for AppIndicator. On Fedora,
  GNOME also needs the `gnome-shell-extension-appindicator` extension enabled.

## Conventions

- **Never block the GLib main loop.** `core.py` calls the CLI with synchronous
  `subprocess.run`, so the applet must run every `core` call in a **daemon
  thread** (`threading.Thread(..., daemon=True)`) and never call it directly from
  a signal handler or timer. A slow network call must never freeze the GNOME panel.
- UI updates happen on the main loop. Worker threads marshal results back with
  `GLib.idle_add` — never touch GTK widgets from a thread.
- Status is re-checked on a `GLib.timeout_add_seconds` timer and after every
  sign action, so the icon reflects reality.
- Icon names come from the Adwaita symbolic set (e.g. `user-available-symbolic`,
  `user-offline-symbolic`). Don't bundle custom icons unless necessary.
- Keep `core`/`status` free of any `gi`/GTK imports.

## CLI contracts (verified against the installed version)

Both `woffu-cli` details the applet depends on have been confirmed:

1. **Sign flag** — `woffu-cli sign --sign-type in|out|any` (default `any`).
   Confirmed via `woffu-cli sign -h`; `core.py` uses `in`/`out`.
2. **Status output** — `woffu-cli get-status --json` (added in this fork) emits
   `{"signed_in": bool, "hours_worked": "HH:MM:SS", "theoretical_hours":
   "HH:MM:SS"|null}` with logs suppressed. `status.parse_json()` consumes it;
   `status.parse_text()` remains as a keyword-match fallback for older CLIs that
   lack `--json`.

Other notes:

- First run with no credentials: `get-status` will fail. Surface this as a clear
  "not configured" state pointing the user to `woffu-cli request-credentials`,
  rather than crashing.
- The applet only appears in GNOME if the AppIndicator extension is active.

## Security

- `woffu-client` currently stores credentials/token in a plaintext JSON file
  (`~/.config/woffu/woffu_auth.json`). Do not copy secrets into this repo, logs,
  or test fixtures.
- A planned improvement is to move secrets into the system keyring (`keyring` /
  libsecret). Prefer that over any new plaintext storage.

## Do / Don't

- ✅ Add features in `core`/`status`; keep `applet` presentational.
- ✅ Run every `core` CLI call from a daemon thread; marshal back with `GLib.idle_add`.
- ✅ Write tests for `status.py` and `core.py` logic.
- ❌ Don't implement Woffu auth or HTTP in the applet layers — drive `woffu-cli`.
- ❌ Don't call `core` (synchronous `subprocess.run`) directly on the main loop.
- ❌ Don't touch GTK widgets from a worker thread.
- ❌ Don't commit credentials, tokens, or real user data.
