# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this project is

A GNOME top-bar applet that lets the user sign in / sign out of Woffu in a couple
of clicks. It is a **thin front-end over `WoffuAPIClient`**, the API client that
also backs `woffu-cli`. This is a fork of `woffu-client`, and the applet lives
**inside the same `woffu_client` package** (`src/woffu_client/applet.py`,
`core.py`, `status.py`) alongside the CLI and the client they both drive.

```text
woffu_client.applet ─┐
                      ├─→ WoffuAPIClient → Woffu backend
woffu_client.cli    ─┘
```

**Core principle: reuse, don't reimplement.** Auth, token caching, and HTTP all
live in `WoffuAPIClient` (`woffu_api_client.py`, in this same package). The
applet only adds the GTK front-end and a thin wrapper around that class. Never
add new HTTP requests to Woffu, token handling, or login logic in the applet
layers — call `WoffuAPIClient` methods instead.

## Architecture

Three layers under `src/woffu_client/`, kept strictly separated:

- `core.py` — UI-agnostic wrapper. Exposes `sign_in()`, `sign_out()`,
  `get_status()`. Imports `WoffuAPIClient` directly and calls its
  `get_status()`/`sign()` methods (no subprocess, no `woffu-cli` dependency);
  converts the result via `status.from_client_result()`. The applet is
  responsible for calling these off the main loop (see Conventions), since
  `WoffuAPIClient` makes synchronous network calls. This layer has no GTK
  imports, so it stays testable and reusable.
- `status.py` — the `WoffuStatus` model plus `from_client_result()` (builds a
  status from a `WoffuAPIClient.get_status()` result) and `format_timedelta()`.
  Pure functions, no I/O. Shared by `core.py` and by `cli.py`'s `--json` output
  so the HH:MM:SS formatting lives in one place. This is the main thing covered
  by tests.
- `applet.py` — GTK 3 + AppIndicator front-end. Builds the indicator and menu,
  reacts to user clicks, and renders state. No business logic beyond presentation.

When adding a feature, put logic in `core`/`status` and keep `applet` thin.

`core.py` builds its own non-interactive `WoffuAPIClient(interactive=False)` and
always checks credentials exist (`~/.config/woffu/woffu_auth.json`) *before*
constructing it — `WoffuAPIClient.__init__` loads that file itself and, if it's
missing, falls back to requesting credentials (prompting interactively, or
`sys.exit` non-interactively), which the applet must never trigger.

## Commands

```bash
# Run the applet (installed entry point, or module form).
# Needs a Python that has PyGObject: a plain pip venv without system gi fails
# to import 'gi'. Use the distro python3-gi (e.g. a venv created with
# --system-site-packages, or the system python).
woffu-applet
python3 -m woffu_client.applet

# One-time setup: populates ~/.config/woffu/woffu_auth.json, which core.py
# also relies on directly (see Architecture)
woffu-cli request-credentials

# Tests + coverage (pure logic, no GTK / no network) — same invocation as
# README.md, enforced on PRs (>= 80% coverage)
pytest -v --maxfail=1 --disable-warnings --junitxml coverage/report.xml \
  --cov-report term --cov-report xml:coverage/coverage.xml --cov=. tests

# Lint / format: this project uses pre-commit (PEP8 plus Markdown/config
# linting), not a standalone ruff invocation — see README.md's Contributing
# section.
pre-commit run --all-files
```

## Dependencies

- Runtime: Python 3, `woffu-client`, PyGObject (GTK 3), an AppIndicator binding.
- AppIndicator binding: import `AyatanaAppIndicator3` first, fall back to legacy
  `AppIndicator3`. Always keep that fallback — distros ship one or the other.
- System packages (not pip): `python3-gi` and the GIR for AppIndicator. On Fedora,
  GNOME also needs the `gnome-shell-extension-appindicator` extension enabled.

## Conventions

- **Never block the GLib main loop.** `core.py` calls `WoffuAPIClient` methods,
  which make synchronous network requests, so the applet must run every `core`
  call in a **daemon thread** (`threading.Thread(..., daemon=True)`) and never
  call it directly from a signal handler or timer. A slow network call must
  never freeze the GNOME panel.
- UI updates happen on the main loop. Worker threads marshal results back with
  `GLib.idle_add` — never touch GTK widgets from a thread.
- Status is re-checked on a `GLib.timeout_add_seconds` timer and after every
  sign action, so the icon reflects reality.
- The applet ships a bundled Woffu brand icon at `src/woffu_client/icons/woffu.svg`,
  loaded with `Indicator.new_with_path`. The same icon is used for every state;
  the menu's status line conveys signed-in / out / error / not-configured. Swap
  that file to change the icon (keep it square and simple so it reads at panel
  size); declare new icon files under `[tool.setuptools.package-data]`.
- Keep `core`/`status` free of any `gi`/GTK imports.

## WoffuAPIClient contract that core.py depends on

- **`sign(type="in"|"out"|"any")`** (default `"any"`) — `core.py` uses `in`/`out`.
- **`get_status(extend=True)`** — returns a `(total_time: timedelta, signed_in:
  bool, theoretical_time: timedelta)` tuple; `status.from_client_result()`
  converts it into a `WoffuStatus`. Changing this return shape is a breaking
  change for both `core.py` and `cli.py` — coordinate any change there with a
  PR discussion first (see PR #54 review) rather than doing it silently.
- `woffu-cli get-status --json` (used by scripts/automation, not by the
  applet) emits `{"signed_in": bool, "hours_worked": "HH:MM:SS",
  "theoretical_hours": "HH:MM:SS"|null}`, built with the same
  `from_client_result()` helper so the two never drift.

Other notes:

- First run with no credentials: constructing `WoffuAPIClient` would normally
  request credentials itself (prompting, or `sys.exit` non-interactively).
  `core.py` checks for `~/.config/woffu/woffu_auth.json` *before* constructing
  the client and short-circuits to a clear "not configured" state pointing the
  user to `woffu-cli request-credentials`, rather than crashing or prompting.
- The applet only appears in GNOME if the AppIndicator extension is active.
- Runtime-verified on GNOME: the indicator renders, and Sign in / Sign out drive
  real Woffu state. Refresh re-queries status too, but because one icon serves
  all states it produces no icon change — its result shows in the menu's status
  line the next time the menu is opened (clicking a menu item closes the menu).

## Security

- `woffu-client` currently stores credentials/token in a plaintext JSON file
  (`~/.config/woffu/woffu_auth.json`). Do not copy secrets into this repo, logs,
  or test fixtures.
- A planned improvement is to move secrets into the system keyring (`keyring` /
  libsecret). Prefer that over any new plaintext storage.

## Do / Don't

- ✅ Add features in `core`/`status`; keep `applet` presentational.
- ✅ Run every `core` call from a daemon thread; marshal back with `GLib.idle_add`.
- ✅ Write tests for `status.py` and `core.py` logic.
- ❌ Don't implement Woffu auth or HTTP in the applet layers — call
  `WoffuAPIClient` methods from `core.py` instead.
- ❌ Don't call `core` (synchronous network calls) directly on the main loop.
- ❌ Don't touch GTK widgets from a worker thread.
- ❌ Don't commit credentials, tokens, or real user data.
