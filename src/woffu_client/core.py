"""Woffu applet core — UI-agnostic CLI wrapper.

Exposes get_status(), sign_in(), sign_out().  No GTK/GLib imports so this
module remains testable and usable outside the applet.

Callers that care about not blocking a GUI event loop should invoke these
functions from a background thread and marshal results back to the main thread
(e.g. via GLib.idle_add in applet.py).
"""
from __future__ import annotations

import json
import subprocess

from .status import parse_json
from .status import parse_text
from .status import WoffuStatus

_CLI = "woffu-cli"
_TIMEOUT = 15


def get_status() -> WoffuStatus:
    """Return the current Woffu sign status and hours worked today."""
    try:
        result = subprocess.run(
            [
                _CLI, "--non-interactive", "--log-level", "CRITICAL",
                "get-status", "--json",
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except FileNotFoundError:
        return WoffuStatus(
            signed_in=False,
            hours_worked="00:00:00",
            error="woffu-cli not found — run: woffu-cli request-credentials",
        )
    except subprocess.TimeoutExpired:
        return WoffuStatus(
            signed_in=False,
            hours_worked="00:00:00",
            error="woffu-cli timed out",
        )

    if result.returncode != 0:
        msg = (result.stderr.strip() or result.stdout.strip() or "CLI error")
        return WoffuStatus(signed_in=False, hours_worked="00:00:00", error=msg)

    try:
        return parse_json(json.loads(result.stdout))
    except (json.JSONDecodeError, KeyError):
        # --json flag may be missing on an older installed version; fall back
        return parse_text(result.stdout + result.stderr)


def sign_in() -> None:
    """Send a sign-in request.  Skips silently if already signed in."""
    subprocess.run(
        [_CLI, "--non-interactive", "sign", "--sign-type", "in"],
        capture_output=True,
        timeout=_TIMEOUT,
    )


def sign_out() -> None:
    """Send a sign-out request.  Skips silently if already signed out."""
    subprocess.run(
        [_CLI, "--non-interactive", "sign", "--sign-type", "out"],
        capture_output=True,
        timeout=_TIMEOUT,
    )
