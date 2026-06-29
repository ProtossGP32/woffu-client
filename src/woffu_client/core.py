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
from pathlib import Path

from .status import parse_json
from .status import parse_text
from .status import WoffuStatus

_CLI = "woffu-cli"
_TIMEOUT = 15

# Where woffu-client caches credentials. Used only to tell a "not configured"
# state apart from a genuine runtime error — never read or written here.
_CONFIG_FILE = Path.home() / ".config/woffu/woffu_auth.json"
_NOT_CONFIGURED_MSG = "Not configured — run: woffu-cli request-credentials"


def _is_configured() -> bool:
    """Return True if the CLI has a credentials file to work with."""
    return _CONFIG_FILE.exists()


def _error_status(message: str) -> WoffuStatus:
    """Wrap a CLI failure as a status, flagging the not-configured case.

    Crucially this never returns signed_in=False *silently*: a failed status
    check always carries an error, so the applet can't mistake it for a real
    signed-out state.
    """
    if not _is_configured():
        return WoffuStatus(
            signed_in=False,
            hours_worked="00:00:00",
            error=_NOT_CONFIGURED_MSG,
            configured=False,
        )
    return WoffuStatus(signed_in=False, hours_worked="00:00:00", error=message)


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
            error="woffu-cli not found — is woffu-client installed?",
        )
    except subprocess.TimeoutExpired:
        return WoffuStatus(
            signed_in=False,
            hours_worked="00:00:00",
            error="woffu-cli timed out",
        )

    stdout = result.stdout.strip()

    # The CLI emits JSON on both success and structured failure ({"error": …}).
    # Parse it regardless of return code so a failure is never silently read
    # as a signed-out status.
    if stdout:
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            data = None
        if data is not None:
            if data.get("error"):
                return _error_status(str(data["error"]))
            return parse_json(data)

    if result.returncode != 0:
        return _error_status(result.stderr.strip() or "woffu-cli error")

    # Return code 0 but non-JSON stdout: older CLI without --json. Fall back to
    # keyword-matching its text output.
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
