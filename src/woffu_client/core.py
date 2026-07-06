"""Woffu applet core — UI-agnostic wrapper around WoffuAPIClient.

Exposes get_status(), sign_in(), sign_out().  No GTK/GLib imports so this
module remains testable and usable outside the applet.

Callers that care about not blocking a GUI event loop should invoke these
functions from a background thread and marshal results back to the main thread
(e.g. via GLib.idle_add in applet.py).
"""
from __future__ import annotations

from pathlib import Path

from .status import from_client_result
from .status import WoffuStatus
from .woffu_api_client import WoffuAPIClient

# Where woffu-client caches credentials. Checked *before* constructing a
# WoffuAPIClient: its constructor loads this file itself, and when it's
# missing the constructor falls back to requesting credentials (prompting,
# or sys.exit in non-interactive mode) — never what we want from the applet.
_CONFIG_FILE = Path.home() / ".config/woffu/woffu_auth.json"
_NOT_CONFIGURED_MSG = "Not configured — run: woffu-cli request-credentials"


def _is_configured() -> bool:
    """Return True if a credentials file exists to load."""
    return _CONFIG_FILE.exists()


def _client() -> WoffuAPIClient:
    """Build a client from cached credentials, non-interactively."""
    return WoffuAPIClient(interactive=False, log_level="CRITICAL")


def _error_status(message: str) -> WoffuStatus:
    """Wrap a failure as a status, flagging the not-configured case.

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
    if not _is_configured():
        return _error_status(_NOT_CONFIGURED_MSG)
    try:
        total_time, signed_in, theoretical_time = _client().get_status(
            extend=True,
        )
    except Exception as e:
        return _error_status(str(e))
    return from_client_result(total_time, signed_in, theoretical_time)


def sign_in() -> None:
    """Send a sign-in request.  Skips silently if already signed in."""
    _sign("in")


def sign_out() -> None:
    """Send a sign-out request.  Skips silently if already signed out."""
    _sign("out")


def _sign(sign_type: str) -> None:
    """Best-effort sign request; failures surface on the next get_status()."""
    if not _is_configured():
        return
    try:
        _client().sign(type=sign_type)
    except Exception:
        pass
