"""Woffu status model and parsers.

Pure functions and data types — no I/O, no GTK.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class WoffuStatus:
    """Current Woffu sign state, as rendered by the applet."""

    signed_in: bool
    hours_worked: str
    theoretical_hours: str | None = None
    error: str | None = None


def parse_json(data: dict) -> WoffuStatus:
    """Build a WoffuStatus from a `woffu-cli get-status --json` payload."""
    return WoffuStatus(
        signed_in=data.get("signed_in", False),
        hours_worked=data.get("hours_worked", "00:00:00"),
        theoretical_hours=data.get("theoretical_hours"),
        error=data.get("error"),
    )


def parse_text(text: str) -> WoffuStatus:
    """Fallback: keyword-match the plain-text output of `woffu-cli get-status`.

    Used when the --json flag is unavailable (older CLI versions).
    Lines look like:
        [...] INFO woffu_api_client: Hours worked today: HH:MM:SS
        [...] INFO woffu_api_client: You're currently signed in.
    """
    signed_in = "signed in" in text
    hours_worked = "00:00:00"
    for line in text.splitlines():
        if "Hours worked today:" in line:
            hours_worked = line.split("Hours worked today:")[-1].strip()
            break
    return WoffuStatus(signed_in=signed_in, hours_worked=hours_worked)
