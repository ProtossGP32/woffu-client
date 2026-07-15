"""Woffu status model and formatting.

Pure functions and data types — no I/O, no GTK.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta


@dataclass
class WoffuStatus:
    """Current Woffu sign state, as rendered by the applet.

    `configured` is False when there are no usable credentials yet, so the
    applet can show an actionable "run request-credentials" hint instead of a
    misleading signed-out state.
    """

    signed_in: bool
    hours_worked: str
    theoretical_hours: str | None = None
    error: str | None = None
    configured: bool = True


def format_timedelta(delta: timedelta) -> str:
    """Format a timedelta as HH:MM:SS."""
    hours, rem = divmod(int(delta.total_seconds()), 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def from_client_result(
    total_time: timedelta, signed_in: bool, theoretical_time: timedelta,
) -> WoffuStatus:
    """Build a WoffuStatus from a `WoffuAPIClient.get_status()` result.

    Shared by core.py (applet) and cli.py (`get-status --json`) so the
    HH:MM:SS formatting lives in one place.
    """
    theoretical_hours = (
        format_timedelta(theoretical_time)
        if theoretical_time.total_seconds() > 0
        else None
    )
    return WoffuStatus(
        signed_in=signed_in,
        hours_worked=format_timedelta(total_time),
        theoretical_hours=theoretical_hours,
    )
