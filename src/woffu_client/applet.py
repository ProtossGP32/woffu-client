"""Woffu GNOME top-bar applet.

GTK 3 + AppIndicator front-end only.  All business logic lives in core.py /
status.py.  CLI calls are dispatched from daemon threads so the GLib main loop
is never blocked; results are marshalled back via GLib.idle_add.
"""
from __future__ import annotations

import threading

import gi

from . import core
from .status import WoffuStatus

gi.require_version("Gtk", "3.0")

# Every gi.repository import must run *after* the require_version() calls, so
# they live inside this try/except: reorder-python-imports leaves nested
# imports in place, whereas top-level ones get hoisted above the version pin
# (importing Gtk before pinning would auto-select an arbitrary GTK version).
# GLib/Gtk are imported first so they exist even if Ayatana is unavailable.
try:
    from gi.repository import GLib
    from gi.repository import Gtk
    gi.require_version("AyatanaAppIndicator3", "0.1")
    from gi.repository import AyatanaAppIndicator3 as AppIndicator3
except ValueError:
    gi.require_version("AppIndicator3", "0.1")
    from gi.repository import AppIndicator3


_POLL_SECONDS = 30

_ICON_ONLINE = "user-available-symbolic"
_ICON_OFFLINE = "user-offline-symbolic"
_ICON_ERROR = "user-busy-symbolic"

_NOT_CONFIGURED_LABEL = "Not configured — run woffu-cli request-credentials"


class WoffuApplet:
    """GNOME indicator that renders Woffu state and drives sign actions."""

    def __init__(self) -> None:
        """Build the indicator and menu, then start the status poll timer."""
        self._indicator = AppIndicator3.Indicator.new(
            "woffu-applet",
            _ICON_OFFLINE,
            AppIndicator3.IndicatorCategory.APPLICATION_STATUS,
        )
        self._indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self._indicator.set_menu(self._build_menu())

        self._refresh_status()
        GLib.timeout_add_seconds(_POLL_SECONDS, self._on_timer)

    # ------------------------------------------------------------------
    # Menu construction
    # ------------------------------------------------------------------

    def _build_menu(self) -> Gtk.Menu:
        menu = Gtk.Menu()

        self._status_label = Gtk.MenuItem(label="Checking status…")
        self._status_label.set_sensitive(False)
        menu.append(self._status_label)

        menu.append(Gtk.SeparatorMenuItem())

        self._sign_in_item = Gtk.MenuItem(label="Sign in")
        self._sign_in_item.connect("activate", self._on_sign_in)
        menu.append(self._sign_in_item)

        self._sign_out_item = Gtk.MenuItem(label="Sign out")
        self._sign_out_item.connect("activate", self._on_sign_out)
        menu.append(self._sign_out_item)

        menu.append(Gtk.SeparatorMenuItem())

        refresh_item = Gtk.MenuItem(label="Refresh")
        refresh_item.connect("activate", lambda _: self._refresh_status())
        menu.append(refresh_item)

        quit_item = Gtk.MenuItem(label="Quit")
        quit_item.connect("activate", lambda _: Gtk.main_quit())
        menu.append(quit_item)

        menu.show_all()
        return menu

    # ------------------------------------------------------------------
    # Status refresh
    # ------------------------------------------------------------------

    def _on_timer(self) -> bool:
        self._refresh_status()
        return True  # keep the timer alive

    def _refresh_status(self) -> None:
        threading.Thread(target=self._fetch_and_update, daemon=True).start()

    def _fetch_and_update(self) -> None:
        status = core.get_status()
        GLib.idle_add(self._apply_status, status)

    def _apply_status(self, status: WoffuStatus) -> bool:
        # Sign actions only make sense once credentials exist.
        signable = status.configured
        self._sign_in_item.set_sensitive(signable)
        self._sign_out_item.set_sensitive(signable)

        if not status.configured:
            self._indicator.set_icon_full(_ICON_ERROR, "not configured")
            self._status_label.set_label(status.error or _NOT_CONFIGURED_LABEL)
        elif status.error:
            self._indicator.set_icon_full(_ICON_ERROR, "error")
            self._status_label.set_label(f"Error: {status.error}")
        elif status.signed_in:
            label = f"Signed in · {status.hours_worked}"
            if status.theoretical_hours:
                label += f" / {status.theoretical_hours}"
            self._indicator.set_icon_full(_ICON_ONLINE, "signed in")
            self._status_label.set_label(label)
        else:
            self._indicator.set_icon_full(_ICON_OFFLINE, "signed out")
            self._status_label.set_label(f"Signed out · {status.hours_worked}")
        return False  # don't repeat the idle_add

    # ------------------------------------------------------------------
    # Sign actions
    # ------------------------------------------------------------------

    def _on_sign_in(self, _: Gtk.MenuItem) -> None:
        threading.Thread(
            target=self._do_sign_then_refresh,
            args=(core.sign_in,),
            daemon=True,
        ).start()

    def _on_sign_out(self, _: Gtk.MenuItem) -> None:
        threading.Thread(
            target=self._do_sign_then_refresh,
            args=(core.sign_out,),
            daemon=True,
        ).start()

    def _do_sign_then_refresh(self, action: object) -> None:
        action()
        status = core.get_status()
        GLib.idle_add(self._apply_status, status)


def main() -> None:
    """Entry point: start the applet and run the GTK main loop."""
    WoffuApplet()
    Gtk.main()


if __name__ == "__main__":
    main()
