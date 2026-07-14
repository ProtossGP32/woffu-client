"""Tests for the Woffu GTK applet's presentation logic.

No real GTK widgets or display are used anywhere in this file. Most tests
build a WoffuApplet via __new__() to skip __init__() and use Mock() widget
attributes directly, covering the status->label/icon mapping and thread/GLib
dispatch wiring. InitAndBuildMenuTest/MainTest instead patch Gtk/AppIndicator3/
GLib at the module level and construct a real WoffuApplet()/call main(), so
__init__()/_build_menu()'s own control flow (which widget gets built, which
handler gets connected to which signal) is exercised without ever touching
a real display.

applet.py imports gi (PyGObject) at module level, which needs the system
GTK/AppIndicator introspection typelibs (see CLAUDE.md) rather than just a
pip install. Skip instead of erroring when that's not available, so a plain
venv without system gi (e.g. a default VS Code venv) doesn't show this whole
module as a collection error.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock
from unittest.mock import patch

import pytest

pytest.importorskip("gi", reason="PyGObject (system gi) is not installed")

import src.woffu_client.applet as applet  # noqa: E402
from src.woffu_client.status import WoffuStatus  # noqa: E402


def _make_applet() -> applet.WoffuApplet:
    """Build a WoffuApplet without running __init__ (no GTK/display needed)."""
    instance = applet.WoffuApplet.__new__(applet.WoffuApplet)
    instance._indicator = Mock()
    instance._status_label = Mock()
    instance._sign_in_item = Mock()
    instance._sign_out_item = Mock()
    return instance


class ApplyStatusTest(unittest.TestCase):
    """Unit tests for WoffuApplet._apply_status()."""

    def test_not_configured_shows_hint_and_disables_sign_items(self):
        """No credentials: hint label, both sign items disabled, no repeat."""
        woffu_applet = _make_applet()
        status = WoffuStatus(
            signed_in=False, hours_worked="00:00:00",
            error=None, configured=False,
        )

        result = woffu_applet._apply_status(status)

        self.assertFalse(result)
        woffu_applet._sign_in_item.set_sensitive.assert_called_once_with(False)
        woffu_applet._sign_out_item.set_sensitive.assert_called_once_with(
            False,
        )
        woffu_applet._status_label.set_label.assert_called_once_with(
            applet._NOT_CONFIGURED_LABEL,
        )
        woffu_applet._indicator.set_icon_full.assert_called_once_with(
            applet._ICON_NAME, "Woffu — not configured",
        )

    def test_not_configured_prefers_specific_error_over_generic_hint(self):
        """A concrete error beats the generic not-configured hint."""
        woffu_applet = _make_applet()
        status = WoffuStatus(
            signed_in=False, hours_worked="00:00:00",
            error="custom message", configured=False,
        )

        woffu_applet._apply_status(status)

        woffu_applet._status_label.set_label.assert_called_once_with(
            "custom message",
        )

    def test_error_shows_message_but_keeps_sign_items_enabled(self):
        """Configured but errored: sign items stay enabled, error is shown."""
        woffu_applet = _make_applet()
        status = WoffuStatus(
            signed_in=False, hours_worked="00:00:00",
            error="boom", configured=True,
        )

        woffu_applet._apply_status(status)

        woffu_applet._sign_in_item.set_sensitive.assert_called_once_with(True)
        woffu_applet._sign_out_item.set_sensitive.assert_called_once_with(True)
        woffu_applet._status_label.set_label.assert_called_once_with(
            "Error: boom",
        )
        woffu_applet._indicator.set_icon_full.assert_called_once_with(
            applet._ICON_NAME, "Woffu — error",
        )

    def test_signed_in_with_theoretical_hours(self):
        """Signed in with theoretical hours: both figures shown."""
        woffu_applet = _make_applet()
        status = WoffuStatus(
            signed_in=True, hours_worked="06:49:39",
            theoretical_hours="06:30:00",
        )

        woffu_applet._apply_status(status)

        woffu_applet._status_label.set_label.assert_called_once_with(
            "Signed in · 06:49:39 / 06:30:00",
        )
        woffu_applet._indicator.set_icon_full.assert_called_once_with(
            applet._ICON_NAME, "Woffu — signed in",
        )

    def test_signed_in_without_theoretical_hours(self):
        """Signed in with no theoretical hours: only worked hours shown."""
        woffu_applet = _make_applet()
        status = WoffuStatus(
            signed_in=True, hours_worked="06:49:39", theoretical_hours=None,
        )

        woffu_applet._apply_status(status)

        woffu_applet._status_label.set_label.assert_called_once_with(
            "Signed in · 06:49:39",
        )

    def test_signed_out(self):
        """Signed out: worked hours shown, sign items enabled."""
        woffu_applet = _make_applet()
        status = WoffuStatus(signed_in=False, hours_worked="01:00:00")

        woffu_applet._apply_status(status)

        woffu_applet._sign_in_item.set_sensitive.assert_called_once_with(True)
        woffu_applet._sign_out_item.set_sensitive.assert_called_once_with(True)
        woffu_applet._status_label.set_label.assert_called_once_with(
            "Signed out · 01:00:00",
        )
        woffu_applet._indicator.set_icon_full.assert_called_once_with(
            applet._ICON_NAME, "Woffu — signed out",
        )


class FetchAndUpdateTest(unittest.TestCase):
    """Unit tests for WoffuApplet._fetch_and_update()."""

    @patch("src.woffu_client.applet.GLib")
    @patch("src.woffu_client.applet.core")
    def test_fetches_status_and_schedules_apply_on_main_loop(
        self, mock_core, mock_glib,
    ):
        """The fetched status is applied via GLib.idle_add, not directly."""
        woffu_applet = _make_applet()
        status = WoffuStatus(signed_in=True, hours_worked="01:00:00")
        mock_core.get_status.return_value = status

        woffu_applet._fetch_and_update()

        mock_core.get_status.assert_called_once_with()
        mock_glib.idle_add.assert_called_once_with(
            woffu_applet._apply_status, status,
        )


class OnTimerTest(unittest.TestCase):
    """Unit tests for WoffuApplet._on_timer()."""

    def test_triggers_refresh_and_keeps_repeating(self):
        """The poll timer refreshes status and asks GLib to keep firing."""
        woffu_applet = _make_applet()
        woffu_applet._refresh_status = Mock()

        result = woffu_applet._on_timer()

        woffu_applet._refresh_status.assert_called_once_with()
        self.assertTrue(result)


class RefreshStatusTest(unittest.TestCase):
    """Unit tests for WoffuApplet._refresh_status()."""

    @patch("src.woffu_client.applet.threading.Thread")
    def test_dispatches_fetch_on_a_daemon_thread(self, mock_thread_cls):
        """Status is fetched off the main loop, on a daemon thread."""
        woffu_applet = _make_applet()

        woffu_applet._refresh_status()

        _, kwargs = mock_thread_cls.call_args
        self.assertEqual(kwargs["target"], woffu_applet._fetch_and_update)
        self.assertTrue(kwargs["daemon"])
        mock_thread_cls.return_value.start.assert_called_once_with()


class SignHandlersTest(unittest.TestCase):
    """Unit tests for _on_sign_in / _on_sign_out / _do_sign_then_refresh."""

    @patch("src.woffu_client.applet.threading.Thread")
    def test_on_sign_in_dispatches_core_sign_in_on_a_daemon_thread(
        self, mock_thread_cls,
    ):
        """Sign-in menu clicks run core.sign_in off the main loop."""
        woffu_applet = _make_applet()

        woffu_applet._on_sign_in(Mock())

        _, kwargs = mock_thread_cls.call_args
        self.assertEqual(kwargs["target"], woffu_applet._do_sign_then_refresh)
        self.assertEqual(kwargs["args"], (applet.core.sign_in,))
        self.assertTrue(kwargs["daemon"])
        mock_thread_cls.return_value.start.assert_called_once_with()

    @patch("src.woffu_client.applet.threading.Thread")
    def test_on_sign_out_dispatches_core_sign_out_on_a_daemon_thread(
        self, mock_thread_cls,
    ):
        """Sign-out menu clicks run core.sign_out off the main loop."""
        woffu_applet = _make_applet()

        woffu_applet._on_sign_out(Mock())

        _, kwargs = mock_thread_cls.call_args
        self.assertEqual(kwargs["target"], woffu_applet._do_sign_then_refresh)
        self.assertEqual(kwargs["args"], (applet.core.sign_out,))
        self.assertTrue(kwargs["daemon"])
        mock_thread_cls.return_value.start.assert_called_once_with()

    @patch("src.woffu_client.applet.GLib")
    @patch("src.woffu_client.applet.core")
    def test_do_sign_then_refresh_runs_action_then_refreshes_status(
        self, mock_core, mock_glib,
    ):
        """The sign action runs first, then status is re-fetched/applied."""
        woffu_applet = _make_applet()
        status = WoffuStatus(signed_in=True, hours_worked="02:00:00")
        mock_core.get_status.return_value = status
        action = Mock()

        woffu_applet._do_sign_then_refresh(action)

        action.assert_called_once_with()
        mock_core.get_status.assert_called_once_with()
        mock_glib.idle_add.assert_called_once_with(
            woffu_applet._apply_status, status,
        )


class InitAndBuildMenuTest(unittest.TestCase):
    """Unit tests for WoffuApplet.__init__() / _build_menu() wiring."""

    @patch("src.woffu_client.applet.threading.Thread")
    @patch("src.woffu_client.applet.GLib")
    @patch("src.woffu_client.applet.AppIndicator3")
    @patch("src.woffu_client.applet.Gtk")
    def test_init_builds_indicator_and_starts_polling(
        self, mock_gtk, mock_indicator3, mock_glib, mock_thread_cls,
    ):
        """__init__ wires the indicator, menu and poll timer together."""
        woffu_applet = applet.WoffuApplet()

        mock_indicator3.Indicator.new_with_path.assert_called_once_with(
            "woffu-applet", applet._ICON_NAME,
            mock_indicator3.IndicatorCategory.APPLICATION_STATUS,
            applet._ICON_DIR,
        )
        indicator = mock_indicator3.Indicator.new_with_path.return_value
        self.assertIs(woffu_applet._indicator, indicator)
        indicator.set_status.assert_called_once_with(
            mock_indicator3.IndicatorStatus.ACTIVE,
        )
        indicator.set_menu.assert_called_once_with(mock_gtk.Menu.return_value)
        mock_thread_cls.assert_called_once_with(
            target=woffu_applet._fetch_and_update, daemon=True,
        )
        mock_glib.timeout_add_seconds.assert_called_once_with(
            applet._POLL_SECONDS, woffu_applet._on_timer,
        )

    @patch("src.woffu_client.applet.threading.Thread")
    @patch("src.woffu_client.applet.GLib")
    @patch("src.woffu_client.applet.AppIndicator3")
    @patch("src.woffu_client.applet.Gtk")
    def test_build_menu_wires_status_and_sign_items(
        self, mock_gtk, mock_indicator3, mock_glib, mock_thread_cls,
    ):
        """Each menu item is built, labelled and wired to its handler."""
        status_item, sign_in_item, sign_out_item, refresh_item, quit_item = (
            Mock(name="status"), Mock(name="sign_in"), Mock(name="sign_out"),
            Mock(name="refresh"), Mock(name="quit"),
        )
        mock_gtk.MenuItem.side_effect = [
            status_item, sign_in_item, sign_out_item, refresh_item, quit_item,
        ]

        woffu_applet = applet.WoffuApplet()

        self.assertIs(woffu_applet._status_label, status_item)
        status_item.set_sensitive.assert_called_once_with(False)

        self.assertIs(woffu_applet._sign_in_item, sign_in_item)
        sign_in_item.connect.assert_called_once_with(
            "activate", woffu_applet._on_sign_in,
        )

        self.assertIs(woffu_applet._sign_out_item, sign_out_item)
        sign_out_item.connect.assert_called_once_with(
            "activate", woffu_applet._on_sign_out,
        )

        refresh_item.connect.assert_called_once()
        self.assertEqual(refresh_item.connect.call_args[0][0], "activate")
        quit_item.connect.assert_called_once()
        self.assertEqual(quit_item.connect.call_args[0][0], "activate")

        menu = mock_gtk.Menu.return_value
        self.assertEqual(menu.append.call_count, 7)  # 5 items + 2 separators
        menu.show_all.assert_called_once_with()


class MainTest(unittest.TestCase):
    """Unit tests for the module-level main() entry point."""

    @patch("src.woffu_client.applet.Gtk")
    @patch("src.woffu_client.applet.WoffuApplet")
    def test_main_builds_applet_and_runs_the_gtk_main_loop(
        self, mock_applet_cls, mock_gtk,
    ):
        """main() constructs the applet once and enters Gtk.main()."""
        applet.main()

        mock_applet_cls.assert_called_once_with()
        mock_gtk.main.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
