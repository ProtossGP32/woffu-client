"""Tests for the Woffu GTK applet's presentation logic.

No real GTK widgets or display are used: WoffuApplet is built via __new__()
to skip __init__() (which constructs real AppIndicator/Gtk objects and needs
a display), and its widget attributes are Mock()s instead. This covers the
status->label/icon mapping and the thread/GLib dispatch wiring that applet.py
owns. _build_menu()/__init__() themselves still need a real GTK display and
are out of scope here.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock
from unittest.mock import patch

import src.woffu_client.applet as applet
from src.woffu_client.status import WoffuStatus


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


if __name__ == "__main__":
    unittest.main()
