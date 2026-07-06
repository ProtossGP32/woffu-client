# Applet TODO / backlog

Future work for the Woffu desktop applet, captured from testing and feedback.
Keep logic in `core`/`status` (with tests) and `applet` presentational — see
CLAUDE.md.

## Interaction / UI

- [ ] **Single exclusive sign toggle.** Replace the separate "Sign in" /
      "Sign out" menu items with one toggle — a slider/"circle" dragged
      left↔right (or pressed) to switch state, since signed-in and signed-out
      are mutually exclusive. Candidates: `Gtk.Switch` inside a menu item, or a
      custom widget.
- [ ] **Drop "Refresh".** Redundant now that status auto-polls every 30s and
      refreshes after every sign action.
- [ ] **Show the username** in the menu (nice to have). Needs a way to expose it
      from the CLI — it already lives in the credentials file / users API.
- [ ] **Per-state icon tint.** Desaturate/grey the Woffu mark when signed out so
      the panel reflects state at a glance (signed-in = full colour). Generate a
      muted variant of `icons/woffu.svg`.

## Notifications

- [ ] **Status-change notification.** Desktop notification after sign in/out (and
      optionally manual refresh) for visible feedback without opening the menu.
      (`Gio.Notification` / libnotify.)
- [ ] **End-of-schedule reminder.** Notify when worked time is within ~30 min of
      the theoretical daily total (e.g. 06:30). The applet already has both
      `hours_worked` and `theoretical_hours`, so remaining time is computable.
      Make the threshold (and on/off) configurable; fire once per day.

## Credentials / onboarding

- [ ] **In-app credentials setup.** A GTK dialog that captures username/password
      and runs the request-credentials flow on the user's behalf, instead of
      making them run `woffu-cli request-credentials` in a terminal. Ties into
      the existing "not configured" state. Security: prefer the system keyring
      over plaintext (see CLAUDE.md "Security").

## Packaging / delivery (already planned)

- [ ] Ship a `.desktop` autostart file so the applet launches on login.
- [x] README install section: system deps (`python3-gi` + AppIndicator GIR),
      `pip install .[gui]`, the `--system-site-packages` venv note, and enabling
      the GNOME AppIndicator extension.

### Self-hosted, no-Python-env installable (separate initiative)

Discussed with reviewer on PR #54: package this as something a user can
install directly, without dealing with a Python env or pip/venv commands, on
both Linux and Windows. Linux and Windows are two different problems here, not
one packaging task — treat as separate follow-up PR(s) from the applet work,
not part of this PR:

- [ ] **Linux.** GTK3 + AppIndicator depend on system-level GObject
      introspection typelibs resolved at runtime against whatever's installed
      on the host, so they can't be meaningfully bundled the PyInstaller/
      single-binary way. Package as a native `.deb`/`.rpm` (e.g. via `fpm`) or
      a Flatpak against the GNOME runtime, declaring those as real
      dependencies so the package manager installs them — not the user
      running shell commands.
- [ ] **Windows.** There is no GTK/AppIndicator target on Windows, so this
      isn't a packaging change — it's a new tray front-end (e.g. `pystray` +
      a native dialog toolkit) replacing `applet.py`. `core.py`/`status.py`
      are already GTK-free by design and should be reusable as-is. Bundle the
      new front-end with PyInstaller + an installer wrapper (Inno Setup/NSIS)
      once it exists — Windows has none of Linux's GI-bundling problem.
