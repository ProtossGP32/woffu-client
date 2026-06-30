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
- [ ] README install section: system deps (`python3-gi` + AppIndicator GIR),
      `pip install .[gui]`, the `--system-site-packages` venv note, and enabling
      the GNOME AppIndicator extension.
- [ ] Open the PR once the above settle.
