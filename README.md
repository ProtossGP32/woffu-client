# woffu-client
<!-- BADGES -->
![PyPI - Python version](https://img.shields.io/badge/dynamic/json?query=info.requires_python&label=python&url=https%3A%2F%2Fpypi.org%2Fpypi%2Fwoffu-client%2Fjson&logo=python)
[![PyPI - Version](https://img.shields.io/pypi/v/woffu-client?logo=pypi)](https://pypi.org/project/woffu-client/)
![PyPI - Downloads](https://img.shields.io/pypi/dm/woffu-client?logo=pypi)
![PyPI - License](https://img.shields.io/pypi/l/woffu-client)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/ProtossGP32/woffu-client/main.svg)](https://results.pre-commit.ci/latest/github/ProtossGP32/woffu-client/main)

Woffu client with access to several endpoints outside their public API, for those users without access to a Woffu API key.

## Installation

### PyPI

The build package is publicly available on PyPI:

```bash
pip install woffu-client
```

#### Development

```bash
pip install -e .[dev]
```

#### Desktop applet (GNOME)

The package also ships `woffu-applet`, a GNOME top-bar applet that lets you
sign in / out of Woffu in a couple of clicks, backed by the same
`WoffuAPIClient` as `woffu-cli`.

It needs GTK 3 and an AppIndicator binding (`gi` / PyGObject), which bind to
your distro's system libraries rather than being pure pip packages. `gi`
binds to the system GTK install, so a plain `venv` won't see it — either
route below needs a venv created with `--system-site-packages`, or the
system Python directly.

There are two different package lists depending on what you're doing:

##### Production — just running the applet

Install the **prebuilt** runtime packages from your distro. No compiler is
needed:

| Package | Debian/Ubuntu | Fedora |
| --- | --- | --- |
| PyGObject (`gi`) bindings | `python3-gi` | `python3-gobject` |
| GTK 3 typelib | `gir1.2-gtk-3.0` | (bundled with `python3-gobject`) |
| AppIndicator typelib | `gir1.2-ayatanaappindicator3-0.1` (legacy: `gir1.2-appindicator3-0.1`) | `libayatana-appindicator-gtk3` |

```bash
# Debian/Ubuntu
sudo apt install python3-gi gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1
# Fedora
sudo dnf install python3-gobject libayatana-appindicator-gtk3
```

Then install `woffu-client` itself — **not** the `[gui]` extra, since the
system package above already provides `gi`:

```bash
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install woffu-client
```

##### Development — building `PyGObject` from source (the `gui` extra)

If you're contributing to this repo, `pip install .[gui]` builds
`PyGObject` (and its `pycairo` build dependency) from source instead of
using a system package. That needs the full compiler toolchain and
`-dev`/`-devel` headers, on top of the runtime packages listed above:

| Package | Debian/Ubuntu | Fedora |
| --- | --- | --- |
| Python headers | `python3-dev` | `python3-devel` |
| Compiler toolchain | `build-essential` | `gcc` `gcc-c++` `make` |
| pkg-config | `pkg-config` | `pkgconf-pkg-config` |
| Cairo headers (for `pycairo`) | `libcairo2-dev` | `cairo-gobject-devel` |
| GObject-Introspection headers (for `PyGObject`) | `libgirepository-2.0-dev` (older releases: `libgirepository1.0-dev`) | `gobject-introspection-devel` |

```bash
# Debian/Ubuntu
sudo apt install python3-dev build-essential pkg-config libcairo2-dev \
  python3-gi gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1
sudo apt install libgirepository-2.0-dev || sudo apt install libgirepository1.0-dev
# Fedora
sudo dnf install python3-devel gcc gcc-c++ make pkgconf-pkg-config \
  cairo-gobject-devel gobject-introspection-devel \
  python3-gobject libayatana-appindicator-gtk3
```

Then, from a clone of this repo:

```bash
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -e .[dev,gui]
```

If you use [`uv`][uv-page] instead of stdlib `venv`, pin the interpreter
explicitly:

```bash
uv venv --python /usr/bin/python3 --system-site-packages .venv
uv pip install -e .[dev,gui]
```

Plain `uv venv --system-site-packages` (no `--python`) lets `uv` pick its own
managed CPython build instead of your distro's `/usr/bin/python3`, and
`--system-site-packages` then can't see `/usr/lib/python3/dist-packages`
(where `python3-gi` lives) since it resolves relative to that managed build,
not the system one — `import gi` fails with `ModuleNotFoundError` even though
the package above is installed.

On GNOME, the applet only shows up in the top bar once the AppIndicator
extension is enabled (install `gnome-shell-extension-appindicator` on
Fedora; it's usually preinstalled on Ubuntu).

Run it after the one-time `woffu-cli request-credentials` setup (see
[Usage](#usage) below):

```bash
woffu-applet
# or, without the entry point:
python3 -m woffu_client.applet
```

## Usage

```bash
usage: woffu-cli [-h] [--config CONFIG] [--non-interactive] {download-all-documents,get-status,sign,request-credentials,summary-report} ...

CLI interface for Woffu API client

options:
  -h, --help            show this help message and exit
  --config CONFIG       Authentication file path (default: /home/mpalacin/.config/woffu/woffu_auth.json)
  --non-interactive     Set session as non-interactive

actions:
  {download-all-documents,get-status,sign,request-credentials,summary-report}
    download-all-documents
                        Download all documents from Woffu
    get-status          Get current status and current day's total amount of worked hours
    sign                Send sign in or sign out request based on the '--sign-type' argument
    request-credentials
                        Request credentials from Woffu. For non-interactive sessions, set username and password as environment variables WOFFU_USERNAME and WOFFU_PASSWORD.
    summary-report      Summary report of work hours for a given time window
```

Each action might have its own arguments, check them by running:

```bash
woffu-cli <action-name> -h
```

## Contributing

### GitFlow convention

Please follow the [GitFlow convention][atlassian-gitflow] to do contributions to the code. CI pipelines expect feature branches to be named as `feature/**`, else they won't trigger any job.

### Linting

Make use of pre-commit git hooks to ensure that the code complies with [PEP8 Style Guide for Python Code][python-pep8-page]. Follow [pre-commit][pre-commit-page] instructions to ensure you have both the pre-commit python package installed and the environment initialized:

```bash
# Install pre-commit package
pip install pre-commit
# Binaries are include in $HOME/.local/bin in Ubuntu
# Ensure that python binaries path are included in the PATH variable
echo 'export PATH="$HOME/.local/bin:$PATH' >> ~/.bashrc
# Close the terminal and open a new one to apply changes or simply reload the .bashrc file
source ~/.bashrc
# Ensure that you have access to the pre-commit binary
pre-commit --version
# Go to the cloned project path and initialize pre-commit with the provided .pre-commit-config.yaml file
cd /path/to/woffu-client
pre-commit install
```

With this, each commit you do will be checked and auto-fixed by the `pre-commit` git hook. You'll have to stage the new changes in the files if something has been fixed. If you want to manually execute `pre-commit`, manually stage your changes and run:

```bash
pre-commit run
```

### Testing

Tests use `pytest` and are located in the `tests` folder. We enforce both tests and code coverage in this project, so make sure to test it before opening a PR.

Run tests and coverage with this command:

```bash
pytest -v --maxfail=1 --disable-warnings --junitxml coverage/report.xml --cov-report term --cov-report xml:coverage/coverage.xml --cov=. tests
```

If you prefer using `coverage` directly:

```bash
coverage run -m pytest -v tests && coverage report -m
```

For a nice HTML report, run:

```bash
coverage html -d .coverage && firefox .coverage/index.html
```

Remember to not push the coverage reports to the repository! `.gitignore` already filters some default paths, but double check it before commiting.

#### Code coverage

A SonarQube instance is in charge of analyzing the new code during CI/CD pipelines. Only contributions that meet the following clean code conditions will be accepted:

- The new code doesn't introduce issues (bugs, vulnerabilites or code smell)
- All new security hotspots are reviewed
- New code has sufficient test coverage (greater or equal to **80.0%**)
- New code has limited duplications (duplicated lines is less than or equal to **3.0%**)

## Disclaimer

This project has been partially coded using AI (ChatGPT) for handling HTTP sessions and responses as well as almost all unit tests. Expect either duplicated tests or code that can be improved; I intend to use static code analysis tools later on to achieve a cleaner code.

<!-- LINKS -->
[atlassian-gitflow]: https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow
[python-pep8-page]: https://peps.python.org/pep-0008/
[pre-commit-page]: https://pre-commit.com/
[uv-page]: https://docs.astral.sh/uv/
