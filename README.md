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
pip install -e .
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

## Contributing

### GitFlow convention

Please follow the [GitFlow convention][atlassian-gitflow] to do contributions to the code.

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

With this, each commit you do will be checked and auto-fixed by the `pre-commit` git hook. You'll have to stage the new changes in the files if something has been fixed.

### Testing

> :warning: TODO: add instructions on how to test code and where to add new tests

## Disclaimer

This project has been partially coded using AI (ChatGPT) for handling HTTP sessions and responses as well as almost all unit tests. Expect either duplicated tests or code that can be improved; I intend to use static code analysis tools later on to achieve a cleaner code.

<!-- LINKS -->
[atlassian-gitflow]: https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow
[python-pep8-page]: https://peps.python.org/pep-0008/
[pre-commit-page]: https://pre-commit.com/
