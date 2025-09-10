# woffu-client
Woffu API client with access to several endpoints.

## Installation

## PyPI

The build package is publicly available on PyPI:

```
pip install woffu-client
```

### Development

```bash
pip install -e .
```

## Usage:

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