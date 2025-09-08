# woffu-client
Woffu API client with access to several endpoints.

## Installation

### Development

```bash
pip install -e .
```

> TODO: Instructions for pre-built package

## Usage:

```bash
$ woffu-cli -h
usage: woffu-cli [-h] [--config CONFIG] [--interactive INTERACTIVE] {download-all-documents,get-status,sign,request-credentials} ...

CLI interface for Woffu API client

options:
  -h, --help            show this help message and exit
  --config CONFIG       Authentication file path (default: /home/${USER}/.config/woffu/woffu_auth.json)
  --interactive INTERACTIVE
                        Set session as interactive or non-interactive (default: True)

actions:
  {download-all-documents,get-status,sign,request-credentials}
    download-all-documents
                        Download all documents from Woffu
    get-status          Get current status and current day's total amount of worked hours
    sign                Send sing in or sign out request based on the '--sign-type' argument
    request-credentials
                        Request credentials from Woffu. For non-interactive sessions, set username and password as environment variables WOFFU_USERNAME and WOFFU_PASSWORD.
```