#!/usr/bin/env python3
"""woffu-cli.

CLI tool for woffu-client.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from woffu_client import WoffuAPIClient  # adjust import path
from woffu_client.status import from_client_result

DEFAULT_CONFIG = Path.home() / ".config/woffu/woffu_auth.json"
DEFAULT_OUTPUT_DIR = Path.home() / "Documents/woffu/docs"
DEFAULT_SUMMARY_REPORTS_DIR = Path.home() / "Documents/woffu/summary_reports"


def _print_status_json(client: WoffuAPIClient) -> None:
    """Print `get-status`'s result as a single JSON line, logs suppressed."""
    logging.disable(logging.INFO)
    try:
        total_time, signed_in, theoretical_time = client.get_status(
            extend=True,
        )
    finally:
        logging.disable(logging.NOTSET)
    status = from_client_result(total_time, signed_in, theoretical_time)
    print(
        json.dumps({
            "signed_in": status.signed_in,
            "hours_worked": status.hours_worked,
            "theoretical_hours": status.theoretical_hours,
        }),
    )


def _handle_download_all_documents(
    client: WoffuAPIClient, args: argparse.Namespace,
) -> None:
    try:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        client.download_all_documents(output_dir=args.output_dir)
        print(f"✅ Files downloaded to {args.output_dir}")
    except Exception as e:
        print(f"❌ Error downloading files: {e}", file=sys.stderr)
        sys.exit(1)


def _handle_get_status(
    client: WoffuAPIClient, args: argparse.Namespace,
) -> None:
    try:
        if args.json:
            _print_status_json(client)
        else:
            client.get_status(extend=args.extend)
    except Exception as e:
        logging.disable(logging.NOTSET)
        if args.json:
            # Emit a structured error so the applet can distinguish a real
            # failure from a signed-out state, and fail loudly.
            print(json.dumps({"error": str(e)}))
            sys.exit(1)
        print(f"❌ Error retrieving status: {e}", file=sys.stderr)


def _handle_sign(client: WoffuAPIClient, args: argparse.Namespace) -> None:
    try:
        client.sign(type=args.sign_type)
    except Exception as e:
        print(f"❌ Error sending sign command: {e}", file=sys.stderr)


def _handle_request_credentials(
    client: WoffuAPIClient, args: argparse.Namespace,
) -> None:
    try:
        client.request_and_save_credentials()
    except Exception as e:
        print(f"❌ Error requesting new credentials: {e}", file=sys.stderr)


def _handle_summary_report(
    client: WoffuAPIClient, args: argparse.Namespace,
) -> None:
    try:
        summary_report = client.get_summary_report(
            from_date=args.from_date, to_date=args.to_date,
        )
        client.export_summary_to_csv(
            summary_report=summary_report,
            from_date=args.from_date,
            to_date=args.to_date,
            output_path=args.output_dir,
        )
    except Exception as e:
        print(f"❌ Error retrieving summary report: {e}", file=sys.stderr)


_COMMAND_HANDLERS = {
    "download-all-documents": _handle_download_all_documents,
    "get-status": _handle_get_status,
    "sign": _handle_sign,
    "request-credentials": _handle_request_credentials,
    "summary-report": _handle_summary_report,
}


def _build_parser() -> argparse.ArgumentParser:
    """Build the woffu-cli argument parser and all its subcommands."""
    parser = argparse.ArgumentParser(
        prog="woffu-cli", description="CLI interface for Woffu API client",
    )

    parser.add_argument(
        "--config",
        required=False,
        type=Path,
        help=f"Authentication file path (default: {DEFAULT_CONFIG})",
        default=DEFAULT_CONFIG,
    )

    parser.add_argument(
        "--non-interactive",
        required=False,
        action="store_true",
        help="Set session as non-interactive",
        default=False,
    )

    parser.add_argument(
        "--log-level",
        required=False,
        type=str,
        help="Set log level",
        default="INFO",
    )

    subparsers = parser.add_subparsers(
        title="actions", dest="command", required=True,
    )

    # ---- download_all_files ----
    dl_parser = subparsers.add_parser(
        "download-all-documents", help="Download all documents from Woffu",
    )
    dl_parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to save downloaded files \
            (default: {DEFAULT_OUTPUT_DIR})",
    )

    # ---- get_status ----
    status_parser = subparsers.add_parser(
        "get-status",
        help="Get current status and current day's \
            total amount of worked hours",
    )

    status_parser.add_argument(
        "--extend",
        action="store_true",
        help="Shows additional info such as theoretical schedule.",
    )

    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Output status as machine-readable JSON (suppresses log output).",
    )

    # ---- sign ----
    sign_parser = subparsers.add_parser(
        "sign",
        help="Send sign in or sign out request \
            based on the '--sign-type' argument",
    )

    sign_parser.add_argument(
        "--sign-type",
        type=str,
        default="any",
        help="Sign type to send. It can be either \
            'in', 'out' or 'any' (default: 'any')",
    )

    # ---- request_credentials ----
    subparsers.add_parser(
        "request-credentials",
        help="Request credentials from Woffu. For non-interactive sessions, \
            set username and password as environment variables \
                WOFFU_USERNAME and WOFFU_PASSWORD.",
    )

    # ---- summary_report ----
    summary_report_parser = subparsers.add_parser(
        "summary-report",
        help="Summary report of work hours for a given time window",
    )

    summary_report_parser.add_argument(
        "--from-date",
        type=str,
        required=True,
        help="Start date of the time window. Format YYYY-mm-dd",
    )

    summary_report_parser.add_argument(
        "--to-date",
        type=str,
        required=True,
        help="End date of the time window. Format YYYY-mm-dd",
    )

    summary_report_parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_SUMMARY_REPORTS_DIR,
        help=f"Directory to save exported CSV file \
            (default: {DEFAULT_SUMMARY_REPORTS_DIR})",
    )

    return parser


def main() -> None:
    """Execute a Woffu action depending on the provided command."""
    args = _build_parser().parse_args()
    client = WoffuAPIClient(
        config=args.config,
        interactive=not args.non_interactive,
        log_level=args.log_level,
    )
    _COMMAND_HANDLERS[args.command](client, args)


if __name__ == "__main__":
    main()
