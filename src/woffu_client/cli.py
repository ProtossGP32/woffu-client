#!/usr/bin/env python3
"""woffu-cli.

CLI tool for woffu-client.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from woffu_client import WoffuAPIClient  # adjust import path

DEFAULT_CONFIG = Path.home() / ".config/woffu/woffu_auth.json"
DEFAULT_OUTPUT_DIR = Path.home() / "Documents/woffu/docs"
DEFAULT_SUMMARY_REPORTS_DIR = Path.home() / "Documents/woffu/summary_reports"


def main() -> None:
    """
    Execute a Woffu action depending on the provided command.

    :params None
    :return None
    """
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
    subparsers.add_parser(
        "get-status",
        help="Get current status and current day's \
            total amount of worked hours",
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

    # ---- get_status ----
    subparsers.add_parser(
        "request-credentials",
        help="Request credentials from Woffu. For non-interactive sessions, \
            set username and password as environment variables \
                WOFFU_USERNAME and WOFFU_PASSWORD.",
    )

    # ---- get_status ----
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

    args = parser.parse_args()

    # Instantiate client
    client = WoffuAPIClient(
        config=args.config,
        interactive=not args.non_interactive,
        log_level=args.log_level,
    )
    match args.command:
        case "download-all-documents":
            try:
                args.output_dir.mkdir(parents=True, exist_ok=True)
                client.download_all_documents(output_dir=args.output_dir)
                print(f"✅ Files downloaded to {args.output_dir}")
            except Exception as e:
                print(f"❌ Error downloading files: {e}", file=sys.stderr)
                sys.exit(1)
        case "get-status":
            try:
                client.get_status()
            except Exception as e:
                print(f"❌ Error retrieving status: {e}", file=sys.stderr)
        case "sign":
            try:
                client.sign(type=args.sign_type)
            except Exception as e:
                print(f"❌ Error sending sign command: {e}", file=sys.stderr)
        case "request-credentials":
            try:
                client._request_credentials()
                client._save_credentials()
            except Exception as e:
                print(
                    f"❌ Error requesting new credentials: {e}",
                    file=sys.stderr,
                )
        case "summary-report":
            try:
                summary_report = client.get_summary_report(
                    from_date=args.from_date,
                    to_date=args.to_date,
                )
                client.export_summary_to_csv(
                    summary_report=summary_report,
                    from_date=args.from_date,
                    to_date=args.to_date,
                    output_path=args.output_dir,
                )
            except Exception as e:
                print(
                    f"❌ Error retrieving summary report: {e}", file=sys.stderr,
                )


if __name__ == "__main__":
    main()
