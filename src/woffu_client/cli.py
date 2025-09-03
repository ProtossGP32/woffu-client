#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
from woffu_client import WoffuAPIClient  # adjust import path

DEFAULT_CONFIG = Path.home() / ".config/woffu/woffu_auth.json"
DEFAULT_OUTPUT_DIR = Path.home() / "Documents/woffu/docs"

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="woffu-cli",
        description="CLI interface for Woffu API client"
    )

    parser.add_argument(
        "--config",
        required=False,
        type=Path,
        help=f"Authentication file path (default: {DEFAULT_CONFIG})",
        default=DEFAULT_CONFIG
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---- download_all_files ----
    dl_parser = subparsers.add_parser(
        "download-all-documents", help="Download all documents from Woffu"
    )
    dl_parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to save downloaded files (default: {DEFAULT_OUTPUT_DIR})"
    )

    args = parser.parse_args()

    # Instantiate client
    client = WoffuAPIClient(config=args.config)
    match args.command:
        case "download-all-documents":
            try:
                args.output_dir.mkdir(parents=True, exist_ok=True)
                client.download_all_documents(output_dir=args.output_dir)
                print(f"✅ Files downloaded to {args.output_dir}")
            except Exception as e:
                print(f"❌ Error downloading files: {e}", file=sys.stderr)
                sys.exit(1)
        case _:
            print(f"❌ Unknown command: {args.command}", file=sys.stderr)
    

if __name__ == "__main__":
    main()
