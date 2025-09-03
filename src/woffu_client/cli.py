#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
from woffu_client import WoffuAPIClient  # adjust import path

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="woffu-cli",
        description="CLI interface for Woffu API client"
    )

    parser.add_argument(
        "--config",
        required=False,
        help=f"Authentication file path (default: {Path.joinpath(Path.home(), ".config/woffu/woffu_auth.json")})",
        default=Path.joinpath(Path.home(), ".config/woffu/woffu_auth.json")
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---- download_all_files ----
    dl_parser = subparsers.add_parser(
        "download-all-documents", help="Download all documents from Woffu"
    )
    dl_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.joinpath(Path.home(), "Documents/woffu/docs"),
        help=f"Directory to save downloaded files (default: {Path.joinpath(Path.home(), "Documents/woffu/docs")})"
    )

    args = parser.parse_args()

    # Instantiate client
    client = WoffuAPIClient(config=args.config)

    if args.command == "download-all-documents":
        try:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            client.download_all_documents(output_dir=args.output_dir)
            print(f"✅ Files downloaded to {args.output_dir}")
        except Exception as e:
            print(f"❌ Error downloading files: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
