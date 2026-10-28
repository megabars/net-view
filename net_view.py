#!/usr/bin/env python3
"""Start the Net View desktop inspector (separate from network_lab.py)."""

import argparse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Net View — просмотр сетевого трафика приложений")
    parser.add_argument("--open", type=Path, help="Open a saved .netview.json or .pcapng session")
    args = parser.parse_args()
    from netview.ui import run
    run(args.open)


if __name__ == "__main__":
    main()
