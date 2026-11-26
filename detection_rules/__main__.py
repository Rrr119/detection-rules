# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Shell for detection-rules."""

import os
import sys
from pathlib import Path

import click

from .main import root

CURR_DIR = Path(__file__).resolve().parent
CLI_DIR = CURR_DIR.parent
ROOT_DIR = CLI_DIR.parent

BANNER = r"""
█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█
"""


def main() -> None:
    """CLI entry point."""
    json_requested = (
        "--json" in sys.argv
        or any(
            arg == "json" and index > 0 and sys.argv[index - 1] in {"--format", "-f"}
            for index, arg in enumerate(sys.argv)
        )
        or any(arg.startswith("--format=json") for arg in sys.argv)
    )
    if not json_requested and not os.getenv("DR_NO_BANNER"):
        click.echo(BANNER)
    root(prog_name="detection_rules")


main()
