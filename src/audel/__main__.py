"""Minimal CLI stub for the placeholder release."""

from __future__ import annotations

import sys

from . import __version__


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] in {"-V", "--version", "version"}:
        print(f"audel {__version__}")
        return 0
    print(
        f"audel {__version__} — Ears for AI Agents (placeholder release).\n"
        "The graded audio API is in active development: "
        "https://github.com/amitpatole/audel"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
