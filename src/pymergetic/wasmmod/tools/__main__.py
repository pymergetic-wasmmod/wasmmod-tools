#!/usr/bin/env python3
"""Unified wasmmod host tooling — ``wasmmod <command> …``.

Install: ``pip install pymergetic-wasmmod-tools`` then ``wasmmod pack …``.
"""

from __future__ import annotations

import sys

COMMANDS: dict[str, str] = {
    "pack": "pack",
    "pack-elf": "pack_elf",
    "pack-tree": "pack_tree",
    "sign": "sign",
    "embed-ca": "embed_ca",
    "embed-host": "embed_host",
    "httpd": "httpd",
    "source": "source",
    "read": "read",
    "zlib": "zlib",
    "publish": "publish",
    "cdn": "cdn",
    "inspect": "inspect",
}


def _load(name: str):
    import importlib

    return importlib.import_module(f"pymergetic.wasmmod.tools.{name}")


def _usage() -> None:
    print((__doc__ or "").strip(), file=sys.stderr)
    print(file=sys.stderr)
    print(f"Commands: {', '.join(COMMANDS)}", file=sys.stderr)
    print("Try: wasmmod <command> -h", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        _usage()
        return 0
    cmd = args[0]
    if cmd not in COMMANDS:
        print(f"wasmmod: unknown command {cmd!r}", file=sys.stderr)
        print(f"Known: {', '.join(COMMANDS)}", file=sys.stderr)
        return 2
    mod = _load(COMMANDS[cmd])
    if not hasattr(mod, "main"):
        raise SystemExit(f"wasmmod: {COMMANDS[cmd]} has no main()")
    sys.argv = [f"wasmmod {cmd}", *args[1:]]
    cli = _load("cliutil")
    return cli.invoke(mod.main, prog=f"wasmmod {cmd}")


if __name__ == "__main__":
    raise SystemExit(main())
