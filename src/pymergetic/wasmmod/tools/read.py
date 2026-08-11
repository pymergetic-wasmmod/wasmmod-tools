
# This file is part of wasmmod, https://github.com/pymergetic-wasmmod/wasmmod
#
# The MIT License (MIT)
#
# Copyright (c) 2026 Rouven Raudzus <raudzus@pymergetic.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
Host reader for wasmmod.source / wasmmod.sig / container sections on .wasm, .aot, or .elf.

Thin wrapper around the Rust binary (crates/wasmmod-read):

  python3 tools/wasmmod.py read meta PATH.wasm
  python3 tools/wasmmod.py read list PATH.aot
  python3 tools/wasmmod.py read sig PATH.aot
  python3 tools/wasmmod.py read verify --trust ROOT.crt.der PATH
  python3 tools/wasmmod.py read read PATH RELPATH
  python3 tools/wasmmod.py read extract PATH -o DIR
  python3 tools/wasmmod.py read sections PATH
  python3 tools/wasmmod.py read section PATH INDEX [--hex]

Build once:
  cargo build --release -p wasmmod-read
  # → target/release/wasmmod-read

Override binary via WASMMOD_READ=/path/to/wasmmod-read.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .paths import wasmmod_root

WASMMOD_ROOT = wasmmod_root() or Path(__file__).resolve().parents[1]


def find_binary() -> Path:
    env = os.environ.get("WASMMOD_READ")
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return p
        raise SystemExit(f"wasmmod read: WASMMOD_READ not executable: {p}")

    root = wasmmod_root()
    candidates: list[Path] = []
    if root is not None:
        candidates.extend(
            (
                root / "target" / "release" / "wasmmod-read",
                root / "target" / "debug" / "wasmmod-read",
            )
        )
    for cand in candidates:
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand

    which = shutil.which("wasmmod-read")
    if which:
        return Path(which)

    raise SystemExit(
        "wasmmod read: wasmmod-read binary not found.\n"
        "  Build: cargo build --release -p wasmmod-read (in WASMMOD_ROOT)\n"
        "  Or set WASMMOD_READ to the binary path."
    )


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    binary = find_binary()
    # Replace this process so stdout/stderr/signals match a native CLI.
    os.execv(str(binary), [str(binary), *args])
    return 1  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())
