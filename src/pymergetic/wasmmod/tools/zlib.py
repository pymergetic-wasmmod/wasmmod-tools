
# This file is part of wasmmod, https://github.com/pymergetic/wasmmod
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
Whole-artifact zlib envelope (MPZL) for bandwidth / CDN-style delivery.

  tools/wasmmod.py zlib wrap PATH.wasm [-o PATH.wasm.zlib]
  tools/wasmmod.py zlib wrap PATH.elf  [-o PATH.elf.zlib]
  tools/wasmmod.py zlib unwrap PATH.wasm.zlib [-o PATH.wasm]
  tools/wasmmod.py zlib info PATH.elf.zlib

Layout: magic "MPZL" | u32le raw_len | zlib(bytes).

Sign the naked .wasm/.aot/.elf first, then wrap. The loader unwraps before verify.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

MAGIC = b"MPZL"


def wrap_bytes(data: bytes, level: int = 9) -> bytes:
    raw_len = len(data)
    if raw_len > 0xFFFFFFFF:
        raise SystemExit("wasm_zlib: artifact too large")
    z = zlib.compress(data, level)
    return MAGIC + struct.pack("<I", raw_len) + z


def unwrap_bytes(blob: bytes) -> bytes:
    if len(blob) < 8 or blob[:4] != MAGIC:
        raise ValueError("not an MPZL artifact")
    (raw_len,) = struct.unpack_from("<I", blob, 4)
    raw = zlib.decompress(blob[8:])
    if len(raw) != raw_len:
        raise ValueError(f"MPZL length mismatch: got {len(raw)} want {raw_len}")
    return raw


def cmd_wrap(args: argparse.Namespace) -> int:
    src = Path(args.path)
    data = src.read_bytes()
    out = Path(args.output) if args.output else Path(str(src) + ".zlib")
    blob = wrap_bytes(data, args.level)
    out.write_bytes(blob)
    kept = 100.0 * len(blob) / max(1, len(data))
    print(
        f"wrapped {src} → {out}: raw={len(data)}B envelope={len(blob)}B kept={kept:.0f}%",
        file=sys.stderr,
    )
    return 0


def cmd_unwrap(args: argparse.Namespace) -> int:
    src = Path(args.path)
    blob = src.read_bytes()
    data = unwrap_bytes(blob)
    if args.output:
        out = Path(args.output)
    elif str(src).endswith(".zlib"):
        out = Path(str(src)[: -len(".zlib")])
    else:
        out = Path(str(src) + ".unwrapped")
    out.write_bytes(data)
    print(f"unwrapped {src} → {out}: {len(data)}B", file=sys.stderr)
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    src = Path(args.path)
    blob = src.read_bytes()
    if len(blob) < 8 or blob[:4] != MAGIC:
        print(f"{src}: not MPZL", file=sys.stderr)
        return 1
    (raw_len,) = struct.unpack_from("<I", blob, 4)
    kept = 100.0 * len(blob) / max(1, raw_len)
    print(f"magic=MPZL raw_len={raw_len} envelope={len(blob)} kept={kept:.0f}%")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="MPZL whole-artifact zlib wrap/unwrap")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_wrap = sub.add_parser("wrap", help="Wrap .wasm/.aot/.elf into .zlib")
    p_wrap.add_argument("path")
    p_wrap.add_argument("-o", "--output", default=None)
    p_wrap.add_argument("--level", type=int, default=9)
    p_wrap.set_defaults(func=cmd_wrap)

    p_un = sub.add_parser("unwrap", help="Unwrap MPZL back to raw artifact")
    p_un.add_argument("path")
    p_un.add_argument("-o", "--output", default=None)
    p_un.set_defaults(func=cmd_unwrap)

    p_info = sub.add_parser("info", help="Show MPZL envelope stats")
    p_info.add_argument("path")
    p_info.set_defaults(func=cmd_info)

    args = ap.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
