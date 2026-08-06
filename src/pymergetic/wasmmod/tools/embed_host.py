# This file is part of wasmmod, https://github.com/pymergetic/wasmmod
#
# The MIT License (MIT)
#
# Copyright (c) 2026 Rouven Raudzus <raudzus@pymergetic.com>
#
# Embed wasmmod.pack + wasmmod.source into the host engine binary
# (micropython.wasm / unix ELF) for self-description / Inspect.
#
#   wasmmod embed-host PATH/micropython.wasm
#   wasmmod embed-host PATH/micropython --alias pymergetic.wasmmod.elf
#
"""Embed pymergetic.wasmmod identity + curated source into a host artifact."""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

from .elf import strip_section
from .pack import SECTION_NAME, build_pack_payload
from .paths import require_wasmmod_root, wasmmod_root
from .source import (
    SOURCE_SECTION,
    append_custom_section,
    build_source_payload,
    should_include_source_file,
)

HOST_PACKAGE = "pymergetic.wasmmod"
_STRIP_SECTIONS = frozenset({"wasmmod.pack", "wasmmod.source", "wasmmod.sig"})


def _version_from_tree(root: Path) -> str:
    ver_file = root / "VERSION"
    if ver_file.is_file():
        v = ver_file.read_text(encoding="utf-8").strip()
        if v:
            return v
    ver_h = root / "version.h"
    if ver_h.is_file():
        m = re.search(
            r'#define\s+MICROPY_WASM_VERSION\s+"([^"]+)"',
            ver_h.read_text(encoding="utf-8", errors="replace"),
        )
        if m:
            return m.group(1)
    return "0.1.0-alpha"


def _uleb128(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _read_uleb(buf: bytes, i: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, i
        shift += 7
    raise ValueError("truncated wasm")


def strip_named_sections(buf: bytes, names: frozenset[str]) -> bytes:
    """Remove named custom sections from wasm/ELF so re-embed is idempotent."""
    if len(buf) >= 4 and buf[:4] == b"\x7fELF":
        out = buf
        for name in names:
            out = strip_section(out, name)
        return out
    if len(buf) < 8 or buf[:4] != b"\x00asm":
        return buf
    want = {n.encode("utf-8") for n in names}
    out = bytearray(buf[:8])
    i = 8
    while i < len(buf):
        sid = buf[i]
        i += 1
        size, i = _read_uleb(buf, i)
        sec_start = i
        sec_end = i + size
        drop = False
        if sid == 0:
            nlen, j = _read_uleb(buf, i)
            if buf[j : j + nlen] in want:
                drop = True
        if not drop:
            body = buf[sec_start:sec_end]
            out.append(sid)
            out += _uleb128(len(body))
            out += body
        i = sec_end
    return bytes(out)


def collect_host_files(root: Path) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    seen: set[str] = set()

    def add(rel: str, data: bytes) -> None:
        if rel in seen:
            return
        seen.add(rel)
        out.append((rel, data))

    trees = [
        (root / "include", "include"),
        (root / "glue", "glue"),
        (root / "ports" / "micropython" / "webassembly", "ports/micropython/webassembly"),
        (root / "crates" / "pm", "crates/pm"),
    ]
    for base, prefix in trees:
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not should_include_source_file(path, base):
                continue
            rel = f"{prefix}/{path.relative_to(base).as_posix()}"
            add(rel, path.read_bytes())

    for path in sorted(root.glob("*.c")) + sorted(root.glob("*.h")):
        add(path.name, path.read_bytes())

    for rel in (
        "README.md",
        "BRANCHES.md",
        "include/README.md",
        "include/SYMBOLS.md",
        "glue/README.md",
        "docs/PACK.md",
        "ports/PORT.md",
        "ports/micropython/webassembly/README.md",
        "crates/pm/README.md",
    ):
        p = root / rel
        if p.is_file():
            add(rel, p.read_bytes())

    out.sort(key=lambda x: x[0])
    return out


def embed(
    path: Path,
    *,
    wasmmod_root: Path,
    version: str,
    out: Path | None,
    also_alias: Path | None,
) -> int:
    raw = strip_named_sections(path.read_bytes(), _STRIP_SECTIONS)
    files = collect_host_files(wasmmod_root)
    tags = [
        ("role", "host"),
        ("product", "wasmmod"),
        ("org", "pymergetic"),
    ]
    src_payload = build_source_payload(HOST_PACKAGE, version, files, tags, compress=True)
    pack_payload = build_pack_payload(HOST_PACKAGE, [], None, compress=False)

    out_bytes = append_custom_section(raw, SECTION_NAME, pack_payload)
    out_bytes = append_custom_section(out_bytes, SOURCE_SECTION, src_payload)

    dest = out or path
    dest.write_bytes(out_bytes)
    print(
        f"embed-host: {dest} name={HOST_PACKAGE!r} version={version!r} "
        f"files={len(files)} pack={len(pack_payload)}B source={len(src_payload)}B "
        f"total={len(out_bytes)}B (+{len(out_bytes) - len(raw)}B)",
        file=sys.stderr,
    )
    if also_alias:
        also_alias.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dest, also_alias)
        print(f"embed-host: alias → {also_alias}", file=sys.stderr)
    return 0


def main() -> int:
    default_root = wasmmod_root()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("artifact", type=Path, help="Host .wasm or ELF binary")
    ap.add_argument("-o", "--output", type=Path, default=None, help="Write here (default: overwrite)")
    ap.add_argument(
        "--alias",
        type=Path,
        default=None,
        help="Also copy result (e.g. pymergetic.wasmmod.wasm)",
    )
    ap.add_argument("--version", default=None, help="Package version (default: VERSION / version.h)")
    ap.add_argument(
        "--wasmmod-root",
        type=Path,
        default=default_root,
        help="wasmmod checkout to embed (default: auto-detect)",
    )
    args = ap.parse_args()
    root = args.wasmmod_root.resolve() if args.wasmmod_root else require_wasmmod_root()
    if not args.artifact.is_file():
        print(f"embed-host: missing {args.artifact}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"embed-host: missing wasmmod root {root}", file=sys.stderr)
        return 2
    return embed(
        args.artifact,
        wasmmod_root=root,
        version=args.version or _version_from_tree(root),
        out=args.output,
        also_alias=args.alias,
    )


if __name__ == "__main__":
    raise SystemExit(main())
