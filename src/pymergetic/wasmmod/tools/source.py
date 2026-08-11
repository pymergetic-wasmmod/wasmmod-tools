
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
Build / inspect the wasmmod.source custom section (MPSR per-file table).

  tools/wasmmod.py source meta PATH.wasm
  tools/wasmmod.py source list PATH.wasm
  tools/wasmmod.py source read PATH.wasm RELPATH
  tools/wasmmod.py source extract PATH.wasm -o DIR
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

SOURCE_SECTION = "wasmmod.source"
SOURCE_MAGIC = b"MPSR"
SOURCE_VERSION = 1
FILE_FLAG_ZLIB = 1 << 0

# Skip build artifacts / noise when collecting a pack tree for source.
SOURCE_SKIP_NAMES = frozenset(
    {
        "Makefile",
        "CMakeLists.txt",
        ".gitignore",
        ".git",
        "__pycache__",
        "build",
        "target",
        ".tools",
    }
)
SOURCE_SKIP_SUFFIXES = frozenset(
    {
        ".wasm",
        ".aot",
        ".elf",
        ".mpack",
        ".sig",
        ".crt",
        ".o",
        ".obj",
        ".a",
        ".so",
        ".dylib",
        ".pyc",
        ".pyo",
    }
)

COMPRESS_THRESHOLD = 64


def uleb128(n: int) -> bytes:
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


def extract_wasm_custom_section(wasm: bytes, section_name: str) -> bytes | None:
    if len(wasm) < 8 or wasm[:4] != b"\x00asm":
        return None
    name_b = section_name.encode("utf-8")
    i = 8
    while i < len(wasm):
        sid = wasm[i]
        i += 1
        size, i = _read_uleb(wasm, i)
        sec_end = i + size
        if sid == 0:
            nlen, j = _read_uleb(wasm, i)
            if wasm[j : j + nlen] == name_b:
                return wasm[j + nlen : sec_end]
        i = sec_end
    return None


# WAMR AOT file: same named payloads via section type 100 / RAW sub-type 0.
AOT_SECTION_TYPE_CUSTOM = 100
AOT_CUSTOM_SECTION_RAW = 0


def extract_aot_custom_section(aot: bytes, section_name: str) -> bytes | None:
    if len(aot) < 8 or aot[:4] != b"\x00aot":
        return None
    want = section_name.encode("utf-8")
    p = 8
    while p + 8 <= len(aot):
        typ, size = struct.unpack_from("<II", aot, p)
        content = p + 8
        end = content + size
        if end > len(aot) or size > 0x10000000:
            return None
        if typ == AOT_SECTION_TYPE_CUSTOM and size >= 6:
            sub = struct.unpack_from("<I", aot, content)[0]
            if sub == AOT_CUSTOM_SECTION_RAW:
                slen = struct.unpack_from("<H", aot, content + 4)[0]
                name_off = content + 6
                if name_off + slen <= end:
                    name_bytes = aot[name_off : name_off + slen]
                    # EMIT_STR stores strlen+1 including trailing NUL.
                    bare = name_bytes[:-1] if name_bytes.endswith(b"\x00") else name_bytes
                    if bare == want:
                        return aot[name_off + slen : end]
        p = (end + 3) & ~3
    return None


def extract_custom_section(buf: bytes, section_name: str) -> bytes | None:
    """Named custom payload from a .wasm, .aot, or .elf (1:1 section names)."""
    if len(buf) >= 4 and buf[:4] == b"\x00asm":
        return extract_wasm_custom_section(buf, section_name)
    if len(buf) >= 4 and buf[:4] == b"\x00aot":
        return extract_aot_custom_section(buf, section_name)
    if len(buf) >= 4 and buf[:4] == b"\x7fELF":
        from .elf import find_section

        return find_section(buf, section_name)
    return None


def append_custom_section(wasm: bytes, section_name: str, payload: bytes) -> bytes:
    if len(wasm) >= 4 and wasm[:4] == b"\x7fELF":
        from .elf import append_section

        return append_section(wasm, section_name, payload)
    name_b = section_name.encode("utf-8")
    body = uleb128(len(name_b)) + name_b + payload
    return wasm + bytes([0]) + uleb128(len(body)) + body


def should_include_source_file(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    parts = rel.parts
    if any(p in SOURCE_SKIP_NAMES or p.startswith(".") for p in parts):
        return False
    if path.suffix in SOURCE_SKIP_SUFFIXES:
        return False
    if not path.is_file():
        return False
    return True


def collect_source_files(pack_root: Path) -> list[tuple[str, bytes]]:
    """Collect pack-tree files (minus build artifacts) as (posix_rel, bytes)."""
    root = pack_root.resolve()
    out: list[tuple[str, bytes]] = []
    for path in sorted(root.rglob("*")):
        if not should_include_source_file(path, root):
            continue
        rel = path.relative_to(root).as_posix()
        if rel.startswith("../") or "/../" in f"/{rel}/":
            raise SystemExit(f"wasm_source: refusing path {rel}")
        out.append((rel, path.read_bytes()))
    return out


def build_source_payload(
    name: str,
    version: str,
    files: list[tuple[str, bytes]],
    tags: list[tuple[str, str]] | None = None,
    *,
    compress: bool = True,
) -> bytes:
    name_b = name.encode("utf-8")
    ver_b = version.encode("utf-8")
    if len(name_b) > 0xFFFF or len(ver_b) > 0xFFFF:
        raise SystemExit("wasm_source: name/version too long")
    tags = tags or []
    if len(tags) > 0xFFFF:
        raise SystemExit("wasm_source: too many tags")

    out = bytearray()
    out += SOURCE_MAGIC
    out += struct.pack("<HH", SOURCE_VERSION, 0)
    out += struct.pack("<H", len(name_b))
    out += name_b
    out += struct.pack("<H", len(ver_b))
    out += ver_b
    out += struct.pack("<H", len(tags))
    for k, v in tags:
        kb, vb = k.encode("utf-8"), v.encode("utf-8")
        if len(kb) > 0xFFFF or len(vb) > 0xFFFF:
            raise SystemExit(f"wasm_source: tag too long: {k}={v}")
        out += struct.pack("<H", len(kb))
        out += kb
        out += struct.pack("<H", len(vb))
        out += vb

    out += struct.pack("<I", len(files))
    for rel, data in files:
        rel_b = rel.encode("utf-8")
        if len(rel_b) > 0xFFFF:
            raise SystemExit(f"wasm_source: path too long: {rel}")
        raw_len = len(data)
        flags = 0
        payload = data
        if compress and raw_len >= COMPRESS_THRESHOLD:
            z = zlib.compress(data, 9)
            if len(z) < raw_len:
                payload = z
                flags |= FILE_FLAG_ZLIB
        out += struct.pack("<H", len(rel_b))
        out += rel_b
        out += struct.pack("<B", flags)
        out += struct.pack("<I", raw_len)
        out += struct.pack("<I", len(payload))
        out += payload
    return bytes(out)


def parse_source_payload(payload: bytes) -> dict:
    if len(payload) < 12 or payload[:4] != SOURCE_MAGIC:
        raise ValueError("not a wasmmod.source payload")
    version, flags = struct.unpack_from("<HH", payload, 4)
    if version != SOURCE_VERSION:
        raise ValueError(f"unsupported source version {version}")
    name_len = struct.unpack_from("<H", payload, 8)[0]
    i = 10
    name = payload[i : i + name_len].decode("utf-8")
    i += name_len
    ver_len = struct.unpack_from("<H", payload, i)[0]
    i += 2
    pkg_version = payload[i : i + ver_len].decode("utf-8")
    i += ver_len
    n_tags = struct.unpack_from("<H", payload, i)[0]
    i += 2
    tags: list[tuple[str, str]] = []
    for _ in range(n_tags):
        kl = struct.unpack_from("<H", payload, i)[0]
        i += 2
        k = payload[i : i + kl].decode("utf-8")
        i += kl
        vl = struct.unpack_from("<H", payload, i)[0]
        i += 2
        v = payload[i : i + vl].decode("utf-8")
        i += vl
        tags.append((k, v))
    n_files = struct.unpack_from("<I", payload, i)[0]
    i += 4
    files: list[dict] = []
    for _ in range(n_files):
        pl = struct.unpack_from("<H", payload, i)[0]
        i += 2
        path = payload[i : i + pl].decode("utf-8")
        i += pl
        fflags = payload[i]
        i += 1
        raw_len, data_len = struct.unpack_from("<II", payload, i)
        i += 8
        data = payload[i : i + data_len]
        i += data_len
        files.append(
            {
                "path": path,
                "flags": fflags,
                "raw_len": raw_len,
                "data": data,
            }
        )
    return {
        "version": version,
        "flags": flags,
        "name": name,
        "pkg_version": pkg_version,
        "tags": tags,
        "files": files,
    }


def read_file_entry(entry: dict) -> bytes:
    data = entry["data"]
    if entry["flags"] & FILE_FLAG_ZLIB:
        raw = zlib.decompress(data)
        if len(raw) != entry["raw_len"]:
            raise ValueError(f"bad inflated size for {entry['path']}")
        return raw
    return data


def open_source_from_wasm(wasm: bytes) -> dict:
    payload = extract_custom_section(wasm, SOURCE_SECTION)
    if payload is None:
        raise ValueError(f"no {SOURCE_SECTION!r} section")
    return parse_source_payload(payload)


def embed_source_section(
    wasm: bytes,
    pack_root: Path,
    name: str,
    version: str,
    tags: list[tuple[str, str]] | None = None,
    *,
    compress: bool = True,
) -> tuple[bytes, int, int]:
    files = collect_source_files(pack_root)
    payload = build_source_payload(name, version, files, tags, compress=compress)
    out = append_custom_section(wasm, SOURCE_SECTION, payload)
    return out, len(files), len(payload)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_meta = sub.add_parser("meta", help="Print name/version/tags/file count")
    p_meta.add_argument("wasm", type=Path)

    p_list = sub.add_parser("list", help="List stored paths")
    p_list.add_argument("wasm", type=Path)

    p_read = sub.add_parser("read", help="Read one stored path to stdout (binary)")
    p_read.add_argument("wasm", type=Path)
    p_read.add_argument("path")

    p_ex = sub.add_parser("extract", help="Extract all source files to a directory")
    p_ex.add_argument("wasm", type=Path)
    p_ex.add_argument("-o", "--output", type=Path, required=True)

    args = ap.parse_args()
    wasm = args.wasm.read_bytes()
    try:
        info = open_source_from_wasm(wasm)
    except ValueError as e:
        raise SystemExit(f"wasm_source: {e}") from e

    if args.cmd == "meta":
        print(f"name={info['name']}")
        print(f"version={info['pkg_version']}")
        print(f"format={info['version']}")
        print(f"files={len(info['files'])}")
        for k, v in info["tags"]:
            print(f"tag {k}={v}")
        return 0

    if args.cmd == "list":
        for f in info["files"]:
            z = "z" if f["flags"] & FILE_FLAG_ZLIB else "-"
            print(f"{z} {f['raw_len']:8d} {f['path']}")
        return 0

    if args.cmd == "read":
        for f in info["files"]:
            if f["path"] == args.path:
                sys.stdout.buffer.write(read_file_entry(f))
                return 0
        raise SystemExit(f"wasm_source: path not found: {args.path}")

    if args.cmd == "extract":
        out: Path = args.output
        out.mkdir(parents=True, exist_ok=True)
        for f in info["files"]:
            dest = out / f["path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(read_file_entry(f))
        print(f"extracted {len(info['files'])} files → {out}", file=sys.stderr)
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
