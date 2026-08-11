"""Host-side pack inspect: symbols, addr2line/locations, disasm, mpy-dis.

Also: ``tools/wasmmod.py inspect PATH`` — pack/source/sig summary (rich via CDN
client, else ``_offline_inspect``). Shared with CDN client; no MicroPython.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
import zlib
from collections.abc import Iterable
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parent
TOOLS_DIR = TOOLS
PROG = "wasmmod inspect"

from . import elf as elf

SHT_SYMTAB = 2
SHT_STRTAB = 3
STT_FUNC = 2
STT_OBJECT = 1
STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
EM_X86_64 = 62
EM_AARCH64 = 183
SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2
STT_FILE = 4

Elf64_Sym = struct.Struct("<IBBHQQ")  # name, info, other, shndx, value, size


@dataclass
class Location:
    path: str
    line: int | None = None
    role: str = "dwarf"  # def|decl|include|twin|dwarf|sym


@dataclass
class Symbol:
    name: str
    section_index: int | None
    offset: int
    size: int
    kind: str  # func|data|export|other
    binding: str = ""


@dataclass
class DisasmLine:
    addr: int
    raw: bytes
    text: str


def _iter_shdrs(buf: bytes) -> Iterable[tuple[int, dict, str | None]]:
    if not elf.is_elf64_le(buf):
        return
        yield  # pragma: no cover — make this a generator
    eh = elf._parse_ehdr(buf)
    shstr = elf._shdr(buf, eh, eh["e_shstrndx"])
    for i in range(eh["e_shnum"]):
        sh = elf._shdr(buf, eh, i)
        # extend _shdr keys used below
        off = eh["e_shoff"] + i * eh["e_shentsize"]
        (
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        ) = elf.Shdr.unpack_from(buf, off)
        sh = {
            "sh_name": sh_name,
            "sh_type": sh_type,
            "sh_flags": sh_flags,
            "sh_addr": sh_addr,
            "sh_offset": sh_offset,
            "sh_size": sh_size,
            "sh_link": sh_link,
            "sh_info": sh_info,
            "sh_addralign": sh_addralign,
            "sh_entsize": sh_entsize,
        }
        yield i, sh, elf._sh_name(buf, eh, shstr, sh["sh_name"])


def _eh_machine(buf: bytes) -> int:
    return struct.unpack_from("<H", buf, 18)[0]


def has_dwarf(buf: bytes) -> bool:
    if not elf.is_elf64_le(buf):
        return False
    for _i, _sh, name in _iter_shdrs(buf):
        if name in (".debug_line", ".debug_info"):
            return True
    return False


def list_symbols(buf: bytes) -> list[Symbol]:
    if elf.is_elf64_le(buf):
        return _list_symbols_elf(buf)
    if len(buf) >= 4 and buf[:4] == b"\x00asm":
        return _list_symbols_wasm(buf)
    return []


def _bind_name(info: int) -> str:
    b = info >> 4
    return {STB_LOCAL: "local", STB_GLOBAL: "global", STB_WEAK: "weak"}.get(b, str(b))


def _list_symbols_elf(buf: bytes) -> list[Symbol]:
    out: list[Symbol] = []
    for _i, sh, name in _iter_shdrs(buf):
        if sh["sh_type"] != SHT_SYMTAB or sh["sh_entsize"] < Elf64_Sym.size:
            continue
        link = sh["sh_link"]
        str_sh = None
        for j, sj, _nj in _iter_shdrs(buf):
            if j == link:
                str_sh = sj
                break
        if str_sh is None or str_sh["sh_type"] != SHT_STRTAB:
            continue
        strtab = buf[str_sh["sh_offset"] : str_sh["sh_offset"] + str_sh["sh_size"]]
        n = sh["sh_size"] // sh["sh_entsize"]
        for k in range(n):
            off = sh["sh_offset"] + k * sh["sh_entsize"]
            st_name, st_info, _st_other, st_shndx, st_value, st_size = Elf64_Sym.unpack_from(
                buf, off
            )
            if (
                st_shndx == SHN_UNDEF
                or st_shndx == SHN_ABS
                or st_shndx == SHN_COMMON
                or st_shndx >= SHN_LORESERVE
                or st_name == 0
            ):
                continue
            end = strtab.find(b"\x00", st_name)
            if end < 0:
                continue
            sname = strtab[st_name:end].decode("utf-8", errors="replace")
            if not sname or sname.startswith("."):
                continue
            t = st_info & 0xF
            if t == STT_FILE:
                continue
            if t == STT_FUNC:
                kind = "func"
            elif t == STT_OBJECT:
                kind = "data"
            else:
                kind = "other"
            out.append(
                Symbol(
                    name=sname,
                    section_index=int(st_shndx),
                    offset=int(st_value),
                    size=int(st_size),
                    kind=kind,
                    binding=_bind_name(st_info),
                )
            )
    out.sort(key=lambda s: (s.section_index or 0, s.offset, s.name))
    return out


def _read_uleb_at(buf: bytes, pos: list[int], end: int | None = None) -> int:
    """Read LEB128 u32; ``pos`` is a one-element mutable index."""
    limit = len(buf) if end is None else end
    v = 0
    shift = 0
    while pos[0] < limit:
        b = buf[pos[0]]
        pos[0] += 1
        v |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return v
        shift += 7
        if shift > 35:
            raise ValueError("leb overflow")
    raise ValueError("truncated")


def _wasm_skip_importdesc(buf: bytes, pos: list[int], end: int) -> None:
    """Advance ``pos`` past one importdesc (kind + payload)."""
    if pos[0] >= end:
        raise ValueError("truncated")
    kind = buf[pos[0]]
    pos[0] += 1
    if kind == 0:  # func → typeidx
        _read_uleb_at(buf, pos, end)
    elif kind == 1:  # table → reftype + limits
        if pos[0] >= end:
            raise ValueError("truncated")
        pos[0] += 1
        flags = _read_uleb_at(buf, pos, end)
        _read_uleb_at(buf, pos, end)  # min
        if flags & 1:
            _read_uleb_at(buf, pos, end)  # max
    elif kind == 2:  # mem → limits
        flags = _read_uleb_at(buf, pos, end)
        _read_uleb_at(buf, pos, end)
        if flags & 1:
            _read_uleb_at(buf, pos, end)
    elif kind == 3:  # global → valtype + mut
        if pos[0] + 2 > end:
            raise ValueError("truncated")
        pos[0] += 2
    else:
        raise ValueError("bad import kind")


def _list_symbols_wasm(buf: bytes) -> list[Symbol]:
    """Wasm exports; func exports carry code-section payload offset/size."""
    out: list[Symbol] = []
    if len(buf) < 8 or buf[:4] != b"\x00asm":
        return out

    n_func_imports = 0
    code_sec_index: int | None = None
    # (offset_in_code_payload, entry_nbytes) for each defined function
    code_entries: list[tuple[int, int]] = []
    export_payload: bytes | None = None

    i = 8
    sec_list_i = 0
    try:
        while i < len(buf):
            sid = buf[i]
            i += 1
            pos = [i]
            slen = _read_uleb_at(buf, pos)
            i = pos[0]
            start = i
            end = i + slen
            if end > len(buf):
                break
            if sid == 2:  # import — count func imports (index space base)
                j = [start]
                nimp = _read_uleb_at(buf, j, end)
                for _ in range(nimp):
                    mlen = _read_uleb_at(buf, j, end)
                    j[0] += mlen
                    flen = _read_uleb_at(buf, j, end)
                    j[0] += flen
                    if j[0] >= end:
                        break
                    if buf[j[0]] == 0:
                        n_func_imports += 1
                    _wasm_skip_importdesc(buf, j, end)
            elif sid == 10:  # code
                code_sec_index = sec_list_i
                j = [start]
                ncode = _read_uleb_at(buf, j, end)
                for _ in range(ncode):
                    entry_off = j[0] - start
                    size = _read_uleb_at(buf, j, end)
                    if j[0] + size > end:
                        break
                    entry_end = j[0] + size
                    code_entries.append((entry_off, entry_end - (start + entry_off)))
                    j[0] = entry_end
            elif sid == 7:  # export
                export_payload = buf[start:end]
            i = end
            sec_list_i += 1
    except ValueError:
        pass

    if not export_payload:
        return out
    try:
        j = [0]
        nexp = _read_uleb_at(export_payload, j)
        for _ in range(nexp):
            nlen = _read_uleb_at(export_payload, j)
            name = export_payload[j[0] : j[0] + nlen].decode("utf-8", errors="replace")
            j[0] += nlen
            if j[0] >= len(export_payload):
                break
            kind = export_payload[j[0]]
            j[0] += 1
            idx = _read_uleb_at(export_payload, j)
            off = 0
            sz = 0
            sec_i = code_sec_index
            if kind == 0:  # func
                local = idx - n_func_imports
                if 0 <= local < len(code_entries):
                    off, sz = code_entries[local]
            else:
                sec_i = None
            out.append(
                Symbol(
                    name=name,
                    section_index=sec_i,
                    offset=off,
                    size=sz,
                    kind="export" if kind == 0 else "other",
                    binding="export",
                )
            )
    except ValueError:
        return out
    return out


def addr2line(buf: bytes, addr: int) -> list[Location]:
    """Map address → locations.

    Order: optional pyelftools DWARF → host ``addr2line`` (binutils) → enclosing
    FUNC as ``role=sym``.
    """
    locs = _addr2line_dwarf(buf, addr)
    if locs:
        return locs
    locs = _addr2line_binutils(buf, addr)
    if locs:
        return locs
    if not elf.is_elf64_le(buf):
        return []
    # Enclosing FUNC in .text-relative space (ET_REL values are section offsets).
    best: Symbol | None = None
    for s in _list_symbols_elf(buf):
        if s.kind != "func" or s.size <= 0:
            continue
        if s.offset <= addr < s.offset + s.size and (
            best is None or s.offset >= best.offset
        ):
            best = s
    if best is None:
        return []
    return [Location(path=best.name, line=None, role="sym")]


def _addr2line_binutils(buf: bytes, addr: int) -> list[Location]:
    """Best-effort DWARF via system ``addr2line`` (no pyelftools required)."""
    if not elf.is_elf64_le(buf) or not has_dwarf(buf):
        return []
    import shutil
    import tempfile

    if not shutil.which("addr2line"):
        return []
    try:
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=True) as tmp:
            tmp.write(buf)
            tmp.flush()
            proc = subprocess.run(
                ["addr2line", "-e", tmp.name, "-C", f"{int(addr):x}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
    except (OSError, subprocess.TimeoutExpired):
        return []
    text = (proc.stdout or "").strip().splitlines()[:1]
    if not text:
        return []
    raw = text[0].strip()
    if not raw or raw.startswith("??"):
        return []
    # ``path:line`` or ``path:line:column``
    parts = raw.rsplit(":", 2)
    if len(parts) == 3 and parts[-1].isdigit() and parts[-2].isdigit():
        path_s, line_s = parts[0], parts[-2]
    elif len(parts) >= 2 and parts[-1].isdigit():
        path_s, line_s = parts[0], parts[-1]
    else:
        return []
    try:
        lineno = int(line_s)
    except ValueError:
        return []
    if lineno <= 0 or not path_s:
        return []
    # Prefer pack-relative tails (``src/hello.c``) over absolute build paths.
    path_s = path_s.strip()
    for marker in ("/src/", "/examples/"):
        idx = path_s.find(marker)
        if idx >= 0:
            path_s = path_s[idx + 1 :]
            break
    else:
        if path_s.startswith("/"):
            path_s = Path(path_s).name
    return [Location(path=path_s, line=lineno, role="dwarf")]


def _addr2line_dwarf(buf: bytes, addr: int) -> list[Location]:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return []
    try:
        ef = ELFFile(BytesIO(buf))
        if not ef.has_dwarf_info():
            return []
        dwarf = ef.get_dwarf_info()
        out: list[Location] = []
        for cu in dwarf.iter_CUs():
            lineprog = dwarf.line_program_for_CU(cu)
            if lineprog is None:
                continue
            prev = None
            for entry in lineprog.get_entries():
                state = entry.state
                if state is None:
                    continue
                if prev is not None and prev.address <= addr < state.address:
                    file_entry = lineprog["file_entry"][prev.file - 1]
                    path = file_entry.name
                    if isinstance(path, bytes):
                        path = path.decode("utf-8", errors="replace")
                    out.append(Location(path=str(path), line=int(prev.line), role="dwarf"))
                    return out
                if not state.end_sequence:
                    prev = state
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError):
        return []
    return []


def _line_is_commentish(line: str) -> bool:
    """True for //, /* … */, or ``* …`` / ``*/`` block-comment continuations.

    Bare ``*ptr`` lines are not treated as comments (second char is not
    whitespace or ``/``).
    """
    s = line.strip()
    if not s:
        return False
    if s.startswith(("//", "/*")):
        return True
    if s.startswith("*"):
        return len(s) == 1 or s[1] in " \t/"
    return False


def _source_def_hits(path: str, text: str, name: str) -> list[tuple[int, str]]:
    """Return (1-based line, role) for definition-like hits — not bare call sites."""
    hits: list[tuple[int, str]] = []
    lines = text.splitlines()
    if path.endswith((".py", ".pyi")):
        py_def = re.compile(rf"^\s*(?:async\s+)?def\s+{re.escape(name)}\s*\(")
        for i, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            if py_def.search(line):
                hits.append((i, "twin"))
        return hits
    if path.endswith(".rs"):
        rs_fn = re.compile(rf"^\s*(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(name)}\s*[<(]")
        for i, line in enumerate(lines, 1):
            if _line_is_commentish(line):
                continue
            if rs_fn.search(line):
                hits.append((i, "def"))
        return hits
    # C/C++: def needs a body `{`; headers keep prototypes ending in `;`.
    # Also accept ``name(...)`` on one line and ``{`` on the next.
    same_line_def = re.compile(rf"\b{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{")
    proto = re.compile(rf"\b{re.escape(name)}\s*\([^;{{}}]*\)\s*;")
    open_sig = re.compile(rf"\b{re.escape(name)}\s*\([^;{{}}]*\)\s*$")
    is_header = path.endswith((".h", ".hpp", ".hh"))
    for i, line in enumerate(lines):
        lineno = i + 1
        if _line_is_commentish(line):
            continue
        if same_line_def.search(line):
            hits.append((lineno, "decl" if is_header else "def"))
            continue
        if is_header and proto.search(line):
            hits.append((lineno, "decl"))
            continue
        if open_sig.search(line) and not is_header:
            # Look ahead for a line that is only `{` (K&R / split signature).
            for j in range(i + 1, min(i + 4, len(lines))):
                nxt = lines[j].strip()
                if not nxt or _line_is_commentish(lines[j]):
                    continue
                if nxt.startswith("{"):
                    hits.append((lineno, "def"))
                break
    return hits


def _is_code_source_path(path: str) -> bool:
    """True for paths worth scanning for symbol defs (not README.md / docs/)."""
    if not path or path.endswith(".mpy"):
        return False
    norm = path.replace("\\", "/").lstrip("./").lower()
    if norm.startswith("docs/") or "/docs/" in f"/{norm}":
        return False
    return norm.endswith(
        (".py", ".pyi", ".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".rs")
    )


def _inflate_blob(data: bytes, *, zlib_flag: bool, raw_len: int) -> bytes | None:
    if not zlib_flag:
        return data
    try:
        out = zlib.decompress(data)
    except zlib.error:
        return None
    if len(out) != raw_len:
        return None
    return out


def _embedded_code_sources(buf: bytes) -> dict[str, str]:
    """path→text from wasmmod.source (preferred) then wasmmod.pack text files."""
    out: dict[str, str] = {}
    source = _load("wasmmod_source")
    try:
        payload = source.extract_custom_section(buf, "wasmmod.source")
    except (OSError, ValueError, TypeError, AttributeError):
        payload = None
    if payload:
        try:
            meta = source.parse_source_payload(payload)
            for entry in meta.get("files") or []:
                path = entry.get("path") or ""
                if not _is_code_source_path(path):
                    continue
                try:
                    raw = source.read_file_entry(entry)
                    text = raw.decode("utf-8")
                except (OSError, ValueError, TypeError, UnicodeDecodeError, KeyError):
                    continue
                if "\x00" in text:
                    continue
                out[path] = text
        except (OSError, ValueError, TypeError, KeyError, struct.error):
            pass
    try:
        pack_payload = source.extract_custom_section(buf, "wasmmod.pack")
    except (OSError, ValueError, TypeError, AttributeError):
        pack_payload = None
    if not pack_payload or len(pack_payload) < 12 or pack_payload[:4] != b"MPWP":
        return out
    try:
        version = struct.unpack_from("<H", pack_payload, 4)[0]
        name_len = struct.unpack_from("<H", pack_payload, 8)[0]
        i = 10 + name_len
        n_files = struct.unpack_from("<I", pack_payload, i)[0]
        i += 4
        for _ in range(n_files):
            pl = struct.unpack_from("<H", pack_payload, i)[0]
            i += 2
            path = pack_payload[i : i + pl].decode("utf-8", errors="replace")
            i += pl
            kind = pack_payload[i]
            i += 1
            if version >= 3:
                fflags = pack_payload[i]
                i += 1
                raw_len, data_len = struct.unpack_from("<II", pack_payload, i)
                i += 8
                blob = pack_payload[i : i + data_len]
                i += data_len
                if path in out or kind not in (1, 3) or not _is_code_source_path(path):
                    continue
                raw = _inflate_blob(blob, zlib_flag=bool(fflags & 1), raw_len=raw_len)
            else:
                data_len = struct.unpack_from("<I", pack_payload, i)[0]
                i += 4
                blob = pack_payload[i : i + data_len]
                i += data_len
                if path in out or kind not in (1, 3) or not _is_code_source_path(path):
                    continue
                raw = blob
            if raw is None:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if "\x00" in text:
                continue
            out[path] = text
    except (struct.error, IndexError, ValueError):
        pass
    return out


_ROLE_RANK = {
    "dwarf": 0,
    "def": 1,
    "decl": 2,
    "twin": 3,
    "sym": 9,
}


def _collapse_locations(locs: list[Location]) -> list[Location]:
    """One chip per source line: merge dwarf+def on the same file:line.

    Basename keys so ``hello.c:4`` and ``src/hello.c:4`` collapse; keep the
    best role and the longest path.
    """
    best: dict[tuple[object, ...], Location] = {}
    order: list[tuple[object, ...]] = []
    for loc in locs:
        if loc.line is not None:
            key: tuple[object, ...] = ("L", loc.path.rsplit("/", 1)[-1], loc.line)
        else:
            key = ("N", loc.path, loc.role)
        cur = best.get(key)
        if cur is None:
            order.append(key)
            best[key] = loc
            continue
        rank_new = _ROLE_RANK.get(loc.role, 5)
        rank_old = _ROLE_RANK.get(cur.role, 5)
        path = loc.path if len(loc.path) >= len(cur.path) else cur.path
        role = loc.role if rank_new < rank_old else cur.role
        if rank_new == rank_old and len(loc.path) > len(cur.path):
            role = loc.role
        best[key] = Location(path=path, line=loc.line, role=role)
    out = [best[k] for k in order]
    out.sort(key=lambda l: (_ROLE_RANK.get(l.role, 5), l.path))
    return out


def locations_for_symbol(
    buf: bytes,
    name: str,
    *,
    source_files: dict[str, str] | None = None,
) -> list[Location]:
    locs: list[Location] = []
    for s in list_symbols(buf):
        if s.name != name:
            continue
        if s.kind == "func" and s.size > 0:
            locs.extend(addr2line(buf, s.offset))
        locs.append(Location(path=s.name, line=None, role="sym"))
        break
    sources = source_files if source_files is not None else _embedded_code_sources(buf)
    if sources:
        for path, text in sources.items():
            for line_no, role in _source_def_hits(path, text, name):
                locs.append(Location(path=path, line=line_no, role=role))
    return _collapse_locations(locs)


def _section_by_index(buf: bytes, index: int) -> tuple[str | None, bytes]:
    for i, sh, name in _iter_shdrs(buf):
        if i == index:
            data = buf[sh["sh_offset"] : sh["sh_offset"] + sh["sh_size"]]
            return name, data
    return None, b""


def disasm(
    buf: bytes, section_index: int, offset: int = 0, limit: int = 64
) -> list[DisasmLine]:
    if elf.is_elf64_le(buf):
        name, data = _section_by_index(buf, section_index)
        chunk = data[offset : offset + limit]
        if name and name.startswith(".text"):
            lines = _disasm_capstone(chunk, offset, _eh_machine(buf))
            if lines:
                return lines
        return _disasm_db(chunk, offset)
    if len(buf) >= 4 and buf[:4] == b"\x00asm":
        # section_index is Wasm section list index from list_sections — walk
        return _disasm_wasm_code(buf, offset, limit)
    return []


def _disasm_db(data: bytes, base: int) -> list[DisasmLine]:
    out: list[DisasmLine] = []
    for i in range(0, len(data), 8):
        raw = data[i : i + 8]
        text = " ".join(f"{b:02x}" for b in raw)
        out.append(DisasmLine(addr=base + i, raw=raw, text=f"db {text}"))
    return out


def _disasm_capstone(data: bytes, base: int, em: int) -> list[DisasmLine]:
    try:
        from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, Cs
    except ImportError:
        return []
    if em == EM_X86_64:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif em == EM_AARCH64:
        md = Cs(CS_ARCH_ARM64, CS_MODE_64)
    else:
        return []
    out: list[DisasmLine] = []
    for insn in md.disasm(data, base):
        raw = bytes(insn.bytes)
        out.append(DisasmLine(addr=insn.address, raw=raw, text=f"{insn.mnemonic} {insn.op_str}".strip()))
    return out


_WASM_OP = {
    0x0B: "end",
    0x10: "call",
    0x20: "local.get",
    0x21: "local.set",
    0x41: "i32.const",
    0x42: "i64.const",
    0x6A: "i32.add",
}


def _disasm_wasm_code(buf: bytes, offset: int, limit: int) -> list[DisasmLine]:
    # Find code section payload and disassemble a window of body bytes.
    i = 8

    def read_u32_at(pos: list[int]) -> int:
        v = 0
        shift = 0
        while pos[0] < len(buf):
            b = buf[pos[0]]
            pos[0] += 1
            v |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return v
            shift += 7
        raise ValueError("truncated")

    try:
        pos = [i]
        while pos[0] < len(buf):
            sid = buf[pos[0]]
            pos[0] += 1
            slen = read_u32_at(pos)
            start = pos[0]
            if sid == 10:  # code
                body = buf[start : start + slen]
                chunk = body[offset : offset + limit]
                out: list[DisasmLine] = []
                j = 0
                while j < len(chunk):
                    op = chunk[j]
                    name = _WASM_OP.get(op, f"op_{op:02x}")
                    out.append(DisasmLine(addr=offset + j, raw=bytes([op]), text=name))
                    j += 1
                    if len(out) >= 64:
                        break
                return out
            pos[0] = start + slen
    except ValueError:
        pass
    return []


def mpy_disasm(mpy: bytes, limit: int = 80) -> list[DisasmLine]:
    """Basic .mpy dump: header + bytecode bytes as op_* lines."""
    out: list[DisasmLine] = []
    if len(mpy) < 4:
        return [DisasmLine(addr=0, raw=mpy, text="truncated mpy")]
    # MPY magic varies; show header words then raw ops.
    out.append(DisasmLine(addr=0, raw=mpy[:4], text=f"mpy_hdr {mpy[:4]!r}"))
    body = mpy[4:]
    n = min(len(body), limit)
    for i in range(n):
        b = body[i]
        out.append(DisasmLine(addr=4 + i, raw=bytes([b]), text=f"bc 0x{b:02x}"))
    return out


def _load(stem: str):
    """Load a tools submodule by legacy wasmmod_* stem or short name."""
    import importlib
    name = stem
    if name.startswith("wasmmod_"):
        name = name[len("wasmmod_") :]
    elif name == "wasmmod":
        name = "__main__"
    return importlib.import_module(f"pymergetic.wasmmod.tools.{name}")



def _cli():
    return _load("wasmmod_cliutil")


def _offline_inspect(path: Path) -> dict[str, Any]:
    """Compose a basic summary without the PyPI client (MPZL-aware)."""
    out: dict[str, Any] = {"path": str(path), "offline": True}
    source = _load("wasmmod_source")
    data = path.read_bytes()
    try:
        if data[:4] == b"MPZL":
            zmod = _load("wasmmod_zlib")
            data = zmod.unwrap_bytes(data)
        payload = source.extract_custom_section(data, "wasmmod.source")
        if payload:
            meta = source.parse_source_payload(payload)
            out["source_name"] = meta.get("name")
            out["source_version"] = meta.get("pkg_version")
            out["source_files"] = [
                e.get("path") for e in (meta.get("files") or []) if isinstance(e, dict)
            ]
        else:
            out["source_files"] = []
    except Exception as exc:
        out["source_error"] = str(exc)

    try:
        pack = _load("wasmmod_pack")
        deps_sec = None
        if hasattr(pack, "extract_custom_section"):
            deps_sec = pack.extract_custom_section(data, pack.DEPS_SECTION)
        else:
            deps_sec = source.extract_custom_section(data, "wasmmod.deps")
        if deps_sec:
            out["deps"] = [
                {"name": n, "version": v} for n, v in pack.parse_deps_payload(deps_sec)
            ]
        else:
            out["deps"] = []
    except Exception as exc:
        out["deps_error"] = str(exc)

    try:
        out["has_dwarf"] = has_dwarf(data)
        out["symbols"] = [
            {"name": s.name, "kind": s.kind, "offset": s.offset, "size": s.size}
            for s in list_symbols(data)[:32]
        ]
    except Exception as exc:
        out["symbols_error"] = str(exc)

    import contextlib
    import io

    from . import sign

    try:
        buf = io.StringIO()
        old_argv = sys.argv
        try:
            sys.argv = ["wasmmod sign", "info", str(path)]
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                try:
                    rc = sign.main()
                except SystemExit as exc:
                    rc = int(exc.code) if isinstance(exc.code, int) else 1
        finally:
            sys.argv = old_argv
        out["sign_info"] = buf.getvalue().strip()
        if rc and not out["sign_info"]:
            out["sign_error"] = f"exit {rc}"
    except OSError as exc:
        out["sign_error"] = str(exc)
    return out


def _print_rich(contents: Any) -> None:
    dump = contents.model_dump() if hasattr(contents, "model_dump") else contents
    if not isinstance(dump, dict):
        print(dump)
        return
    print(f"kind={dump.get('kind')} encoding={dump.get('encoding')} signed={dump.get('signed')}")
    if dump.get("has_dwarf") is not None:
        print(f"has_dwarf={dump.get('has_dwarf')}")
    if dump.get("error"):
        print(f"error: {dump['error']}")
    pack = dump.get("pack")
    if isinstance(pack, dict):
        print(f"pack: {pack.get('name')} v{pack.get('version')}")
        for f in pack.get("files") or []:
            if isinstance(f, dict):
                print(f"  pack/{f.get('path')}  {f.get('kind')}  {f.get('raw_len')}B")
    source = dump.get("source")
    if isinstance(source, dict):
        print(f"source: {source.get('name')} {source.get('pkg_version') or ''}".rstrip())
        for f in source.get("files") or []:
            if isinstance(f, dict):
                print(f"  src/{f.get('path')}  {f.get('raw_len')}B")
    sig = dump.get("sig")
    if isinstance(sig, dict):
        print(
            f"sig: format={sig.get('format')} flags={sig.get('flags')} "
            f"sig_len={sig.get('sig_len')} chain_len={sig.get('chain_len')}"
        )
    elif dump.get("sig_error"):
        print(f"sig error: {dump['sig_error']}")
    deps = dump.get("deps")
    if isinstance(deps, list) and deps:
        print("deps:")
        for d in deps:
            if isinstance(d, dict):
                print(f"  {d.get('name')}@{d.get('version')}")
            else:
                print(f"  {d}")
    elif dump.get("deps_error"):
        print(f"deps error: {dump['deps_error']}")
    syms = dump.get("symbols")
    if isinstance(syms, list) and syms:
        print(f"symbols ({len(syms)}):")
        for s in syms[:24]:
            if isinstance(s, dict):
                print(
                    f"  {s.get('kind', '?'):6} +0x{int(s.get('offset') or 0):04x} "
                    f"{s.get('name')}"
                )


_OPS = frozenset({"symbols", "addr2line", "locations", "disasm", "mpy", "has-dwarf"})


def _main_ops(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("symbols")
    p.add_argument("path", type=Path)

    p = sub.add_parser("addr2line")
    p.add_argument("path", type=Path)
    p.add_argument("addr", type=lambda s: int(s, 0))

    p = sub.add_parser("locations")
    p.add_argument("path", type=Path)
    p.add_argument("name")

    p = sub.add_parser("disasm")
    p.add_argument("path", type=Path)
    p.add_argument("index", type=int)
    p.add_argument("offset", type=int, nargs="?", default=0)
    p.add_argument("limit", type=int, nargs="?", default=64)

    p = sub.add_parser("mpy")
    p.add_argument("path", type=Path)

    p = sub.add_parser("has-dwarf")
    p.add_argument("path", type=Path)

    args = ap.parse_args(argv)
    data = args.path.read_bytes()
    if data[:4] == b"MPZL":
        try:
            data = _load("wasmmod_zlib").unwrap_bytes(data)
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    if args.cmd == "symbols":
        for s in list_symbols(data):
            print(f"{s.kind:6} {s.binding:6} +0x{s.offset:04x} sz={s.size:<5} {s.name}")
        return 0
    if args.cmd == "addr2line":
        for loc in addr2line(data, args.addr):
            ln = "" if loc.line is None else f":{loc.line}"
            print(f"{loc.role:6} {loc.path}{ln}")
        return 0
    if args.cmd == "locations":
        for loc in locations_for_symbol(data, args.name):
            ln = "" if loc.line is None else f":{loc.line}"
            print(f"{loc.role:6} {loc.path}{ln}")
        return 0
    if args.cmd == "disasm":
        for line in disasm(data, args.index, args.offset, args.limit):
            hx = line.raw.hex()
            print(f"0x{line.addr:04x}: {hx:<16} {line.text}")
        return 0
    if args.cmd == "mpy":
        for line in mpy_disasm(data):
            print(f"0x{line.addr:04x}: {line.text}")
        return 0
    if args.cmd == "has-dwarf":
        print("yes" if has_dwarf(data) else "no")
        return 0
    return 2


def _main_artifact(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", type=Path, help="Local .wasm / .aot / .elf / .zlib")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--verify", action="store_true", help="Verify MPWS against --trust roots")
    ap.add_argument(
        "--trust",
        type=Path,
        action="append",
        default=[],
        help="Root CA PEM/DER (repeatable); used with --verify",
    )
    args = ap.parse_args(argv)
    cli = _cli()
    path: Path = args.path
    if not path.is_file():
        cli.die(PROG, f"not a file: {path}")

    data = path.read_bytes()
    rich = None
    try:
        from pymergetic.wasmmod.cdn_client.contents import inspect_artifact

        rich = inspect_artifact(data, filename=path.name)
    except ImportError:
        rich = None

    if args.verify:
        roots = [p.read_bytes() for p in args.trust]
        if not roots:
            cli.die(PROG, "--verify requires at least one --trust root")
        try:
            from pymergetic.wasmmod.cdn_client.verify import verify_artifact

            result = verify_artifact(data, trust_roots=roots, filename=path.name)
            if args.json:
                print(
                    json.dumps(
                        {
                            "ok": result.ok,
                            "error": result.error,
                            "signed": result.signed,
                            "format": result.format,
                            "leaf_sha256": result.leaf_sha256,
                        },
                        indent=2,
                    )
                )
            else:
                if result.ok:
                    print(f"verify: ok ({result.format})")
                else:
                    print(f"verify: FAIL — {result.error}", file=sys.stderr)
                    return 1
            if rich is None:
                return 0 if result.ok else 1
        except ImportError:
            from . import sign

            old_argv = sys.argv
            try:
                sys.argv = ["wasmmod sign", "verify", str(path)]
                for root in args.trust:
                    sys.argv.extend(["--trust", str(root)])
                rc = sign.main()
            finally:
                sys.argv = old_argv
            if rc:
                return rc

    if rich is not None:
        if args.json:
            dump = rich.model_dump() if hasattr(rich, "model_dump") else rich
            print(json.dumps(dump, indent=2, default=str))
        else:
            _print_rich(rich)
        return 0

    summary = _offline_inspect(path)
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
        return 0
    print(f"path: {path} (offline inspect — install client for full dump)")
    if summary.get("has_dwarf") is not None:
        print(f"has_dwarf={summary.get('has_dwarf')}")
    if summary.get("source_files"):
        print("source files:")
        for p in summary["source_files"]:
            print(f"  {p}")
    if summary.get("source_error"):
        print(f"source: {summary['source_error']}")
    deps = summary.get("deps")
    if isinstance(deps, list) and deps:
        print("deps:")
        for d in deps:
            if isinstance(d, dict):
                print(f"  {d.get('name')}@{d.get('version')}")
    elif summary.get("deps_error"):
        print(f"deps: {summary['deps_error']}")
    syms = summary.get("symbols")
    if isinstance(syms, list) and syms:
        print(f"symbols ({len(syms)}):")
        for s in syms:
            print(f"  {s.get('kind', '?'):6} +0x{int(s.get('offset') or 0):04x} {s.get('name')}")
    if summary.get("sign_info"):
        print(summary["sign_info"])
    if summary.get("sign_error"):
        print(f"sign: {summary['sign_error']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in _OPS:
        return _main_ops(args)
    return _main_artifact(args)


if __name__ == "__main__":
    raise SystemExit(_cli().invoke(main, prog=PROG))
