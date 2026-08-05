#!/usr/bin/env python3
"""ELF64 LE helpers for wasmmod metadata sections (.wasmmod.*).

Append is incremental (preserves ET_REL code/symtab). A trailing WPSE cookie
lets strip restore the exact pre-append bytes for stable sign digests.
"""
from __future__ import annotations

import struct

EI_NIDENT = 16
ELFCLASS64 = 2
ELFDATA2LSB = 1
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_NOTE = 7
SHT_NOBITS = 8

Ehdr = struct.Struct("<16sHHIQQQIHHHHHH")
Shdr = struct.Struct("<IIQQQQIIQQ")
# Trailing restore cookie (not covered by e_shoff table).
WPSE_MAGIC = b"WPSE"
WPSE = struct.Struct("<4sQQHHI")  # magic, old_len, old_shoff, old_shnum, old_shstrndx, pad (=28)


def is_elf64_le(buf: bytes) -> bool:
    return (
        len(buf) >= 64
        and buf[:4] == b"\x7fELF"
        and buf[4] == ELFCLASS64
        and buf[5] == ELFDATA2LSB
    )


def _parse_ehdr(buf: bytes) -> dict:
    if not is_elf64_le(buf):
        raise SystemExit("not ELF64 LE")
    (
        _e_ident,
        _e_type,
        _e_machine,
        _e_version,
        _e_entry,
        _e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = Ehdr.unpack_from(buf, 0)
    if e_shnum == 0 or e_shstrndx >= e_shnum or e_shentsize < Shdr.size:
        raise SystemExit("bad ELF section headers")
    sh_end = e_shoff + e_shnum * e_shentsize
    if e_shoff >= len(buf) or sh_end > len(buf):
        raise SystemExit("ELF shdr out of range")
    return {
        "e_shoff": e_shoff,
        "e_shentsize": e_shentsize,
        "e_shnum": e_shnum,
        "e_shstrndx": e_shstrndx,
    }


def _shdr(buf: bytes, eh: dict, i: int) -> dict:
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
    ) = Shdr.unpack_from(buf, off)
    return {
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


def _sh_name(buf: bytes, eh: dict, shstr: dict, name_off: int) -> str | None:
    if shstr["sh_type"] != SHT_STRTAB:
        return None
    base = shstr["sh_offset"] + name_off
    if name_off >= shstr["sh_size"] or base >= len(buf):
        return None
    end = buf.find(b"\x00", base, shstr["sh_offset"] + shstr["sh_size"])
    if end < 0:
        return None
    return buf[base:end].decode("utf-8", errors="replace")


def _name_matches(sec: str | None, want: str) -> bool:
    if sec is None:
        return False
    if sec == want:
        return True
    if want[:1] != "." and sec[:1] == "." and sec[1:] == want:
        return True
    return want[:1] == "." and sec[:1] != "." and sec == want[1:]


def _read_cookie(buf: bytes) -> dict | None:
    if len(buf) < WPSE.size:
        return None
    magic, old_len, old_shoff, old_shnum, old_shstrndx, _pad = WPSE.unpack_from(
        buf, len(buf) - WPSE.size
    )
    if magic != WPSE_MAGIC:
        return None
    if old_len == 0 or old_len > len(buf) - WPSE.size:
        return None
    return {
        "old_len": old_len,
        "old_shoff": old_shoff,
        "old_shnum": old_shnum,
        "old_shstrndx": old_shstrndx,
    }


def find_section(buf: bytes, name: str) -> bytes | None:
    if not is_elf64_le(buf):
        return None
    # Ignore trailing cookie for shdr bounds
    view = buf
    _read_cookie(buf)  # validate cookie; shdr uses full buf
    eh = _parse_ehdr(view)
    shstr = _shdr(view, eh, eh["e_shstrndx"])
    for i in range(eh["e_shnum"]):
        sh = _shdr(view, eh, i)
        if sh["sh_type"] not in (SHT_PROGBITS, SHT_NOTE) or sh["sh_size"] == 0:
            continue
        sn = _sh_name(view, eh, shstr, sh["sh_name"])
        if not _name_matches(sn, name):
            continue
        end = sh["sh_offset"] + sh["sh_size"]
        if end > len(view):
            return None
        return view[sh["sh_offset"] : end]
    return None


def append_section(buf: bytes, name: str, payload: bytes) -> bytes:
    """Append SHT_PROGBITS named .name; write WPSE cookie for exact strip restore."""
    eh = _parse_ehdr(buf)
    sec_name = name if name.startswith(".") else f".{name}"
    name_b = sec_name.encode("utf-8") + b"\x00"
    shstr = _shdr(buf, eh, eh["e_shstrndx"])
    if shstr["sh_type"] != SHT_STRTAB:
        raise SystemExit("ELF missing shstrtab")

    old_len = len(buf)
    # Drop prior cookie if re-appending
    ck = _read_cookie(buf)
    if ck is not None:
        buf = buf[: len(buf) - WPSE.size]
        old_len = len(buf)
        eh = _parse_ehdr(buf)
        shstr = _shdr(buf, eh, eh["e_shstrndx"])

    old_shoff = eh["e_shoff"]
    old_shnum = eh["e_shnum"]
    old_shstrndx = eh["e_shstrndx"]

    out = bytearray(buf)
    cursor = (len(out) + 15) & ~15
    if cursor > len(out):
        out.extend(b"\x00" * (cursor - len(out)))
    payload_off = cursor
    out.extend(payload)
    cursor = len(out)

    cursor = (cursor + 7) & ~7
    if cursor > len(out):
        out.extend(b"\x00" * (cursor - len(out)))
    new_shstr_off = cursor
    old_str = buf[shstr["sh_offset"] : shstr["sh_offset"] + shstr["sh_size"]]
    name_idx = shstr["sh_size"]
    out.extend(old_str)
    out.extend(name_b)
    new_str_size = len(old_str) + len(name_b)
    cursor = len(out)

    hdrs = []
    for i in range(eh["e_shnum"]):
        sh = _shdr(buf, eh, i)
        if i == eh["e_shstrndx"]:
            sh = dict(sh)
            sh["sh_offset"] = new_shstr_off
            sh["sh_size"] = new_str_size
        hdrs.append(sh)
    hdrs.append(
        {
            "sh_name": name_idx,
            "sh_type": SHT_PROGBITS,
            "sh_flags": 0,
            "sh_addr": 0,
            "sh_offset": payload_off,
            "sh_size": len(payload),
            "sh_link": 0,
            "sh_info": 0,
            "sh_addralign": 1,
            "sh_entsize": 0,
        }
    )

    cursor = (len(out) + 7) & ~7
    if cursor > len(out):
        out.extend(b"\x00" * (cursor - len(out)))
    shoff = cursor
    for sh in hdrs:
        out.extend(
            Shdr.pack(
                sh["sh_name"],
                sh["sh_type"],
                sh["sh_flags"],
                sh["sh_addr"],
                sh["sh_offset"],
                sh["sh_size"],
                sh["sh_link"],
                sh["sh_info"],
                sh["sh_addralign"],
                sh["sh_entsize"],
            )
        )

    struct.pack_into("<Q", out, 40, shoff)
    struct.pack_into("<H", out, 60, len(hdrs))
    # Cookie restores exact pre-append image for sign digests.
    out.extend(WPSE.pack(WPSE_MAGIC, old_len, old_shoff, old_shnum, old_shstrndx, 0))
    return bytes(out)


def strip_section(buf: bytes, name: str) -> bytes:
    """Remove named section. Prefer WPSE cookie restore when section was last append."""
    if find_section(buf, name) is None:
        # No section — drop trailing cookie if present so digest is clean artifact.
        ck = _read_cookie(buf)
        if ck is not None:
            return bytes(buf[: len(buf) - WPSE.size])
        return bytes(buf)

    ck = _read_cookie(buf)
    if ck is not None:
        eh = _parse_ehdr(buf)
        shstr = _shdr(buf, eh, eh["e_shstrndx"])
        # If the named section lives at/after old_len, cookie restore is exact.
        for i in range(eh["e_shnum"]):
            sh = _shdr(buf, eh, i)
            sn = _sh_name(buf, eh, shstr, sh["sh_name"])
            if _name_matches(sn, name) and sh["sh_offset"] >= ck["old_len"]:
                out = bytearray(buf[: ck["old_len"]])
                struct.pack_into("<Q", out, 40, ck["old_shoff"])
                struct.pack_into("<H", out, 60, ck["old_shnum"])
                struct.pack_into("<H", out, 62, ck["old_shstrndx"])
                return bytes(out)

    raise SystemExit(
        f"ELF strip of {name!r} needs WPSE cookie (re-pack/sign with current wasmmod_elf)"
    )
