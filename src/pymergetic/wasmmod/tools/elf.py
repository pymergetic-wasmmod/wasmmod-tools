"""ELF LE helpers for wasmmod metadata sections (.wasmmod.*).

Supports ELF64 and ELF32 (BIOS trampoline is ELF32 i386). Append is
incremental; a trailing WPSE cookie lets strip restore the exact pre-append
bytes for stable sign digests.
"""
from __future__ import annotations

import struct

EI_NIDENT = 16
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_NOTE = 7
SHT_NOBITS = 8

# ELF64
Ehdr64 = struct.Struct("<16sHHIQQQIHHHHHH")
Shdr64 = struct.Struct("<IIQQQQIIQQ")
# ELF32
Ehdr32 = struct.Struct("<16sHHIIIIIHHHHHH")
Shdr32 = struct.Struct("<IIIIIIIIII")

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


def is_elf32_le(buf: bytes) -> bool:
    return (
        len(buf) >= 52
        and buf[:4] == b"\x7fELF"
        and buf[4] == ELFCLASS32
        and buf[5] == ELFDATA2LSB
    )


def is_elf_le(buf: bytes) -> bool:
    return is_elf64_le(buf) or is_elf32_le(buf)


def _cls(buf: bytes) -> int:
    if is_elf64_le(buf):
        return ELFCLASS64
    if is_elf32_le(buf):
        return ELFCLASS32
    raise SystemExit("not ELF32/ELF64 LE")


def _parse_ehdr(buf: bytes) -> dict:
    cls = _cls(buf)
    if cls == ELFCLASS64:
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
        ) = Ehdr64.unpack_from(buf, 0)
        shdr_size = Shdr64.size
    else:
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
        ) = Ehdr32.unpack_from(buf, 0)
        shdr_size = Shdr32.size
    if e_shnum == 0 or e_shstrndx >= e_shnum or e_shentsize < shdr_size:
        raise SystemExit("bad ELF section headers")
    sh_end = e_shoff + e_shnum * e_shentsize
    if e_shoff >= len(buf) or sh_end > len(buf):
        raise SystemExit("ELF shdr out of range")
    return {
        "cls": cls,
        "e_shoff": e_shoff,
        "e_shentsize": e_shentsize,
        "e_shnum": e_shnum,
        "e_shstrndx": e_shstrndx,
    }


def _shdr(buf: bytes, eh: dict, i: int) -> dict:
    off = eh["e_shoff"] + i * eh["e_shentsize"]
    if eh["cls"] == ELFCLASS64:
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
        ) = Shdr64.unpack_from(buf, off)
    else:
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
        ) = Shdr32.unpack_from(buf, off)
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


def _pack_shdr(cls: int, sh: dict) -> bytes:
    if cls == ELFCLASS64:
        return Shdr64.pack(
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
    return Shdr32.pack(
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


def _write_ehdr_sh_fields(out: bytearray, cls: int, shoff: int, shnum: int, shstrndx: int | None = None) -> None:
    if cls == ELFCLASS64:
        struct.pack_into("<Q", out, 40, shoff)
        struct.pack_into("<H", out, 60, shnum)
        if shstrndx is not None:
            struct.pack_into("<H", out, 62, shstrndx)
    else:
        struct.pack_into("<I", out, 32, shoff)
        struct.pack_into("<H", out, 48, shnum)
        if shstrndx is not None:
            struct.pack_into("<H", out, 50, shstrndx)


def find_section(buf: bytes, name: str) -> bytes | None:
    if not is_elf_le(buf):
        return None
    view = buf
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
    cls = eh["cls"]
    sec_name = name if name.startswith(".") else f".{name}"
    name_b = sec_name.encode("utf-8") + b"\x00"
    shstr = _shdr(buf, eh, eh["e_shstrndx"])
    if shstr["sh_type"] != SHT_STRTAB:
        raise SystemExit("ELF missing shstrtab")

    old_len = len(buf)
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
    align = 15 if cls == ELFCLASS64 else 3
    cursor = (len(out) + align) & ~align
    if cursor > len(out):
        out.extend(b"\x00" * (cursor - len(out)))
    payload_off = cursor
    out.extend(payload)
    cursor = len(out)

    cursor = (cursor + align) & ~align
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

    cursor = (len(out) + align) & ~align
    if cursor > len(out):
        out.extend(b"\x00" * (cursor - len(out)))
    shoff = cursor
    for sh in hdrs:
        out.extend(_pack_shdr(cls, sh))

    _write_ehdr_sh_fields(out, cls, shoff, len(hdrs))
    out.extend(WPSE.pack(WPSE_MAGIC, old_len, old_shoff, old_shnum, old_shstrndx, 0))
    return bytes(out)


def strip_section(buf: bytes, name: str) -> bytes:
    """Remove named section. Prefer WPSE cookie restore when section was last append."""
    if find_section(buf, name) is None:
        ck = _read_cookie(buf)
        if ck is not None:
            return bytes(buf[: len(buf) - WPSE.size])
        return bytes(buf)

    ck = _read_cookie(buf)
    if ck is not None:
        eh = _parse_ehdr(buf)
        shstr = _shdr(buf, eh, eh["e_shstrndx"])
        for i in range(eh["e_shnum"]):
            sh = _shdr(buf, eh, i)
            sn = _sh_name(buf, eh, shstr, sh["sh_name"])
            if _name_matches(sn, name) and sh["sh_offset"] >= ck["old_len"]:
                out = bytearray(buf[: ck["old_len"]])
                _write_ehdr_sh_fields(
                    out, eh["cls"], ck["old_shoff"], ck["old_shnum"], ck["old_shstrndx"]
                )
                return bytes(out)

    raise SystemExit(
        f"ELF strip of {name!r} needs WPSE cookie (re-pack/sign with current wasmmod_elf)"
    )
