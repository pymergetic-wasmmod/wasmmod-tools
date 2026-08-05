"""Offline tests for wasmmod_inspect (needs examples/packs/hello.elf with -g)."""
from __future__ import annotations

import os
from pathlib import Path

from pymergetic.wasmmod.tools import inspect as insp
from pymergetic.wasmmod.tools.paths import wasmmod_root

ROOT = wasmmod_root() or Path(os.environ.get("WASMMOD_ROOT", "/nonexistent"))
ELF = ROOT / "examples" / "packs" / "hello.elf"
WASM = ROOT / "examples" / "packs" / "hello.wasm"


def test_hello_elf_symbols_and_dwarf() -> None:
    assert ELF.is_file(), f"missing {ELF}; make -C examples/hello_elf"
    data = ELF.read_bytes()
    assert insp.has_dwarf(data)
    names = {s.name for s in insp.list_symbols(data)}
    assert "hello" in names
    assert "add" in names
    assert "hello.c" not in names  # STT_FILE / SHN_ABS filtered
    hello = next(s for s in insp.list_symbols(data) if s.name == "hello")
    assert hello.kind == "func"
    locs = insp.addr2line(data, hello.offset)
    assert locs
    # Prefer DWARF via pyelftools or host addr2line; else enclosing sym.
    assert locs[0].role in ("sym", "dwarf")
    if locs[0].role == "dwarf":
        assert locs[0].line and locs[0].line > 0
        assert "hello" in locs[0].path
    assert insp.locations_for_symbol(data, "hello")


def test_addr2line_binutils_hello_elf() -> None:
    """When binutils addr2line exists, hello.elf offset 0 → hello.c:4."""
    import shutil

    if not shutil.which("addr2line"):
        return
    assert ELF.is_file()
    data = ELF.read_bytes()
    hello = next(s for s in insp.list_symbols(data) if s.name == "hello")
    locs = insp.addr2line(data, hello.offset)
    assert locs and locs[0].role == "dwarf"
    assert locs[0].line == 4
    assert locs[0].path.endswith("hello.c")


def test_locations_source_scan() -> None:
    data = ELF.read_bytes()
    src = {"src/hello.c": "int hello(void) {\n    return 42;\n}\n"}
    locs = insp.locations_for_symbol(data, "hello", source_files=src)
    assert any(l.path == "src/hello.c" and l.line == 1 for l in locs)


def test_locations_py_twin_requires_def() -> None:
    data = ELF.read_bytes()
    src = {
        "__init__.py": "def hello():\n    return 42\n\ndef other():\n    return hello()\n",
        "call_only.py": "x = hello()\n",
    }
    locs = insp.locations_for_symbol(data, "hello", source_files=src)
    twins = [l for l in locs if l.role == "twin"]
    assert any(l.path == "__init__.py" and l.line == 1 for l in twins)
    assert not any(l.path == "call_only.py" for l in twins)
    assert not any(l.path == "__init__.py" and l.line == 4 for l in twins)


def test_locations_c_def_not_call_or_proto() -> None:
    data = ELF.read_bytes()
    src = {
        "src/hello.c": (
            "int hello(void);\n"
            "int helper(void) { return hello(); }\n"
            "/* int hello(void) { */\n"
            "// int hello(void) {\n"
            "int hello(void)\n"
            "{\n"
            "    return 42;\n"
            "}\n"
        ),
        "src/hello.h": "int hello(void);\n/* Call hello(x) from clients. */\n",
    }
    locs = insp.locations_for_symbol(data, "hello", source_files=src)
    defs = [l for l in locs if l.role == "def"]
    decls = [l for l in locs if l.role == "decl"]
    assert any(l.path == "src/hello.c" and l.line == 5 for l in defs)
    assert not any(l.path == "src/hello.c" and l.line in (1, 2, 3, 4) for l in defs)
    assert any(l.path == "src/hello.h" and l.line == 1 for l in decls)
    assert not any(l.path == "src/hello.h" and l.line == 2 for l in decls)


def test_locations_auto_load_embedded_source() -> None:
    """Wasm pack embeds MPSR; locations_for_symbol finds defs without source_files=."""
    assert WASM.is_file(), f"missing {WASM}"
    data = WASM.read_bytes()
    locs = insp.locations_for_symbol(data, "hello")
    assert any(l.role == "def" and l.path.endswith("hello.c") for l in locs)


def test_locations_auto_load_elf_source() -> None:
    """ELF packs with [source] embed also expose C defs via locations_for_symbol."""
    assert ELF.is_file(), f"missing {ELF}"
    data = ELF.read_bytes()
    locs = insp.locations_for_symbol(data, "hello")
    # dwarf+def on the same line collapse; prefer dwarf with the longer path.
    lined = [l for l in locs if l.line is not None and l.path.endswith("hello.c")]
    assert lined
    keys = [(l.path.rsplit("/", 1)[-1], l.line) for l in lined]
    assert len(keys) == len(set(keys))
    assert any(l.role in ("dwarf", "def") for l in lined)


def test_locations_collapse_dwarf_and_def() -> None:
    locs = insp._collapse_locations(
        [
            insp.Location(path="hello.c", line=4, role="dwarf"),
            insp.Location(path="hello", line=None, role="sym"),
            insp.Location(path="src/hello.c", line=4, role="def"),
            insp.Location(path="src/hello.h", line=1, role="decl"),
        ]
    )
    assert [(l.path, l.line, l.role) for l in locs] == [
        ("src/hello.c", 4, "dwarf"),
        ("src/hello.h", 1, "decl"),
        ("hello", None, "sym"),
    ]


def test_locations_skips_block_comment_star_lines() -> None:
    data = ELF.read_bytes()
    src = {
        "src/hello.c": (
            "/*\n"
            " * int hello(void) { return 0; }\n"
            " */\n"
            "int *out;\n"
            "int hello(void) { return 42; }\n"
        ),
    }
    locs = insp.locations_for_symbol(data, "hello", source_files=src)
    defs = [l for l in locs if l.role == "def"]
    assert any(l.path == "src/hello.c" and l.line == 5 for l in defs)
    assert not any(l.path == "src/hello.c" and l.line == 2 for l in defs)


def test_disasm_text_nonempty() -> None:
    data = ELF.read_bytes()
    # Find .text index
    text_i = None
    for i, _sh, name in insp._iter_shdrs(data):
        if name == ".text":
            text_i = i
            break
    assert text_i is not None
    hello = next(s for s in insp.list_symbols(data) if s.name == "hello")
    assert hello.section_index == text_i
    lines = insp.disasm(data, text_i, 0, 32)
    assert lines


def test_mpy_disasm_header() -> None:
    fake = b"MP\x06\x00" + bytes(range(12))
    lines = insp.mpy_disasm(fake, limit=8)
    assert lines[0].text.startswith("mpy_hdr")
    assert len(lines) >= 2


def test_hello_wasm_exports() -> None:
    assert WASM.is_file(), f"missing {WASM}; make -C examples/hello"
    syms = insp.list_symbols(WASM.read_bytes())
    names = {s.name for s in syms}
    assert "hello" in names
    assert "add" in names
    hello = next(s for s in syms if s.name == "hello")
    add = next(s for s in syms if s.name == "add")
    assert hello.kind == "export" and add.kind == "export"
    assert hello.size > 0 and add.size > 0
    assert hello.offset != add.offset
    assert hello.section_index is not None
    assert hello.section_index == add.section_index
    h = [ln.text for ln in insp.disasm(WASM.read_bytes(), hello.section_index, hello.offset, 8)]
    a = [ln.text for ln in insp.disasm(WASM.read_bytes(), add.section_index, add.offset, 8)]
    assert h != a


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def test_wasm_export_name_leb128() -> None:
    """Name length ≥128 must be LEB128, not a single byte."""
    name = b"a" * 130
    # minimal module: magic/version + export section with one func export
    body = bytearray()
    body.append(1)  # nexp
    body.extend(_uleb(len(name)))
    body.extend(name)
    body.append(0)  # func
    body.append(0)  # index
    sec = bytes([7]) + _uleb(len(body)) + bytes(body)
    mod = b"\x00asm\x01\x00\x00\x00" + sec
    syms = insp.list_symbols(mod)
    assert len(syms) == 1
    assert syms[0].name == "a" * 130
