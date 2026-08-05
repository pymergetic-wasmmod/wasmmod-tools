"""Offline unit tests for wasmmod_elf WPSE append/find/strip (no CDN)."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent


def _load(stem: str):
    """Load a tools submodule by legacy wasmmod_* stem or short name."""
    import importlib
    name = stem
    if name.startswith("wasmmod_"):
        name = name[len("wasmmod_") :]
    elif name == "wasmmod":
        name = "__main__"
    return importlib.import_module(f"pymergetic.wasmmod.tools.{name}")



def _compile_et_rel(tmp: Path) -> bytes:
    src = tmp / "t.c"
    obj = tmp / "t.o"
    src.write_text("int answer(void) { return 42; }\n", encoding="utf-8")
    subprocess.check_call(
        [
            "gcc",
            "-ffreestanding",
            "-fPIC",
            "-fno-plt",
            "-fno-stack-protector",
            "-O2",
            "-c",
            "-o",
            str(obj),
            str(src),
        ]
    )
    return obj.read_bytes()


def test_elf_append_find_strip_roundtrip() -> None:
    elf = _load("wasmmod_elf")
    with tempfile.TemporaryDirectory() as td:
        raw = _compile_et_rel(Path(td))
    assert elf.is_elf64_le(raw)
    payload = b"MPWPtestdata"
    with_sec = elf.append_section(raw, "wasmmod.pack", payload)
    assert with_sec != raw
    assert elf.WPSE_MAGIC in with_sec[-64:]
    found = elf.find_section(with_sec, "wasmmod.pack")
    assert found == payload
    # Dotted and undotted names both match
    assert elf.find_section(with_sec, ".wasmmod.pack") == payload
    stripped = elf.strip_section(with_sec, "wasmmod.pack")
    assert stripped == raw
    assert elf.find_section(stripped, "wasmmod.pack") is None


def test_elf_multi_section_append() -> None:
    elf = _load("wasmmod_elf")
    with tempfile.TemporaryDirectory() as td:
        raw = _compile_et_rel(Path(td))
    a = elf.append_section(raw, "wasmmod.pack", b"PACK")
    b = elf.append_section(a, "wasmmod.imports", b"IMPS")
    assert elf.find_section(b, "wasmmod.pack") == b"PACK"
    assert elf.find_section(b, "wasmmod.imports") == b"IMPS"
    # Strip last append restores prior image (cookie drops prior WPSE on re-append).
    back = elf.strip_section(b, "wasmmod.imports")
    assert elf.find_section(back, "wasmmod.imports") is None
    assert elf.find_section(back, "wasmmod.pack") == b"PACK"


def test_inspect_offline_mpzl_elf_roundtrip(tmp_path: Path) -> None:
    import sys

    if str(TOOLS) not in sys.path:
        sys.path.insert(0, str(TOOLS))
    elf = _load("wasmmod_elf")
    zmod = _load("wasmmod_zlib")
    insp = _load("wasmmod_inspect")
    with tempfile.TemporaryDirectory() as td:
        raw = _compile_et_rel(Path(td))
    packed = elf.append_section(raw, "wasmmod.pack", b"\x00" * 8)
    zlibbed = zmod.wrap_bytes(packed)
    path = tmp_path / "hello.elf.zlib"
    path.write_bytes(zlibbed)
    summary = insp._offline_inspect(path)
    assert summary.get("offline") is True
    # Unwrap must succeed (no bogus MPZL layout error).
    assert "source_error" not in summary or "MPZL" not in str(summary.get("source_error"))
    assert "wasmmod_elf" not in str(summary.get("source_error", ""))
    assert "wasmmod_elf" not in str(summary.get("deps_error", ""))


def test_elf_sign_verify_wpse_roundtrip(tmp_path: Path) -> None:
    """Sign/verify an ELF pack via WPSE strip (openssl + wasmmod_sign)."""
    import shutil
    import sys

    if shutil.which("openssl") is None:
        import pytest

        pytest.skip("openssl not available")

    if str(TOOLS) not in sys.path:
        sys.path.insert(0, str(TOOLS))
    elf = _load("wasmmod_elf")
    sign = _load("wasmmod_sign")

    keys = tmp_path / "keys"
    sign.cmd_gen_pki(keys, False, 1)
    leaf_key = keys / "sign" / "leaf.key.pem"
    chain = keys / "sign" / "chain.der"
    trust = keys / "trust" / "root.crt.der"
    assert leaf_key.is_file() and chain.is_file() and trust.is_file()

    raw = _compile_et_rel(tmp_path)
    packed = elf.append_section(raw, "wasmmod.pack", b"PACKDATA")
    target = tmp_path / "hello.elf"
    target.write_bytes(packed)

    sign.cmd_sign(leaf_key, target, cert=None, chain=chain)
    signed = target.read_bytes()
    assert elf.find_section(signed, "wasmmod.sig") is not None
    # Digest excludes sig; WPSE restore must match pre-sign image.
    stripped = sign.without_sig_section(signed)
    assert elf.find_section(stripped, "wasmmod.sig") is None
    assert elf.find_section(stripped, "wasmmod.pack") == b"PACKDATA"

    sign.cmd_verify(target, trust=trust, pubkey=None)
