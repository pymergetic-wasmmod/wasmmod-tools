"""Unit tests for wasmmod publish staging (no CDN / no wamrc)."""

from __future__ import annotations

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



def test_stage_zlib_without_sign(tmp_path: Path) -> None:
    pub = _load("wasmmod_publish")
    zmod = _load("wasmmod_zlib")
    wasm = tmp_path / "hello.wasm"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00" + b"x" * 32)
    files = pub.stage_artifacts(
        [wasm],
        key=None,
        chain=None,
        cert=None,
        do_sign=False,
        do_zlib=True,
        also_naked=True,
        arch=None,
    )
    assert len(files) == 2
    zlib_path = next(p for p in files if p.name.endswith(".zlib"))
    naked = next(p for p in files if not p.name.endswith(".zlib"))
    assert naked == wasm
    blob = zlib_path.read_bytes()
    assert blob[:4] == b"MPZL"
    assert zmod.unwrap_bytes(blob) == wasm.read_bytes()


def test_arch_rename_aot(tmp_path: Path) -> None:
    pub = _load("wasmmod_publish")
    aot = tmp_path / "hello.aot6"
    aot.write_bytes(b"\x00aot" + b"\x00" * 16)
    files = pub.stage_artifacts(
        [aot],
        key=None,
        chain=None,
        cert=None,
        do_sign=False,
        do_zlib=True,
        also_naked=False,
        arch="x86_64",
    )
    assert len(files) == 1
    assert files[0].name == "hello.x86_64.aot6.zlib"
    assert not aot.exists()


def test_arch_rename_elf(tmp_path: Path) -> None:
    pub = _load("wasmmod_publish")
    elf = tmp_path / "hello.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 32)
    files = pub.stage_artifacts(
        [elf],
        key=None,
        chain=None,
        cert=None,
        do_sign=False,
        do_zlib=True,
        also_naked=False,
        arch="x86_64",
    )
    assert len(files) == 1
    assert files[0].name == "hello.x86_64.elf.zlib"
    assert not elf.exists()
    # Already arch-tagged stems are left alone.
    tagged = tmp_path / "hello.aarch64.elf"
    tagged.write_bytes(b"\x7fELF" + b"\x00" * 16)
    files2 = pub.stage_artifacts(
        [tagged],
        key=None,
        chain=None,
        cert=None,
        do_sign=False,
        do_zlib=False,
        also_naked=False,
        arch="x86_64",
    )
    assert files2 == [tagged]


def test_from_artifacts_elf_arch_preserves_source(tmp_path: Path) -> None:
    pub = _load("wasmmod_publish")
    src = tmp_path / "src"
    out = tmp_path / "out"
    src.mkdir()
    elf = src / "hello.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 32)
    rc = pub.main(
        [
            "--from-artifacts",
            str(elf),
            "--package",
            "hello",
            "--version",
            "0.1.0",
            "--arch",
            "x86_64",
            "--no-sign",
            "--dry-run",
            "-o",
            str(out),
        ]
    )
    assert rc == 0
    assert elf.is_file(), "source ELF must not be renamed/deleted"
    assert (out / "hello.x86_64.elf.zlib").is_file()


def test_elf_flag_alongside_wasm_artifact(tmp_path: Path) -> None:
    pub = _load("wasmmod_publish")
    src = tmp_path / "src"
    out = tmp_path / "out"
    src.mkdir()
    wasm = src / "hello.wasm"
    elf = src / "hello.elf"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
    elf.write_bytes(b"\x7fELF" + b"\x00" * 32)
    rc = pub.main(
        [
            "--from-artifacts",
            str(wasm),
            "--elf",
            str(elf),
            "--package",
            "hello",
            "--version",
            "0.1.0",
            "--arch",
            "x86_64",
            "--no-sign",
            "--dry-run",
            "-o",
            str(out),
        ]
    )
    assert rc == 0
    assert elf.is_file()
    assert (out / "hello.x86_64.elf.zlib").is_file()
    # Wasm is zlib-wrapped in place when it is the --from-artifacts path.
    assert Path(str(wasm) + ".zlib").is_file()


def test_dry_run_from_artifacts(tmp_path: Path) -> None:
    pub = _load("wasmmod_publish")
    wasm = tmp_path / "demo.wasm"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
    rc = pub.main(
        [
            "--from-artifacts",
            str(wasm),
            "--package",
            "demo",
            "--version",
            "0.1.0",
            "--no-sign",
            "--dry-run",
        ]
    )
    assert rc == 0
    assert Path(str(wasm) + ".zlib").is_file()


def test_missing_key_fails_before_pack(tmp_path: Path) -> None:
    pub = _load("wasmmod_publish")
    pack = tmp_path / "pack.toml"
    pack.write_text('name = "x"\nversion = "0.0.1"\n', encoding="utf-8")
    try:
        pub.main([str(pack), "--key", str(tmp_path / "nope.pem"), "--dry-run"])
        raise AssertionError("expected SystemExit")
    except SystemExit as e:
        msg = str(e)
        assert "wasmmod publish:" in msg
        assert "missing signing key" in msg
        assert "gen-pki" in msg


def test_discover_elfs_prefers_arch(tmp_path: Path) -> None:
    pub = _load("wasmmod_publish")
    (tmp_path / "hello.elf").write_bytes(b"\x7fELF" + b"\x00" * 8)
    tagged = tmp_path / "hello.x86_64.elf"
    tagged.write_bytes(b"\x7fELF" + b"\x00" * 8)
    found = pub._discover_elfs(tmp_path, "hello", arch="x86_64")
    names = [p.name for p in found]
    assert "hello.x86_64.elf" in names
    assert "hello.elf" in names


def test_auto_elf_from_out_dir(tmp_path: Path) -> None:
    pub = _load("wasmmod_publish")
    out = tmp_path / "out"
    out.mkdir()
    wasm = tmp_path / "hello.wasm"
    elf = out / "hello.elf"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
    elf.write_bytes(b"\x7fELF" + b"\x00" * 32)
    rc = pub.main(
        [
            "--from-artifacts",
            str(wasm),
            "--package",
            "hello",
            "--version",
            "0.1.0",
            "--no-sign",
            "--dry-run",
            "-o",
            str(out),
        ]
    )
    assert rc == 0
    assert (out / "hello.elf.zlib").is_file()


def test_no_elf_skips_auto(tmp_path: Path) -> None:
    pub = _load("wasmmod_publish")
    out = tmp_path / "out"
    out.mkdir()
    wasm = tmp_path / "hello.wasm"
    elf = out / "hello.elf"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
    elf.write_bytes(b"\x7fELF" + b"\x00" * 32)
    rc = pub.main(
        [
            "--from-artifacts",
            str(wasm),
            "--package",
            "hello",
            "--version",
            "0.1.0",
            "--no-sign",
            "--no-elf",
            "--dry-run",
            "-o",
            str(out),
        ]
    )
    assert rc == 0
    assert not (out / "hello.elf.zlib").is_file()


def test_elf_and_no_elf_conflict(tmp_path: Path) -> None:
    pub = _load("wasmmod_publish")
    wasm = tmp_path / "hello.wasm"
    elf = tmp_path / "hello.elf"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
    elf.write_bytes(b"\x7fELF" + b"\x00" * 8)
    try:
        pub.main(
            [
                "--from-artifacts",
                str(wasm),
                "--elf",
                str(elf),
                "--no-elf",
                "--package",
                "hello",
                "--version",
                "0.1.0",
                "--no-sign",
                "--dry-run",
            ]
        )
        raise AssertionError("expected SystemExit")
    except SystemExit as e:
        assert e.code not in (0, None)
