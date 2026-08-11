
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
Build a freestanding Wasm guest and optionally append a MicroPython pack
section (`wasmmod.pack`). See docs/PACK.md (this repo).

Examples:
  tools/wasmmod.py pack hello.c -o hello.wasm --export hello --export add
  tools/wasmmod.py pack hello.c -o hello.wasm --name hello --mount src \\
      --export hello --export add
  tools/wasmmod.py pack examples/hello -o hello.wasm
  tools/wasmmod.py pack examples/hello/pack.toml -o hello.wasm
  # or: tools/wasmmod_pack.py …
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

from . import pmm
from .paths import wasmmod_root

SECTION_NAME = "wasmmod.pack"
IMPORTS_SECTION = "wasmmod.imports"
DEPS_SECTION = "wasmmod.deps"
MAGIC = b"MPWP"
IMPORTS_MAGIC = b"MPWI"
DEPS_MAGIC = b"MPWD"
PACK_VERSION_V1 = 1
PACK_VERSION_V2 = 2
PACK_VERSION_V3 = 3
IMPORTS_VERSION = 1
DEPS_VERSION = 1

KIND_PY = 1
KIND_MPY = 2
KIND_RAW = 3
KIND_PYC = 4

FILE_FLAG_ZLIB = 1 << 0
COMPRESS_THRESHOLD = 64
COMPRESS_KINDS = {KIND_PY, KIND_MPY, KIND_PYC}

SIG_AUTO = 255
C_EXTS = {".c"}
CXX_EXTS = {".cc", ".cpp", ".cxx", ".C"}
RS_EXTS = {".rs"}
NATIVE_EXTS = C_EXTS | CXX_EXTS | RS_EXTS

# Default pack layout: one src/ tree (Python module paths + co-located natives).
DEFAULT_SRC_DIR = "src"

# Skip when embedding mount trees (natives are linked, not packed as files).
EMBED_SKIP_NAMES = frozenset(
    {
        "pack.toml",
        "Makefile",
        "CMakeLists.txt",
        ".gitignore",
    }
)
EMBED_SKIP_SUFFIXES = frozenset(
    {
        ".wasm",
        ".aot",
        ".mpack",
        ".sig",
        ".o",
        ".obj",
        ".md",
        ".toml",
        ".pyi",
    }
)

# Host-tagged bytecode targets (see docs/PACK.md).
DEFAULT_PYTHON_TARGETS = (
    "upy:mpy6:sib31",
    "upy:mpy6:sib63",
    "cpy:cp312",
    "cpy:cp313",
    "cpy:cp314",
)


def is_native_source(path: Path) -> bool:
    return path.suffix in NATIVE_EXTS


def should_embed_file(path: Path) -> bool:
    """True if path belongs in wasmmod.pack (not native/build noise)."""
    name = path.name
    if name.startswith("."):
        return False
    if name in EMBED_SKIP_NAMES:
        return False
    if path.suffix in EMBED_SKIP_SUFFIXES:
        return False
    if is_native_source(path):
        return False
    return True


def collect_native_sources(dir_path: Path) -> list[str]:
    """Recurse for C/C++/Rust under dir_path (co-located with Python ok)."""
    out: list[str] = []
    if not dir_path.is_dir():
        return out
    for p in sorted(dir_path.rglob("*")):
        if p.is_file() and is_native_source(p):
            out.append(str(p.resolve()))
    return out

def sig_tag(sig: str | None) -> int:
    """Map pack.toml sig strings to binder tags.

    Loader introspects real Wasm types (i32/i64/f32/f64). Keep optional
    legacy N-i32 tags for old readers; anything richer → SIG_AUTO.
    """
    if not sig:
        return SIG_AUTO
    parts = [p for p in sig.split("_") if p]
    if not parts:
        return SIG_AUTO
    if any(p not in ("i32",) for p in parts):
        return SIG_AUTO
    # all i32: optional compact tag (result is last)
    nparams = len(parts) - 1
    if 0 <= nparams <= 8 and parts[-1] == "i32":
        return nparams
    return SIG_AUTO


def load_toml(path: Path) -> dict:
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError as e:
            raise SystemExit(
                "wasm_pack: need Python 3.11+ (tomllib) or the tomli package to read pack.toml"
            ) from e
    with path.open("rb") as f:
        return tomllib.load(f)


def find_wasm_ld() -> str | None:
    env = os.environ.get("WASM_LD")
    if env and Path(env).is_file():
        return env
    for candidate in (
        shutil.which("wasm-ld"),
        shutil.which("wasm-ld-18"),
        shutil.which("wasm-ld-17"),
    ):
        if candidate:
            return candidate
    # Do not Path.resolve() wasm-ld: wasi-sdk's wasm-ld → lld symlink breaks
    # clang's -fuse-ld driver selection.
    wm = wasmmod_root()
    if wm is not None:
        for metal in (wm.parents[2] / "metal", wm.parent.parent.parent / "metal"):
            wasi_ld = metal / ".tools" / "wasi-sdk" / "bin" / "wasm-ld"
            if wasi_ld.exists():
                return str(wasi_ld)
    rustup = Path.home() / ".rustup" / "toolchains"
    if rustup.is_dir():
        for ld in rustup.glob("*/lib/rustlib/*/bin/gcc-ld/wasm-ld"):
            return str(ld)
    return None


def find_clang() -> str:
    env = os.environ.get("WASM_CC") or os.environ.get("CC_WASM")
    if env:
        return env
    wm = wasmmod_root()
    if wm is not None:
        for metal in (wm.parents[2] / "metal", wm.parent.parent.parent / "metal"):
            wasi_clang = metal / ".tools" / "wasi-sdk" / "bin" / "clang"
            if wasi_clang.exists():
                return str(wasi_clang)
    clang = shutil.which("clang")
    if not clang:
        raise SystemExit("wasm_pack: clang not found (set WASM_CC)")
    return clang


def find_clangxx(clang: str) -> str:
    env = os.environ.get("WASM_CXX") or os.environ.get("CXX_WASM")
    if env:
        return env
    cand = Path(clang).with_name(Path(clang).name.replace("clang", "clang++"))
    if cand.exists():
        return str(cand)
    cxx = shutil.which("clang++")
    if not cxx:
        raise SystemExit("wasm_pack: clang++ not found (set WASM_CXX) for C++ sources")
    return cxx


def find_rustc() -> str:
    env = os.environ.get("WASM_RUSTC") or os.environ.get("RUSTC")
    if env:
        return env
    rustc = shutil.which("rustc")
    if not rustc:
        raise SystemExit("wasm_pack: rustc not found (set WASM_RUSTC) for Rust sources")
    return rustc


def uleb128(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def kind_for_path(path: str) -> int:
    if path.endswith(".py"):
        return KIND_PY
    if path.endswith(".mpy"):
        return KIND_MPY
    if path.endswith(".pyc"):
        return KIND_PYC
    return KIND_RAW


class PythonTarget:
    """Parsed `upy:mpy6:sib31` / `cpy:cp312` (optional native: `upy:mpy6:sub3:archx64:sib31`)."""

    __slots__ = ("arch", "cp", "host", "mpy_ver", "raw", "sib", "sub")

    def __init__(
        self,
        host: str,
        *,
        mpy_ver: int | None = None,
        sib: int | None = None,
        sub: int | None = None,
        arch: str | None = None,
        cp: int | None = None,
        raw: str = "",
    ) -> None:
        self.host = host
        self.mpy_ver = mpy_ver
        self.sib = sib
        self.sub = sub
        self.arch = arch
        self.cp = cp
        self.raw = raw

    def tagged_path(self, py_rel: str) -> str:
        stem = py_rel.removesuffix(".py")
        if self.host == "upy":
            parts = ["upy", f"mpy{self.mpy_ver}"]
            if self.sub is not None:
                parts.append(f"sub{self.sub}")
            if self.arch:
                parts.append(f"arch{self.arch}")
            parts.append(f"sib{self.sib}")
            return stem + "." + ".".join(parts) + ".mpy"
        return f"{stem}.cpy.cp{self.cp}.pyc"


def parse_python_target(spec: str) -> PythonTarget:
    s = spec.strip()
    if not s:
        raise SystemExit("wasm_pack: empty python target")
    parts = s.split(":")
    host = parts[0]
    if host == "upy":
        mpy_ver = sib = sub = None
        arch = None
        for p in parts[1:]:
            if p.startswith("mpy") and p[3:].isdigit():
                mpy_ver = int(p[3:])
            elif p.startswith("sib") and p[3:].isdigit():
                sib = int(p[3:])
            elif p.startswith("sub") and p[3:].isdigit():
                sub = int(p[3:])
            elif p.startswith("arch") and len(p) > 4:
                arch = p[4:]
            else:
                raise SystemExit(f"wasm_pack: bad upy target field {p!r} in {spec!r}")
        if mpy_ver is None or sib is None:
            raise SystemExit(f"wasm_pack: upy target needs mpyN and sibN: {spec!r}")
        return PythonTarget("upy", mpy_ver=mpy_ver, sib=sib, sub=sub, arch=arch, raw=s)
    if host == "cpy":
        if len(parts) != 2 or not parts[1].startswith("cp") or not parts[1][2:].isdigit():
            raise SystemExit(f"wasm_pack: cpy target like cpy:cp312 expected, got {spec!r}")
        return PythonTarget("cpy", cp=int(parts[1][2:]), raw=s)
    raise SystemExit(f"wasm_pack: unknown python target host in {spec!r}")


def find_mpy_cross() -> str | None:
    """Locate ``mpy-cross`` for upy pack targets.

    Order: ``MPY_CROSS`` env, ``PATH``, then walk from ``wasmmod_root()`` / cwd
    (MicroPython / metalpython checkouts). Standalone pip users only need the
    binary on ``PATH``.
    """
    env = os.environ.get("MPY_CROSS")
    if env and Path(env).is_file():
        return env
    which = shutil.which("mpy-cross")
    if which:
        return which

    roots: list[Path] = []
    wr = wasmmod_root()
    if wr is not None:
        roots.append(wr)
        # submodule: …/extmod/wasmmod → µPy / metalpython root
        if len(wr.parents) >= 2 and wr.name == "wasmmod" and wr.parent.name == "extmod":
            roots.append(wr.parents[1])
    roots.append(Path.cwd().resolve())
    roots.extend(Path.cwd().resolve().parents)

    seen: set[Path] = set()
    for parent in roots:
        parent = parent.resolve()
        if parent in seen:
            continue
        seen.add(parent)
        for cand in (
            parent / "mpy-cross" / "build" / "mpy-cross",
            parent / "mpy-cross" / "mpy-cross",
        ):
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)
    return None


def find_cpython(cp: int) -> str | None:
    """Map cp312 → python3.12 binary if present."""
    major, minor = divmod(cp, 100)  # 312 → (3, 12)
    ver = f"{major}.{minor}"
    env = os.environ.get(f"PYTHON{major}{minor}") or os.environ.get(f"PYTHON_{ver}")
    candidates = [env, f"python{ver}", f"python{major}.{minor}", "python3"]
    for c in candidates:
        if not c:
            continue
        path = c if (os.sep in c and Path(c).is_file()) else shutil.which(c)
        if not path:
            continue
        try:
            out = subprocess.check_output(
                [path, "-c", "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"],
                text=True,
            ).strip()
        except (OSError, subprocess.CalledProcessError):
            continue
        if out == ver:
            return path
    return None


def freeze_py_to_mpy(
    rel: str,
    data: bytes,
    mpy_cross: str,
    opt: str,
    *,
    sib: int,
    arch: str | None = None,
) -> bytes:
    """Compile .py source bytes to .mpy via mpy-cross."""
    import tempfile

    with tempfile.TemporaryDirectory(prefix="wasm_pack_mpy_") as td:
        td_path = Path(td)
        base = Path(rel).name
        if not base.endswith(".py"):
            base = base + ".py"
        py_path = td_path / base
        mpy_path = td_path / (Path(base).stem + ".mpy")
        py_path.write_bytes(data)
        cmd = [mpy_cross, f"-O{opt}", f"-msmall-int-bits={sib}"]
        if arch:
            cmd += [f"-march={arch}", "-X", "emit=native"]
        cmd += ["-o", str(mpy_path), "-s", rel, str(py_path)]
        print("+", " ".join(cmd), file=sys.stderr)
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError as e:
            raise SystemExit(f"wasm_pack: mpy-cross failed for {rel} (sib={sib})") from e
        return mpy_path.read_bytes()

def freeze_py_to_pyc(rel: str, data: bytes, python: str) -> bytes:
    """Compile .py to .pyc with a specific CPython."""
    import tempfile

    with tempfile.TemporaryDirectory(prefix="wasm_pack_pyc_") as td:
        td_path = Path(td)
        base = Path(rel).name
        if not base.endswith(".py"):
            base = base + ".py"
        py_path = td_path / base
        pyc_path = td_path / (Path(base).stem + ".pyc")
        py_path.write_bytes(data)
        script = (
            "import py_compile, sys; "
            f"py_compile.compile({str(py_path)!r}, cfile={str(pyc_path)!r}, "
            "doraise=True, optimize=0)"
        )
        cmd = [python, "-c", script]
        print("+", python, "-c", f"py_compile {rel}", file=sys.stderr)
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError as e:
            raise SystemExit(f"wasm_pack: py_compile failed for {rel} with {python}") from e
        return pyc_path.read_bytes()


def collect_mounts(
    mount_dirs: list[Path],
    *,
    targets: list[PythonTarget] | None = None,
    keep_source: bool = True,
    mpy_cross: str | None = None,
    opt: str = "2",
) -> list[tuple[str, int, bytes]]:
    """Embed mount tree; optionally emit host-tagged bytecode beside .py."""
    files: list[tuple[str, int, bytes]] = []
    targets = targets or []
    need_mpy = any(t.host == "upy" for t in targets)
    if need_mpy and not mpy_cross:
        raise SystemExit(
            "wasm_pack: upy targets require mpy-cross "
            "(build mpy-cross, or set MPY_CROSS=/path/to/mpy-cross)"
        )
    cpy_bins: dict[int, str] = {}
    for t in targets:
        if t.host == "cpy":
            assert t.cp is not None
            if t.cp not in cpy_bins:
                bin_ = find_cpython(t.cp)
                if bin_ is None:
                    print(
                        f"wasm_pack: skip target {t.raw}: no CPython {t.cp // 100}.{t.cp % 100}",
                        file=sys.stderr,
                    )
                else:
                    cpy_bins[t.cp] = bin_

    for root in mount_dirs:
        root = root.resolve()
        if not root.is_dir():
            raise SystemExit(f"wasm_pack: --mount not a directory: {root}")
        for path in sorted(root.rglob("*")):
            if not path.is_file() or not should_embed_file(path):
                continue
            rel = path.relative_to(root).as_posix()
            if rel.startswith("../") or "/../" in f"/{rel}/":
                raise SystemExit(f"wasm_pack: refusing path {rel}")
            data = path.read_bytes()
            kind = kind_for_path(rel)
            if kind == KIND_PY:
                if keep_source or not targets:
                    files.append((rel, KIND_PY, data))
                for t in targets:
                    if t.host == "upy":
                        assert t.sib is not None
                        blob = freeze_py_to_mpy(
                            rel, data, mpy_cross, opt, sib=t.sib, arch=t.arch  # type: ignore[arg-type]
                        )
                        files.append((t.tagged_path(rel), KIND_MPY, blob))
                    elif t.host == "cpy":
                        assert t.cp is not None
                        py = cpy_bins.get(t.cp)
                        if py is None:
                            continue
                        blob = freeze_py_to_pyc(rel, data, py)
                        files.append((t.tagged_path(rel), KIND_PYC, blob))
            else:
                files.append((rel, kind, data))
    return files


def build_pack_payload(
    name: str,
    files: list[tuple[str, int, bytes]],
    exports: list[tuple[str, str, str, int]] | None = None,
    *,
    compress: bool = True,
) -> bytes:
    """exports entries: (module, func, export_name, sig_tag).

    Always writes pack version 3 (per-file flags + raw_len). Compresses
    .py/.mpy/.pyc when compress=True and the zlib blob is smaller.
    """
    name_b = name.encode("utf-8")
    if len(name_b) > 0xFFFF:
        raise SystemExit("wasm_pack: package name too long")
    exports = exports or []
    out = bytearray()
    out += MAGIC
    out += struct.pack("<HH", PACK_VERSION_V3, 0)
    out += struct.pack("<H", len(name_b))
    out += name_b
    out += struct.pack("<I", len(files))
    n_zlib = 0
    raw_total = 0
    packed_total = 0
    for rel, kind, data in files:
        rel_b = rel.encode("utf-8")
        if len(rel_b) > 0xFFFF:
            raise SystemExit(f"wasm_pack: path too long: {rel}")
        raw_len = len(data)
        if raw_len > 0xFFFFFFFF:
            raise SystemExit(f"wasm_pack: file too large: {rel}")
        flags = 0
        payload = data
        if compress and kind in COMPRESS_KINDS and raw_len >= COMPRESS_THRESHOLD:
            z = zlib.compress(data, 9)
            if len(z) < raw_len:
                payload = z
                flags |= FILE_FLAG_ZLIB
                n_zlib += 1
        raw_total += raw_len
        packed_total += len(payload)
        out += struct.pack("<H", len(rel_b))
        out += rel_b
        out += struct.pack("<B", kind)
        out += struct.pack("<B", flags)
        out += struct.pack("<I", raw_len)
        out += struct.pack("<I", len(payload))
        out += payload
    out += struct.pack("<I", len(exports))
    for module, func, export_name, sig in exports:
        for label, s in (("module", module), ("func", func), ("export", export_name)):
            b = s.encode("utf-8")
            if len(b) > 0xFFFF:
                raise SystemExit(f"wasm_pack: {label} too long: {s}")
            out += struct.pack("<H", len(b))
            out += b
        out += struct.pack("<B", sig & 0xFF)
    # Stash stats for the caller via attribute (optional).
    build_pack_payload.last_stats = {  # type: ignore[attr-defined]
        "n_zlib": n_zlib,
        "raw_total": raw_total,
        "packed_total": packed_total,
    }
    return bytes(out)


def aot_format_version(wamr_root: Path | None = None) -> int:
    """Read WAMR AOT_CURRENT_VERSION (file-format N for .aotN names)."""
    if wamr_root is None:
        wm = wasmmod_root()
        wamr_root = (wm / "third_party" / "wamr") if wm is not None else Path("third_party/wamr")
    cfg = wamr_root / "core" / "config.h"
    if not cfg.is_file():
        return 0
    for line in cfg.read_text().splitlines():
        line = line.strip()
        if line.startswith("#define AOT_CURRENT_VERSION"):
            parts = line.split()
            if len(parts) >= 3 and parts[2].isdigit():
                return int(parts[2])
    return 0


def aot_output_path(wasm_out: Path, explicit: str | Path | None = None) -> Path:
    """Default sibling name: hello.wasm → hello.aot6 (format-tagged)."""
    if explicit is not None and explicit != "":
        return Path(explicit)
    ver = aot_format_version()
    if ver > 0:
        return wasm_out.with_name(f"{wasm_out.stem}.aot{ver}")
    return wasm_out.with_suffix(".aot")


def append_custom_section(wasm: bytes, section_name: str, payload: bytes) -> bytes:
    if len(wasm) >= 4 and wasm[:4] == b"\x7fELF":
        from .elf import append_section

        return append_section(wasm, section_name, payload)
    name_b = section_name.encode("utf-8")
    body = uleb128(len(name_b)) + name_b + payload
    return wasm + bytes([0]) + uleb128(len(body)) + body


def build_imports_payload(imports: list[tuple[str, str]]) -> bytes:
    out = bytearray()
    out += IMPORTS_MAGIC
    out += struct.pack("<H", IMPORTS_VERSION)
    out += struct.pack("<I", len(imports))
    for module, func in imports:
        for label, s in (("module", module), ("func", func)):
            b = s.encode("utf-8")
            if len(b) > 0xFFFF:
                raise SystemExit(f"wasm_pack: import {label} too long: {s}")
            out += struct.pack("<H", len(b))
            out += b
    return bytes(out)


def build_deps_payload(deps: list[tuple[str, str]]) -> bytes:
    """CDN / install deps (exact name → version). Distinct from ``[[imports]]``."""
    out = bytearray()
    out += DEPS_MAGIC
    out += struct.pack("<H", DEPS_VERSION)
    out += struct.pack("<I", len(deps))
    for name, version in deps:
        for label, s in (("name", name), ("version", version)):
            b = s.encode("utf-8")
            if len(b) > 0xFFFF:
                raise SystemExit(f"wasm_pack: deps {label} too long: {s}")
            out += struct.pack("<H", len(b))
            out += b
    return bytes(out)


def parse_deps_payload(payload: bytes) -> list[tuple[str, str]]:
    """Parse MPWD ``wasmmod.deps`` payload → ``[(name, version), …]``."""
    if len(payload) < 10 or payload[:4] != DEPS_MAGIC:
        raise ValueError("not a wasmmod.deps payload")
    version = struct.unpack_from("<H", payload, 4)[0]
    if version != DEPS_VERSION:
        raise ValueError(f"unsupported wasmmod.deps version: {version}")
    n = struct.unpack_from("<I", payload, 6)[0]
    if n > 1024:
        raise ValueError("wasmmod.deps: too many entries")
    i = 10
    out: list[tuple[str, str]] = []
    for _ in range(n):
        nl = struct.unpack_from("<H", payload, i)[0]
        i += 2
        name = payload[i : i + nl].decode("utf-8")
        i += nl
        vl = struct.unpack_from("<H", payload, i)[0]
        i += 2
        ver = payload[i : i + vl].decode("utf-8")
        i += vl
        out.append((name, ver))
    return out


def parse_manifest_deps(data: dict) -> list[tuple[str, str]]:
    """Read ``[deps]`` table from pack.toml → ``[(name, version), …]``."""
    raw = data.get("deps")
    if raw is None:
        return []
    if isinstance(raw, dict):
        out: list[tuple[str, str]] = []
        for name, ver in raw.items():
            if not isinstance(name, str) or not name:
                raise SystemExit("wasm_pack: deps keys must be non-empty strings")
            if isinstance(ver, dict):
                raise SystemExit(
                    f"wasm_pack: deps[{name!r}] looks nested — quote dotted package "
                    f'names in pack.toml, e.g. "{name}.…" = "0.1.0"'
                )
            if not isinstance(ver, str) or not ver:
                raise SystemExit(f"wasm_pack: deps[{name!r}] must be a non-empty version string")
            out.append((name, ver))
        return out
    if isinstance(raw, list):
        out = []
        for item in raw:
            if not isinstance(item, dict):
                raise SystemExit("wasm_pack: deps list entries must be tables")
            name = item.get("name")
            ver = item.get("version")
            if not isinstance(name, str) or not name or not isinstance(ver, str) or not ver:
                raise SystemExit("wasm_pack: deps entries need name= and version=")
            out.append((name, ver))
        return out
    raise SystemExit("wasm_pack: deps must be a table or list of tables")


def _guest_header(root: Path) -> Path:
    """Unified-tree guest umbrella: ``src/pymergetic/wasmmod/guest.h``."""
    return root / "src" / "pymergetic" / "wasmmod" / "guest.h"


def guest_include_dir() -> Path | None:
    """Crate root for the ``-I`` rule (``#include "src/pymergetic/…"``).

    No parallel ``include/`` — guest macros live under ``src/`` like
    every other module face (see docs/SOURCETREE.md).
    """
    candidates: list[Path] = []
    root = wasmmod_root()
    if root is not None:
        candidates.append(root)
    here = Path.cwd().resolve()
    for cand in (here, *here.parents):
        candidates.append(cand)
    pkg = Path(__file__).resolve()
    for parent in pkg.parents:
        candidates.append(parent / "wasmmod")
        candidates.append(parent / "micropython-wasmmod" / "extmod" / "wasmmod")
        candidates.append(parent / "metalpython" / "extmod" / "wasmmod")
    seen: set[Path] = set()
    for cand in candidates:
        try:
            cand = cand.resolve()
        except OSError:
            continue
        if cand in seen:
            continue
        seen.add(cand)
        if _guest_header(cand).is_file():
            return cand
    return None


def guest_include_flags() -> list[str]:
    """``-I`` crate root so guests can ``#include "src/pymergetic/wasmmod/guest.h"``."""
    inc = guest_include_dir()
    return [f"-I{inc}"] if inc is not None else []


def compile_to_obj(src: Path, obj: Path, opt: str) -> None:
    ext = src.suffix
    guest_inc = guest_include_flags()
    if ext in C_EXTS:
        clang = find_clang()
        cmd = [
            clang,
            f"-O{opt}",
            "--target=wasm32",
            "-nostdlib",
            "-ffreestanding",
            *guest_inc,
            "-c",
            "-o",
            str(obj),
            str(src),
        ]
    elif ext in CXX_EXTS:
        cxx = find_clangxx(find_clang())
        cmd = [
            cxx,
            f"-O{opt}",
            "--target=wasm32",
            "-nostdlib",
            "-ffreestanding",
            "-fno-exceptions",
            "-fno-rtti",
            *guest_inc,
            "-c",
            "-o",
            str(obj),
            str(src),
        ]
    elif ext in RS_EXTS:
        rustc = find_rustc()
        cmd = [
            rustc,
            f"-Copt-level={opt}",
            "--target=wasm32-unknown-unknown",
            "--crate-type=lib",
            "--emit=obj",
            "-Cpanic=abort",
            "-o",
            str(obj),
            str(src),
        ]
    else:
        raise SystemExit(f"wasm_pack: unsupported source type: {src}")
    print("+", " ".join(cmd), file=sys.stderr)
    subprocess.check_call(cmd)


def compile_wasm(sources: list[str], out: Path, exports: list[str], opt: str) -> None:
    """Compile mixed C/C++/Rust sources and link a freestanding .wasm."""
    clang = find_clang()
    wasm_ld = find_wasm_ld()
    src_paths = [Path(s) for s in sources]
    guest_inc = guest_include_flags()
    # Fast path: single C file can still go through the clang driver.
    if len(src_paths) == 1 and src_paths[0].suffix in C_EXTS:
        cmd = [
            clang,
            f"-O{opt}",
            "--target=wasm32",
            "-nostdlib",
            "-ffreestanding",
            *guest_inc,
            "-Wl,--no-entry",
            "-Wl,--allow-undefined",
        ]
        if exports:
            for sym in exports:
                cmd.append(f"-Wl,--export={sym}")
        else:
            cmd.append("-Wl,--export-all")
        if wasm_ld:
            cmd.append(f"-fuse-ld={wasm_ld}")
        cmd.extend(["-o", str(out), str(src_paths[0])])
        print("+", " ".join(cmd), file=sys.stderr)
        subprocess.check_call(cmd)
        return

    objs: list[Path] = []
    try:
        for src in src_paths:
            try:
                rel = src.resolve().relative_to(out.parent.resolve())
            except ValueError:
                rel = Path(src.name)
            tag = str(rel).replace("/", "__").replace("\\", "__")
            # Keep intermediates in cwd (pack project), not next to -o (e.g. packs/).
            obj = Path.cwd() / f".{out.stem}.{tag}.o"
            compile_to_obj(src, obj, opt)
            objs.append(obj)
        if wasm_ld:
            cmd = [wasm_ld, "--no-entry", "--allow-undefined", "-o", str(out)]
        else:
            cmd = [
                clang,
                "--target=wasm32",
                "-nostdlib",
                "-Wl,--no-entry",
                "-Wl,--allow-undefined",
                "-o",
                str(out),
            ]
        if exports:
            for sym in exports:
                flag = f"--export={sym}" if wasm_ld else f"-Wl,--export={sym}"
                cmd.append(flag)
        else:
            cmd.append("--export-all" if wasm_ld else "-Wl,--export-all")
        cmd.extend(str(o) for o in objs)
        print("+", " ".join(cmd), file=sys.stderr)
        subprocess.check_call(cmd)
    finally:
        for o in objs:
            try:
                o.unlink()
            except OSError:
                pass


def resolve_pack_root(arg: Path) -> tuple[Path, Path] | None:
    """If arg is a pack dir or pack.toml, return (root, pack.toml path)."""
    if arg.is_file() and arg.name == "pack.toml":
        return arg.parent.resolve(), arg.resolve()
    if arg.is_dir():
        manifest = arg / "pack.toml"
        if manifest.is_file():
            return arg.resolve(), manifest.resolve()
    return None


def manifest_to_build(
    root: Path, data: dict
) -> tuple[
    list[str],
    list[str],
    list[tuple[str, str, str, int]],
    list[tuple[str, str]],
    list[Path],
    str,
    bool | None,
    list[str] | None,
    bool | None,
]:
    """Return sources…, name, freeze, target_specs, keep_source.

    None fields mean “use CLI / tool defaults”.
    """
    name = data.get("name")
    if not name or not isinstance(name, str):
        raise SystemExit("wasm_pack: pack.toml missing string 'name'")

    native = data.get("native") or {}
    sources: list[str] = []
    listed = native.get("sources")
    if listed:
        if not isinstance(listed, list) or not all(isinstance(s, str) for s in listed):
            raise SystemExit("wasm_pack: native.sources must be a list of strings")
        for s in listed:
            p = (root / s).resolve()
            if not p.is_file():
                raise SystemExit(f"wasm_pack: source not found: {p}")
            sources.append(str(p))
    else:
        ndir = native.get("dir", DEFAULT_SRC_DIR)
        if not isinstance(ndir, str):
            raise SystemExit("wasm_pack: native.dir must be a string")
        d = (root / ndir).resolve()
        sources = collect_native_sources(d)
        if not sources:
            raise SystemExit(
                f"wasm_pack: no native sources (set native.sources or put "
                f".c/.cpp/.rs under {ndir}/, nested ok)"
            )

    link_exports: list[str] = []
    pack_exports: list[tuple[str, str, str, int]] = []
    for item in data.get("exports") or []:
        if not isinstance(item, dict):
            continue
        func = item.get("func")
        if not isinstance(func, str) or not func:
            continue
        export_name = item.get("export", func)
        if not isinstance(export_name, str) or not export_name:
            export_name = func
        module = item.get("module", "")
        if module is None:
            module = ""
        if not isinstance(module, str):
            raise SystemExit("wasm_pack: exports.module must be a string")
        if module == ".":
            module = ""
        sig = item.get("sig")
        sig_s = sig if isinstance(sig, str) else None
        pack_exports.append((module, func, export_name, sig_tag(sig_s)))
        if export_name not in link_exports:
            link_exports.append(export_name)

    life = data.get("lifecycle") or {}
    for key in ("load", "unload"):
        fn = life.get(key)
        if isinstance(fn, str) and fn and fn not in link_exports:
            link_exports.append(fn)

    imports: list[tuple[str, str]] = []
    for item in data.get("imports") or []:
        if not isinstance(item, dict):
            continue
        mod = item.get("module")
        func = item.get("func")
        if isinstance(mod, str) and mod and isinstance(func, str) and func:
            imports.append((mod, func))

    mounts: list[Path] = []
    py = data.get("python") or {}
    mount = py.get("mount", DEFAULT_SRC_DIR)
    if isinstance(mount, str) and mount:
        m = (root / mount).resolve()
        if m.is_dir():
            mounts.append(m)

    freeze: bool | None = None
    if "freeze" in py:
        freeze = bool(py.get("freeze"))

    target_specs: list[str] | None = None
    if "targets" in py:
        raw_t = py.get("targets")
        if raw_t is None:
            target_specs = []
        elif isinstance(raw_t, list) and all(isinstance(x, str) for x in raw_t):
            target_specs = list(raw_t)
        else:
            raise SystemExit("wasm_pack: python.targets must be a list of strings")

    keep_source: bool | None = None
    if "keep_source" in py:
        keep_source = bool(py.get("keep_source"))

    return (
        sources,
        link_exports,
        pack_exports,
        imports,
        mounts,
        name,
        freeze,
        target_specs,
        keep_source,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "inputs",
        nargs="+",
        help="C sources, a pack directory, pack.toml, or a __pmm__.toml card/its dir",
    )
    ap.add_argument("-o", "--output", required=True, help="Output .wasm path")
    ap.add_argument("--export", action="append", default=[], help="Export symbol (repeatable)")
    ap.add_argument("-O", default="2", help="Optimization level (default 2)")
    ap.add_argument("--name", help="Package name for wasmmod.pack (default: output stem)")
    ap.add_argument(
        "--mount",
        action="append",
        default=[],
        type=Path,
        help="Directory of .py/.mpy/assets to embed (repeatable; default from pack.toml: src/)",
    )
    ap.add_argument(
        "--freeze",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Emit bytecode targets (default: off; pack.toml freeze/targets)",
    )
    ap.add_argument(
        "--python-target",
        action="append",
        default=[],
        dest="python_targets",
        help="Bytecode target e.g. upy:mpy6:sib31 or cpy:cp312 (repeatable)",
    )
    ap.add_argument(
        "--keep-source",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Keep .py beside bytecode (default: on when targets are set)",
    )
    ap.add_argument(
        "--mpy-cross",
        default=os.environ.get("MPY_CROSS"),
        help="mpy-cross binary (default: MPY_CROSS or discover next to host tree)",
    )
    ap.add_argument(
        "--no-pack-section",
        action="store_true",
        help="Do not append wasmmod.pack even if --mount/--name given",
    )
    ap.add_argument(
        "--write-mpack",
        nargs="?",
        const="",
        default=None,
        help="Write raw wasmmod.pack payload to PATH (default: <out>.mpack)",
    )
    ap.add_argument(
        "--aot",
        nargs="?",
        const="",
        default=None,
        help="Run wamrc to produce PATH (default: <out>.aotN; N=WAMR AOT format)",
    )
    ap.add_argument("--wamrc", default=os.environ.get("WAMRC", "wamrc"), help="wamrc binary")
    ap.add_argument(
        "--with-source",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Embed wasmmod.source (pack tree minus build artifacts); default from [source] embed",
    )
    ap.add_argument(
        "--pkg-version",
        default=None,
        help="Package version string stored in wasmmod.source (default: pack.toml version)",
    )
    ap.add_argument(
        "--tag",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Build tag for wasmmod.source (repeatable)",
    )
    ap.add_argument(
        "--compress-source",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="zlib-compress source entries (default: on)",
    )
    ap.add_argument(
        "--compress",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="zlib-compress pack .py/.mpy/.pyc entries (default: on)",
    )
    args = ap.parse_args()

    sources: list[str] = []
    link_exports: list[str] = list(args.export)
    pack_exports: list[tuple[str, str, str, int]] = []
    pack_imports: list[tuple[str, str]] = []
    pack_deps: list[tuple[str, str]] = []
    mounts: list[Path] = list(args.mount)
    pkg_name: str | None = args.name
    # Default: source-only. Opt in via freeze/targets / --freeze / --python-target.
    freeze: bool | None = args.freeze
    manifest_freeze: bool | None = None
    manifest_targets: list[str] | None = None
    manifest_keep: bool | None = None
    pack_root: Path | None = None
    pkg_version: str | None = args.pkg_version
    manifest_embed_source: bool | None = None
    manifest_compress_source: bool | None = None
    manifest_compress_pack: bool | None = None
    source_tags: list[tuple[str, str]] = []

    for inp in args.inputs:
        path = Path(inp)
        pmm_resolved = pmm.resolve_pmm_root(path)
        resolved = pmm_resolved if pmm_resolved is not None else resolve_pack_root(path)
        if resolved is not None:
            root, manifest = resolved
            data = pmm.synthesize_manifest_dict(root, manifest) if pmm_resolved is not None else load_toml(manifest)
            (
                m_sources,
                m_link,
                m_pack,
                m_imports,
                m_mounts,
                m_name,
                m_freeze,
                m_targets,
                m_keep,
            ) = manifest_to_build(root, data)
            sources.extend(m_sources)
            for e in m_link:
                if e not in link_exports:
                    link_exports.append(e)
            pack_exports.extend(m_pack)
            pack_imports.extend(m_imports)
            for name_ver in parse_manifest_deps(data):
                if name_ver not in pack_deps:
                    pack_deps.append(name_ver)
            for m in m_mounts:
                if m not in mounts:
                    mounts.append(m)
            if pkg_name is None:
                pkg_name = m_name
            if m_freeze is not None:
                manifest_freeze = m_freeze
            if m_targets is not None:
                manifest_targets = m_targets
            if m_keep is not None:
                manifest_keep = m_keep
            pack_root = root
            if pkg_version is None:
                ver = data.get("version")
                if isinstance(ver, str):
                    pkg_version = ver
            src_cfg = data.get("source") or {}
            if isinstance(src_cfg, dict):
                if "embed" in src_cfg:
                    manifest_embed_source = bool(src_cfg.get("embed"))
                if "compress" in src_cfg:
                    manifest_compress_source = bool(src_cfg.get("compress"))
                raw_tags = src_cfg.get("tags") or {}
                if isinstance(raw_tags, dict):
                    for k, v in raw_tags.items():
                        if isinstance(k, str) and isinstance(v, str):
                            source_tags.append((k, v))
            pack_cfg = data.get("pack") or {}
            if isinstance(pack_cfg, dict) and "compress" in pack_cfg:
                manifest_compress_pack = bool(pack_cfg.get("compress"))
            print(f"manifest {manifest}", file=sys.stderr)
            continue
        if path.is_file():
            sources.append(str(path.resolve()))
            continue
        raise SystemExit(f"wasm_pack: not a source, pack dir, pack.toml, or __pmm__.toml: {inp}")

    for t in args.tag:
        if "=" not in t:
            raise SystemExit(f"wasm_pack: --tag needs KEY=VALUE, got {t!r}")
        k, v = t.split("=", 1)
        source_tags.append((k, v))

    target_specs: list[str] = list(args.python_targets)
    if not target_specs and manifest_targets is not None:
        target_specs = list(manifest_targets)

    if freeze is None:
        if target_specs:
            freeze = True
        else:
            freeze = False if manifest_freeze is None else manifest_freeze

    if freeze and not target_specs:
        target_specs = list(DEFAULT_PYTHON_TARGETS)

    if not freeze:
        target_specs = []

    targets = [parse_python_target(s) for s in target_specs]
    keep_source = True
    if args.keep_source is not None:
        keep_source = args.keep_source
    elif manifest_keep is not None:
        keep_source = manifest_keep
    elif not targets:
        keep_source = True

    # CLI --export without pack.toml metadata → auto-arity table entries.
    if args.export and not pack_exports:
        for e in args.export:
            pack_exports.append(("", e, e, SIG_AUTO))

    if not sources:
        raise SystemExit("wasm_pack: no sources to compile")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    compile_wasm(sources, out, link_exports, args.O)

    raw = out.read_bytes()
    want_section = (not args.no_pack_section) and (mounts or pkg_name or pack_exports)
    if want_section:
        name = pkg_name or out.stem
        mpy_cross = args.mpy_cross or find_mpy_cross()
        files = (
            collect_mounts(
                mounts,
                targets=targets,
                keep_source=keep_source,
                mpy_cross=mpy_cross,
                opt=args.O,
            )
            if mounts
            else []
        )
        n_mpy = sum(1 for _, k, _ in files if k == KIND_MPY)
        n_py = sum(1 for _, k, _ in files if k == KIND_PY)
        n_pyc = sum(1 for _, k, _ in files if k == KIND_PYC)
        compress_pack = True
        if args.compress is not None:
            compress_pack = args.compress
        elif manifest_compress_pack is not None:
            compress_pack = manifest_compress_pack
        payload = build_pack_payload(name, files, pack_exports or None, compress=compress_pack)
        stats = getattr(build_pack_payload, "last_stats", {})
        raw = append_custom_section(raw, SECTION_NAME, payload)
        ratio = ""
        if stats.get("raw_total"):
            kept = 100.0 * stats["packed_total"] / stats["raw_total"]
            ratio = f" compress={compress_pack} zlib_files={stats.get('n_zlib', 0)} kept={kept:.0f}%"
        print(
            f"packed section {SECTION_NAME!r}: name={name!r} files={len(files)} "
            f"(py={n_py} mpy={n_mpy} pyc={n_pyc} targets={len(targets)}) "
            f"exports={len(pack_exports)} payload={len(payload)}B{ratio}",
            file=sys.stderr,
        )
    if pack_imports:
        ipayload = build_imports_payload(pack_imports)
        raw = append_custom_section(raw, IMPORTS_SECTION, ipayload)
        print(
            f"packed section {IMPORTS_SECTION!r}: imports={len(pack_imports)} payload={len(ipayload)}B",
            file=sys.stderr,
        )
    if pack_deps:
        dpayload = build_deps_payload(pack_deps)
        raw = append_custom_section(raw, DEPS_SECTION, dpayload)
        print(
            f"packed section {DEPS_SECTION!r}: deps={len(pack_deps)} payload={len(dpayload)}B",
            file=sys.stderr,
        )

    want_source = args.with_source
    if want_source is None:
        want_source = bool(manifest_embed_source)
    compress_source = True
    if args.compress_source is not None:
        compress_source = args.compress_source
    elif manifest_compress_source is not None:
        compress_source = manifest_compress_source
    if want_source:
        if pack_root is None:
            raise SystemExit(
                "wasm_pack: --with-source needs a pack directory / pack.toml input"
            )
        from .source import embed_source_section

        name = pkg_name or out.stem
        ver = pkg_version or "0.0.0"
        raw, n_src, plen = embed_source_section(
            raw,
            pack_root,
            name,
            ver,
            source_tags,
            compress=compress_source,
        )
        print(
            f"packed section 'wasmmod.source': name={name!r} version={ver!r} "
            f"files={n_src} tags={len(source_tags)} payload={plen}B compress={compress_source}",
            file=sys.stderr,
        )

    if want_section or pack_imports or pack_deps or want_source:
        out.write_bytes(raw)
    else:
        raw = out.read_bytes()

    if args.write_mpack is not None:
        mpack_path = Path(args.write_mpack) if args.write_mpack else out.with_suffix(".mpack")
        payload = extract_custom_section(raw, SECTION_NAME)
        if payload is None:
            raise SystemExit("wasm_pack: no wasmmod.pack section to write")
        mpack_path.write_bytes(payload)
        print(f"wrote {mpack_path} ({len(payload)}B)", file=sys.stderr)

    if args.aot is not None:
        aot_path = aot_output_path(out, args.aot if args.aot else None)
        wamrc = args.wamrc
        if not Path(wamrc).is_file():
            found = shutil.which(wamrc)
            if found:
                wamrc = found
            else:
                # Common metalpython / wasmmod host build location.
                wm = wasmmod_root()
                if wm is not None:
                    cand = wm.parents[1] / "ports" / "unix" / "build-wamrc" / "wamrc"
                    # wm = …/extmod/wasmmod → parents[1]=metalpython
                    if not cand.is_file():
                        cand = wm.parents[2] / "metalpython" / "ports" / "unix" / "build-wamrc" / "wamrc"
                    if cand.is_file():
                        wamrc = str(cand)
        # Carry pack metadata into the .aot (same payloads as on the .wasm).
        # Do NOT emit wasmmod.sig here: the signature covers the final artifact
        # bytes (sign after AOT with `sign sign --key … --chain …`).
        emit = "wasmmod.pack,wasmmod.imports,wasmmod.deps,wasmmod.source"
        cmd = [
            wamrc,
            f"--emit-custom-sections={emit}",
            "-o",
            str(aot_path),
            str(out),
        ]
        print("+", " ".join(cmd), file=sys.stderr)
        try:
            subprocess.check_call(cmd)
        except (OSError, subprocess.CalledProcessError) as e:
            raise SystemExit(
                f"wasm_pack: wamrc failed ({e}); install/build wamrc for --aot "
                f"(or pass --wamrc /path/to/wamrc)"
            ) from e
        print(aot_path, file=sys.stderr)
        print(aot_path)

    print(out)
    return 0


def extract_custom_section(wasm: bytes, section_name: str) -> bytes | None:
    if len(wasm) >= 4 and wasm[:4] == b"\x7fELF":
        from .elf import find_section

        return find_section(wasm, section_name)
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
    raise SystemExit("wasm_pack: truncated wasm")


if __name__ == "__main__":
    raise SystemExit(main())
