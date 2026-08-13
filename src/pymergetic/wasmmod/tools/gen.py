"""``wasmmod gen`` — thin launcher for ``pymergetic.util.gen`` (Rust).

  cargo run --features gen --bin wasmmod-gen -- [--check] [path]

Product bin (after unix build with gen feature):

  micropython -c \"import pymergetic.util.gen as g; g.run('/path')\"
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def _crate_root() -> Path:
    here = Path(__file__).resolve()
    for p in here.parents:
        if (p / "src" / "pymergetic").is_dir() and (p / "Cargo.toml").is_file():
            return p
    return Path.cwd()


def _find_bin(crate: Path) -> Path | None:
    env = os.environ.get("WASMMOD_GEN")
    if env and Path(env).is_file():
        return Path(env)
    which = shutil.which("wasmmod-gen")
    if which:
        return Path(which)
    for profile in ("release", "debug"):
        cand = crate / "target" / profile / "wasmmod-gen"
        if cand.is_file():
            return cand
    return None


def _ensure_bin(crate: Path) -> Path:
    existing = _find_bin(crate)
    if existing is not None:
        return existing
    print("wasmmod gen: building wasmmod-gen (cargo --features gen)…", file=sys.stderr)
    subprocess.check_call(
        ["cargo", "build", "--features", "gen", "--bin", "wasmmod-gen"],
        cwd=crate,
    )
    bin_path = crate / "target" / "debug" / "wasmmod-gen"
    if not bin_path.is_file():
        raise SystemExit("wasmmod gen: binary missing after build")
    return bin_path


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    crate = _crate_root()
    bin_path = _ensure_bin(crate)
    return subprocess.call([str(bin_path), *args])


if __name__ == "__main__":
    raise SystemExit(main())
