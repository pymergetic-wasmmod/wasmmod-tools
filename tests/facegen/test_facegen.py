"""Facegen tests removed — SoT is ``pymergetic.util.gen`` (Rust introspection).

Run:
  cargo test --lib
  cargo test --features gen --bin wasmmod-gen
"""

from __future__ import annotations

import subprocess
from pathlib import Path

WASMMOD = Path(__file__).resolve().parents[4]


def test_rust_util_gen_introspect_unit():
    """Registry+gen unit tests live in the Rust crate."""
    subprocess.check_call(
        ["cargo", "test", "--lib", "util::gen::"],
        cwd=WASMMOD,
    )


def test_wasmmod_gen_cli_builds():
    subprocess.check_call(
        ["cargo", "build", "--features", "gen", "--bin", "wasmmod-gen"],
        cwd=WASMMOD,
    )
    assert (WASMMOD / "target" / "debug" / "wasmmod-gen").is_file()
