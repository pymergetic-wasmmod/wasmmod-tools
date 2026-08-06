"""Resolve the wasmmod git checkout (crates, examples, third_party)."""

from __future__ import annotations

import os
from pathlib import Path


def wasmmod_root() -> Path | None:
    """Return the wasmmod repo root, or None if not found.

    Order: ``WASMMOD_ROOT`` env, installed ``pymergetic-wasmmod`` share tree,
    cwd parents, then common os-sdk sibling layout.
    """
    env = os.environ.get("WASMMOD_ROOT")
    if env:
        p = Path(env).expanduser().resolve()
        if p.is_dir():
            return p
        return None

    def _looks_like(root: Path) -> bool:
        return (root / "loader.c").is_file() or (root / "crates" / "wasmmod-read").is_dir()

    here = Path.cwd().resolve()
    # Prefer a live checkout (cwd parents) over the wheel share tree — share may
    # lag (e.g. missing include/) while examples/ pack against the submodule.
    for cand in (here, *here.parents):
        if _looks_like(cand):
            return cand

    try:
        from pymergetic.wasmmod.rt import root as _rt_root

        bundled = _rt_root()
        if bundled is not None and _looks_like(bundled):
            return bundled
    except ImportError:
        pass

    # packages/wasmmod-tools → packages/metalpython/extmod/wasmmod
    pkg = Path(__file__).resolve()
    for parent in pkg.parents:
        sibling = parent / "metalpython" / "extmod" / "wasmmod"
        if _looks_like(sibling):
            return sibling
        sibling2 = parent / "extmod" / "wasmmod"
        if _looks_like(sibling2):
            return sibling2
    return None


def require_wasmmod_root() -> Path:
    root = wasmmod_root()
    if root is None:
        raise SystemExit(
            "wasmmod tools: cannot find wasmmod checkout.\n"
            "  pip install --pre pymergetic-wasmmod   # ships source under the wheel\n"
            "  # or: set WASMMOD_ROOT=/path/to/wasmmod (repo with loader.c / crates/)"
        )
    return root
