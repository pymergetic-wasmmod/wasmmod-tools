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
        # Old reference tree (packages/metalpython/extmod/wasmmod).
        if (root / "loader.c").is_file() or (root / "crates" / "wasmmod-read").is_dir():
            return True
        # New destination tree (packages/micropython-wasmmod/extmod/wasmmod,
        # and the wheel-bundled rt/share/ copy of the same shape): a Cargo
        # crate with the loader/registry under src/pymergetic/wasmmod/.
        if (root / "Cargo.toml").is_file() and (root / "src" / "pymergetic" / "wasmmod").is_dir():
            return True
        return False

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

    # packages/wasmmod-tools → os-sdk packages/*/extmod/wasmmod checkouts
    pkg = Path(__file__).resolve()
    for parent in pkg.parents:
        for rel in (
            ("micropython-wasmmod", "extmod", "wasmmod"),
            ("metalpython", "extmod", "wasmmod"),
            ("extmod", "wasmmod"),
        ):
            sibling = parent.joinpath(*rel)
            if _looks_like(sibling):
                return sibling
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
