
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
``*.pmm.toml`` card-tree parser (the ``pmm-parser`` from ``docs/SOURCETREE.md``).

Replaces ``pack.toml`` as the manifest a deliverable root is packed from.
Does *not* replace ``manifest_to_build()`` in :mod:`pack.py` — instead this
module walks a card tree and produces a plain dict shaped exactly like a
parsed ``pack.toml``, so the existing (unchanged) ``manifest_to_build()``
keeps being the one place that turns a manifest dict into a build plan.
See ``docs/SOURCETREE.md``'s "Schema reference (consolidated)" section for
the authoritative key list this module implements against.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

CARD_NAME = "__pmm__.toml"


def _load_toml(path: Path) -> dict:
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError as e:
            raise SystemExit(
                "wasm_pack: need Python 3.11+ (tomllib) or the tomli package to read *.pmm.toml"
            ) from e
    with path.open("rb") as f:
        return tomllib.load(f)


@dataclass
class Card:
    """One parsed ``__pmm__.toml`` / bare-sibling ``x.pmm.toml``."""

    path: Path
    fqn: str
    pep420: bool
    impl: str | None  # "c" | "rs" | "py" | None (pep420 nodes)
    on_load: str | None
    on_unload: str | None
    deps: dict[str, str]
    version: str | None
    build: list[str]  # [] if this card isn't a deliverable root
    build_cfg: dict = field(default_factory=dict)

    @property
    def is_root(self) -> bool:
        return bool(self.build)

    @property
    def dir(self) -> Path:
        return self.path.parent


def load_card(path: Path) -> Card:
    """Parse one ``__pmm__.toml`` (or bare-sibling ``x.pmm.toml``) file.

    Only validates the card's own internal shape (required ``fqn``, either
    ``pep420`` or ``impl``, ``deps``/``version`` never both absent-`build`-
    and-present at once) — path/fqn agreement is a *tree*-level check, done
    by the caller once it knows the tree's ``src/`` anchor (see
    ``assert_fqn_matches_path``).
    """
    data = _load_toml(path)

    fqn = data.get("fqn")
    if not fqn or not isinstance(fqn, str):
        raise SystemExit(f"wasm_pack: {path}: missing required string 'fqn' (always first)")

    pep420 = bool(data.get("pep420", False))
    impl = data.get("impl")
    if pep420:
        if impl is not None:
            raise SystemExit(f"wasm_pack: {path}: 'pep420' and 'impl' are mutually exclusive")
    else:
        if impl not in ("c", "rs", "py"):
            raise SystemExit(f"wasm_pack: {path}: 'impl' must be one of c|rs|py (or set pep420 = true)")

    build = data.get("build") or []
    if build and (not isinstance(build, list) or not all(t in ("wasm", "elf") for t in build)):
        raise SystemExit(f"wasm_pack: {path}: 'build' must be an array of \"wasm\"/\"elf\"")

    deps = data.get("deps") or {}
    if deps and not isinstance(deps, dict):
        raise SystemExit(f"wasm_pack: {path}: 'deps' must be a table ({{fqn = version}})")
    version = data.get("version")

    # Root-only rule (docs/SOURCETREE.md decision log, corrected 2026-08-11):
    # a non-root module has no independent existence to depend on or pin a
    # version of — it always ships baked into whichever root's artifact
    # contains it, at that root's own commit/checkout.
    if not build and (deps or version is not None):
        raise SystemExit(
            f"wasm_pack: {path}: 'deps'/'version' are only meaningful on a "
            f"build-marked root (this card has no 'build' key)"
        )

    # `build` (array) is the deliverable-root marker; its knobs live under a
    # *distinctly named* `[build_cfg]` table — `build = [...]` then `[build]`
    # would both target the same TOML key and is a real parse error (found
    # while implementing this: tomllib raises "Cannot declare ('build',)
    # twice"), so the sub-table can't reuse the same name.
    build_cfg = data.get("build_cfg") or {}
    if build_cfg and not isinstance(build_cfg, dict):
        raise SystemExit(f"wasm_pack: {path}: 'build_cfg' must be a table")

    return Card(
        path=path,
        fqn=fqn,
        pep420=pep420,
        impl=impl,
        on_load=data.get("on_load"),
        on_unload=data.get("on_unload"),
        deps=deps,
        version=version,
        build=build if isinstance(build, list) else [],
        build_cfg=build_cfg,
    )


def find_src_root(card_dir: Path) -> Path | None:
    """Walk up from a card's own dir to the nearest ancestor literally
    named ``src`` — the anchor "path == module" is measured from."""
    for parent in (card_dir, *card_dir.parents):
        if parent.name == "src":
            return parent
    return None


def assert_fqn_matches_path(card: Card, src_root: Path) -> None:
    """Hard-error if fqn disagrees with the real path — a checked
    assertion, never an independent declaration (docs/SOURCETREE.md
    "Module card")."""
    rel = card.dir.relative_to(src_root)
    expected = ".".join(rel.parts)
    if expected != card.fqn:
        raise SystemExit(
            f"wasm_pack: {card.path}: fqn {card.fqn!r} disagrees with real path "
            f"(expected {expected!r} from {card.dir} relative to {src_root})"
        )


def _direct_card_path(p: Path) -> Path | None:
    if p.is_file() and p.name == CARD_NAME:
        return p
    if p.is_dir():
        c = p / CARD_NAME
        if c.is_file():
            return c
    return None


def resolve_pmm_root(arg: Path) -> tuple[Path, Path] | None:
    """If ``arg`` is (or contains) a build-marked ``*.pmm.toml``, or is a
    pack-root directory whose ``src/`` holds exactly one, return
    ``(pack_root, card_path)``. ``pack_root`` is where ``[build]`` knobs
    like ``mount`` resolve relative to (the old ``pack.toml`` dir's role).
    """
    direct = _direct_card_path(arg)
    if direct is not None:
        card = load_card(direct)
        src_root = find_src_root(card.dir)
        pack_root = src_root.parent if src_root is not None else card.dir
        return pack_root.resolve(), direct.resolve()

    if arg.is_dir():
        src_dir = arg / "src"
        if src_dir.is_dir():
            candidates = []
            for p in sorted(src_dir.rglob(CARD_NAME)):
                c = load_card(p)
                if c.is_root:
                    candidates.append(p)
            if len(candidates) == 1:
                return arg.resolve(), candidates[0].resolve()
            if len(candidates) > 1:
                raise SystemExit(
                    f"wasm_pack: multiple build-marked {CARD_NAME} under {src_dir}, "
                    f"name one directly instead of the pack-root dir"
                )
    return None


def walk_subtree(root_card_path: Path) -> list[Card]:
    """Collect every card in a build root's own subtree, stopping the
    instant a *nested* card also carries its own `build` key (recursive
    build boundary — docs/SOURCETREE.md). The root's own card is included
    even though it obviously has `build` set."""
    root_card = load_card(root_card_path)
    src_root = find_src_root(root_card.dir)
    if src_root is None:
        raise SystemExit(f"wasm_pack: {root_card_path}: no ancestor directory named 'src' found")
    assert_fqn_matches_path(root_card, src_root)

    out = [root_card]
    for p in sorted(root_card.dir.rglob(CARD_NAME)):
        if p == root_card_path:
            continue
        card = load_card(p)
        assert_fqn_matches_path(card, src_root)
        if card.is_root:
            # Nested build root: belongs entirely to its own build, never
            # folded into this one's compiled output. Don't descend past
            # it (rglob already yielded it; just skip adding it and rely
            # on the caller not walking its children as sources either —
            # subtree_sources() re-checks this per file's directory).
            continue
        out.append(card)
    return out


def _under_nested_root(path: Path, root_dir: Path, nested_roots: list[Path]) -> bool:
    for nr in nested_roots:
        try:
            path.relative_to(nr)
        except ValueError:
            continue
        if nr != root_dir:
            return True
    return False


def subtree_c_impl_files(root_card_path: Path) -> list[Path]:
    """Every ``__impl__.c`` inside a build root's own boundary (recursive
    build boundary applied: none from a nested root's own subtree)."""
    root_card = load_card(root_card_path)
    nested_root_dirs = [c.dir for c in walk_subtree(root_card_path) if c.is_root and c.dir != root_card.dir]
    out: list[Path] = []
    for p in sorted(root_card.dir.rglob("__impl__.c")):
        if _under_nested_root(p, root_card.dir, nested_root_dirs):
            continue
        out.append(p)
    return out


def synthesize_manifest_dict(pack_root: Path, card_path: Path) -> dict:
    """Build a ``pack.toml``-shaped dict from a ``*.pmm.toml`` card tree,
    so the existing, unchanged ``manifest_to_build()`` in ``pack.py`` can
    consume it exactly as it consumes a real parsed ``pack.toml``.
    """
    from . import faces

    root_card = load_card(card_path)
    if not root_card.is_root:
        raise SystemExit(f"wasm_pack: {card_path}: not a build-marked root (no 'build' key)")

    c_files = subtree_c_impl_files(card_path)
    if not c_files:
        raise SystemExit(f"wasm_pack: {card_path}: no __impl__.c found in this root's subtree")

    exports = faces.scan_c_exports(c_files)

    build_cfg = root_card.build_cfg

    data: dict = {
        "name": root_card.fqn,
        "native": {"sources": [str(p) for p in c_files]},
        "exports": [
            {"module": mod, "func": impl_fn, "export": export_name, "sig": sig}
            for (mod, export_name, impl_fn, sig) in exports
        ],
        "imports": [],  # face-derived import discovery: not built this pass (hello has none)
        "lifecycle": {
            "load": root_card.on_load or "",
            "unload": root_card.on_unload or "",
        },
        "deps": root_card.deps or {},
    }
    if root_card.version is not None:
        data["version"] = root_card.version

    python_cfg: dict = {}
    if "mount" in build_cfg:
        python_cfg["mount"] = build_cfg["mount"]
    if "freeze" in build_cfg:
        python_cfg["freeze"] = build_cfg["freeze"]
    if "targets" in build_cfg:
        python_cfg["targets"] = build_cfg["targets"]
    if "keep_source" in build_cfg:
        python_cfg["keep_source"] = build_cfg["keep_source"]
    if python_cfg:
        data["python"] = python_cfg

    source_cfg: dict = {}
    if "embed_source" in build_cfg:
        source_cfg["embed"] = build_cfg["embed_source"]
    if "compress_source" in build_cfg:
        source_cfg["compress"] = build_cfg["compress_source"]
    if source_cfg:
        data["source"] = source_cfg

    if "compress_pack" in build_cfg:
        data["pack"] = {"compress": build_cfg["compress_pack"]}

    return data
