# This file is part of wasmmod, https://github.com/pymergetic/wasmmod
#
# Discover nested pack.toml markers and build one .wasm per type=package.
#
#   tools/wasmmod.py pack-tree examples/tree/nested -o examples/packs
#
# Sibling flat packs (different repo) and nested monorepo trees both work:
# each directory with type="package" is taken out of the tree and packed alone.

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _load_toml(path: Path) -> dict:
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError as exc:
            raise SystemExit("pack-tree: need tomllib/tomli") from exc
    return tomllib.loads(path.read_text(encoding="utf-8"))


def discover_packages(root: Path) -> list[tuple[Path, str]]:
    """Return (pack_dir, package_name) for every type=package under root."""
    root = root.resolve()
    found: list[tuple[Path, str]] = []
    for manifest in sorted(root.rglob("pack.toml")):
        data = _load_toml(manifest)
        kind = data.get("type", "package")
        if kind != "package":
            continue
        name = data.get("name")
        if not isinstance(name, str) or not name:
            # Derive from path relative to walk root: a/b/c → a.b.c
            rel = manifest.parent.relative_to(root)
            name = ".".join(rel.parts) if rel.parts else root.name
        found.append((manifest.parent, name))
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="wasmmod pack-tree",
        description="Walk a source tree; pack each type=package pack.toml into its own .wasm",
    )
    ap.add_argument(
        "root",
        type=Path,
        help="Tree root to scan (e.g. examples/tree/nested/test_a2)",
    )
    ap.add_argument(
        "-o",
        "--out-dir",
        type=Path,
        required=True,
        help="Directory for <name>.wasm artifacts (flat dotted filenames)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print packages that would be built",
    )
    args = ap.parse_args(argv)

    root = args.root.resolve()
    if not root.is_dir():
        print(f"pack-tree: not a directory: {root}", file=sys.stderr)
        return 1

    packs = discover_packages(root)
    if not packs:
        print(f"pack-tree: no type=package pack.toml under {root}", file=sys.stderr)
        return 1

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    from . import pack

    for pack_dir, name in packs:
        out = out_dir / f"{name}.wasm"
        rel = pack_dir
        try:
            rel = pack_dir.relative_to(root)
        except ValueError:
            pass
        print(f"pack-tree: {rel} → {name} → {out}", file=sys.stderr)
        if args.dry_run:
            continue
        old_argv = sys.argv
        try:
            sys.argv = ["wasmmod pack", str(pack_dir), "-o", str(out)]
            rc = pack.main()
            if rc:
                return rc
        finally:
            sys.argv = old_argv

    print(f"pack-tree: built {len(packs)} package(s) into {out_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
