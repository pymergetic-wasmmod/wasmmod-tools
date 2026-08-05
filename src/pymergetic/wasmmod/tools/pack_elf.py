"""Embed wasmmod.pack (+ imports/deps/python tree) into an ELF64 ET_REL object."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent

from . import elf as elf
from . import pack as pack


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--obj", required=True, type=Path, help="input ET_REL .o/.elf")
    ap.add_argument("--manifest", required=True, type=Path, help="pack.toml")
    ap.add_argument("-o", "--output", required=True, type=Path)
    ap.add_argument(
        "--mpy-cross",
        default=None,
        help="mpy-cross binary when freeze/upy targets are set",
    )
    args = ap.parse_args(argv)

    manifest = args.manifest.resolve()
    root = manifest.parent
    data = pack.load_toml(manifest)
    name = data.get("name") or args.output.stem.split(".")[0]
    exports: list[tuple[str, str, str, int]] = []
    for item in data.get("exports") or []:
        if not isinstance(item, dict):
            continue
        func = item.get("func") or ""
        export_name = item.get("export") or func
        module = item.get("module") or ""
        sig_s = item.get("sig") if isinstance(item.get("sig"), str) else None
        exports.append((module, func, export_name, pack.sig_tag(sig_s)))

    imports: list[tuple[str, str]] = []
    for item in data.get("imports") or []:
        if not isinstance(item, dict):
            continue
        mod = item.get("module") or ""
        func = item.get("func") or ""
        if mod and func:
            imports.append((mod, func))

    deps = pack.parse_manifest_deps(data)

    py = data.get("python") or {}
    mount = py.get("mount", pack.DEFAULT_SRC_DIR)
    mounts: list[Path] = []
    if isinstance(mount, str) and mount:
        m = (root / mount).resolve()
        if m.is_dir():
            mounts.append(m)
        elif mount != pack.DEFAULT_SRC_DIR:
            raise SystemExit(f"pack-elf: python.mount not a directory: {m}")

    target_specs: list[str] = []
    raw_t = py.get("targets")
    if isinstance(raw_t, list) and all(isinstance(x, str) for x in raw_t):
        target_specs = list(raw_t)
    targets = [pack.parse_python_target(s) for s in target_specs]

    keep_source = True
    if "keep_source" in py:
        keep_source = bool(py.get("keep_source"))
    elif targets:
        keep_source = True

    files: list[tuple[str, int, bytes]] = []
    if mounts:
        files = pack.collect_mounts(
            mounts,
            targets=targets,
            keep_source=keep_source if targets else True,
            mpy_cross=args.mpy_cross or os.environ.get("MPY_CROSS"),
            opt="2",
        )

    compress = bool((data.get("pack") or {}).get("compress", False))
    payload = pack.build_pack_payload(name, files, exports, compress=compress)
    raw = args.obj.read_bytes()
    out = elf.append_section(raw, "wasmmod.pack", payload)
    if imports:
        out = elf.append_section(out, pack.IMPORTS_SECTION, pack.build_imports_payload(imports))
    if deps:
        out = elf.append_section(out, pack.DEPS_SECTION, pack.build_deps_payload(deps))

    src = data.get("source") or {}
    if bool(src.get("embed", False)):
        from .source import embed_source_section

        ver = data.get("version") or "0.0.0"
        if not isinstance(ver, str):
            ver = "0.0.0"
        compress_source = bool(src.get("compress", True))
        out, n_src, plen = embed_source_section(
            out, root, name, ver, [], compress=compress_source
        )
        print(
            f"packed section 'wasmmod.source': files={n_src} payload={plen}B",
            file=sys.stderr,
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(out)
    n_py = sum(1 for _, k, _ in files if k == pack.KIND_PY)
    n_mpy = sum(1 for _, k, _ in files if k == pack.KIND_MPY)
    print(
        f"wrote {args.output} pack={name} exports={len(exports)} "
        f"imports={len(imports)} deps={len(deps)} "
        f"files={len(files)} (py={n_py} mpy={n_mpy})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
