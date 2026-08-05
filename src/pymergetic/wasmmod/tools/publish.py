
# This file is part of wasmmod, https://github.com/pymergetic/wasmmod
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
One-shot CDN release: pack → AOT → sign → zlib → metal-cdn upload.

By default builds **wasm + AOT** and attaches any matching ELF twins under
``-o`` / ``--elf``. Use ``--no-aot`` / ``--no-elf`` for a faster local loop;
uploads should keep the full set.

  tools/wasmmod.py publish examples/hello --version 0.1.0 \\
      --key .keys/sign/leaf.key.pem --chain .keys/sign/chain.der

  # Explicit ELF twin (otherwise auto-picks packs/<pkg>.elf / .<arch>.elf):
  tools/wasmmod.py publish examples/hello --version 0.1.0 --elf packs/hello.elf \\
      --arch x86_64 --key … --chain …

  # Dev: skip AOT (and optional ELF) for a closer pack loop:
  tools/wasmmod.py publish examples/hello --version 0.1.0 --no-aot --no-elf \\
      --dry-run --key … --chain …

  # Stage artifacts only (no HTTP):
  tools/wasmmod.py publish examples/hello --version 0.1.0 --dry-run \\
      --key … --chain …

  # Upload already-built naked artifacts (skip pack/AOT):
  tools/wasmmod.py publish --from-artifacts packs/hello.wasm packs/hello.elf \\
      --package hello --version 0.1.0 --token "$METAL_CDN_TOKEN" \\
      --cdn-url https://cdn.example/cdn

Requires: openssl (sign), wamrc (unless ``--no-aot``), and
``pip install pymergetic-metal-cdn-client`` for upload (not needed for --dry-run).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
PROG = "wasmmod publish"


def _load(stem: str):
    """Load a tools submodule by legacy wasmmod_* stem or short name."""
    import importlib
    name = stem
    if name.startswith("wasmmod_"):
        name = name[len("wasmmod_") :]
    elif name == "wasmmod":
        name = "__main__"
    return importlib.import_module(f"pymergetic.wasmmod.tools.{name}")



def _cli():
    return _load("wasmmod_cliutil")


def _read_manifest_meta(pack_arg: Path) -> dict[str, Any]:
    """Read publish metadata from pack.toml when present."""
    pack = _load("wasmmod_pack")
    resolved = pack.resolve_pack_root(pack_arg)
    if resolved is None:
        return {}
    _root, manifest = resolved
    data = pack.load_toml(manifest)
    meta: dict[str, Any] = {}
    if isinstance(data.get("name"), str):
        meta["name"] = data["name"]
    ver = data.get("version")
    if ver is not None:
        meta["version"] = ver if isinstance(ver, str) else str(ver)
    for key in ("description", "homepage", "license", "comment"):
        val = data.get(key)
        if isinstance(val, str) and val:
            meta[key] = val
    author = data.get("author") or data.get("maintainer") or data.get("maintainer_email")
    if isinstance(author, str) and author:
        meta["maintainer_email"] = author
    try:
        deps = pack.parse_manifest_deps(data)
    except SystemExit:
        deps = []
    if deps:
        meta["deps"] = dict(deps)
    return meta


def _run_pack(
    pack_arg: Path,
    *,
    out_wasm: Path,
    package: str | None,
    version: str | None,
    aot: bool,
    wamrc: str,
    extra_pack_args: list[str],
) -> tuple[Path, Path | None, int | None]:
    pack = _load("wasmmod_pack")
    argv = [
        str(pack_arg),
        "-o",
        str(out_wasm),
        *extra_pack_args,
    ]
    if package:
        argv.extend(["--name", package])
    if version:
        argv.extend(["--pkg-version", version])
    if aot:
        argv.append("--aot")
        argv.extend(["--wamrc", wamrc])

    old = sys.argv
    sys.argv = ["wasmmod pack", *argv]
    try:
        rc = int(pack.main())
    finally:
        sys.argv = old
    if rc != 0:
        raise SystemExit(rc)
    if not out_wasm.is_file():
        _cli().die(PROG, f"pack did not write {out_wasm}")

    aot_path: Path | None = None
    aot_ver: int | None = None
    if aot:
        built_aot = Path(pack.aot_output_path(out_wasm))
        if not built_aot.is_file():
            _cli().die(PROG, f"AOT output missing: {built_aot}")
        aot_path = built_aot
        aot_ver = pack.aot_format_version() or None
        # Tagged name hello.aot6 → version 6
        m = re.search(r"\.aot(\d+)$", built_aot.name)
        if m:
            aot_ver = int(m.group(1))
    return out_wasm, aot_path, aot_ver


def _sign(path: Path, *, key: Path, chain: Path | None, cert: Path | None) -> None:
    sign = _load("wasmmod_sign")
    sign.cmd_sign(key, path, cert=cert, chain=chain)


def _zlib_wrap(path: Path) -> Path:
    zmod = _load("wasmmod_zlib")
    out = Path(str(path) + ".zlib")
    out.write_bytes(zmod.wrap_bytes(path.read_bytes()))
    print(f"wrapped {path} → {out}", file=sys.stderr)
    return out


def _cdn_name(path: Path, *, arch: str | None) -> Path:
    """Optionally insert arch infix before .aotN / .elf (CDN layout)."""
    if not arch:
        return path
    name = path.name
    m = re.match(r"^(?P<stem>.+)\.aot(?P<ver>\d*)(?P<zlib>\.zlib)?$", name)
    if m:
        ver = m.group("ver")
        zlib_suf = m.group("zlib") or ""
        renamed = path.with_name(f"{m.group('stem')}.{arch}.aot{ver}{zlib_suf}")
        if renamed != path:
            path.rename(renamed)
            print(f"renamed {path.name} → {renamed.name}", file=sys.stderr)
        return renamed
    m = re.match(r"^(?P<stem>.+)\.elf(?P<zlib>\.zlib)?$", name)
    if m:
        # Skip if already arch-tagged: hello.x86_64.elf
        stem = m.group("stem")
        if "." in Path(stem).name:
            return path
        zlib_suf = m.group("zlib") or ""
        renamed = path.with_name(f"{stem}.{arch}.elf{zlib_suf}")
        if renamed != path:
            path.rename(renamed)
            print(f"renamed {path.name} → {renamed.name}", file=sys.stderr)
        return renamed
    return path


def _stage_copy(path: Path, out_dir: Path) -> Path:
    """Copy *path* into *out_dir* unless it already lives there (avoids mutating sources)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    staged = out_dir / path.name
    if staged.resolve() != path.resolve():
        shutil.copy2(path, staged)
        return staged
    return path


def stage_artifacts(
    naked: list[Path],
    *,
    key: Path | None,
    chain: Path | None,
    cert: Path | None,
    do_sign: bool,
    do_zlib: bool,
    also_naked: bool,
    arch: str | None,
) -> list[Path]:
    """Sign (optional) + zlib-wrap; return files to upload."""
    upload: list[Path] = []
    for path in naked:
        target = path
        if do_sign:
            if key is None:
                _cli().die(PROG, "--key required to sign")
                raise SystemExit(1)  # die() is NoReturn; helps type checkers after dynamic import
            _sign(target, key=key, chain=chain, cert=cert)
        if arch and (".aot" in target.name or target.name.endswith(".elf") or ".elf." in target.name):
            target = _cdn_name(target, arch=arch)
        if do_zlib:
            upload.append(_zlib_wrap(target))
            if also_naked:
                upload.append(target)
        else:
            upload.append(target)
    return upload


def upload_files(
    files: list[Path],
    *,
    package: str,
    version: str,
    cdn_url: str | None,
    token: str | None,
    aot_version: int | None,
    lead: bool,
    pin: bool,
    force: bool,
    claim: bool,
    description: str | None,
    homepage: str | None,
    license: str | None,
    deps: dict[str, str] | None = None,
    maintainer_email: str | None = None,
) -> dict:
    cli = _cli()
    cdn = cli.require_cdn_client(PROG)
    CdnClient = cdn.CdnClient
    ClientError = cdn.ClientError
    if cdn_url and token:
        client = CdnClient(cdn_url, token=token)
    elif cdn_url or token:
        cli.die(PROG, "pass both --cdn-url and --token, or neither (config)")
    else:
        client = CdnClient.from_config()

    cli.warn_experimental(client, prog=PROG)

    if claim:
        try:
            client.claim(package)
            print(f"claimed {package}", file=sys.stderr)
        except ClientError as exc:
            # Already claimed by us is fine; treat other errors as hard fail.
            if exc.status not in (409, 400):
                cli.die_client(exc, prog=f"{PROG} claim")
            print(f"claim: {exc}", file=sys.stderr)

    try:
        result = client.publish(
            package=package,
            version=version,
            files=files,
            lead=lead,
            pin=pin,
            aot_version=aot_version,
            force=force,
            deps=deps or {},
            description=description,
            homepage=homepage,
            license=license,
            maintainer_email=maintainer_email,
        )
    except ClientError as exc:
        cli.die_client(exc, prog=PROG, force=force)
    return result if isinstance(result, dict) else {"ok": True}


def _print_publish_summary(result: dict[str, Any], *, file=sys.stderr) -> None:
    """Human-readable publish result (omit nested contents dump)."""
    pkg = result.get("package", "?")
    ver = result.get("version", "?")
    print(f"published {pkg}@{ver}", file=file)

    channels = result.get("channels") or []
    if channels:
        print(f"  channels:  {', '.join(str(c) for c in channels)}", file=file)

    artifacts = result.get("artifacts") or result.get("filenames") or []
    raw_contents = result.get("contents")
    contents: dict[str, Any] = raw_contents if isinstance(raw_contents, dict) else {}
    art_meta: dict[str, dict[str, Any]] = {}
    for item in contents.get("artifacts") or []:
        if isinstance(item, dict) and item.get("filename"):
            art_meta[str(item["filename"])] = item

    if artifacts:
        print("  artifacts:", file=file)
        seen_meta: set[str] = set()
        for name in artifacts:
            base = str(name).rsplit("/", 1)[-1]
            meta = art_meta.get(str(name)) or art_meta.get(base) or {}
            # Pin + lead share one inspect blob — detail only once per basename.
            show_detail = bool(meta) and base not in seen_meta
            if show_detail:
                seen_meta.add(base)
            bits: list[str] = []
            if show_detail:
                size = meta.get("size")
                if size is not None:
                    try:
                        from pymergetic.metal.cdn_client.format import human_size

                        bits.append(human_size(size))
                    except ImportError:
                        bits.append(f"{size}B")
                kind = meta.get("kind")
                enc = meta.get("encoding")
                if kind:
                    bits.append(str(kind) + (f"/{enc}" if enc else ""))
                if meta.get("signed"):
                    bits.append("signed")
                n_pack = meta.get("pack_file_count")
                n_src = meta.get("source_file_count")
                if n_pack is not None:
                    bits.append(f"pack={n_pack}")
                if n_src is not None:
                    bits.append(f"source={n_src}")
                err = meta.get("error")
                if err:
                    bits.append(f"error={err}")
            suffix = f" ({', '.join(bits)})" if bits else ""
            print(f"    {name}{suffix}", file=file)
    elif art_meta:
        print("  artifacts:", file=file)
        for name, meta in art_meta.items():
            size = meta.get("size")
            if size is None:
                print(f"    {name}", file=file)
            else:
                try:
                    from pymergetic.metal.cdn_client.format import human_size

                    label = human_size(size)
                except ImportError:
                    label = f"{size}B"
                print(f"    {name} ({label})", file=file)

    if contents:
        flags: list[str] = []
        if contents.get("has_pack"):
            flags.append("pack")
        if contents.get("has_source"):
            flags.append("source")
        if contents.get("signed"):
            flags.append("signed")
        exports = contents.get("exports") or []
        if flags or exports:
            line = "  contents:  " + ("+".join(flags) if flags else "—")
            if exports:
                line += f"  exports={exports}"
            print(line, file=file)

    indexes = result.get("index_paths") or []
    if indexes:
        print(f"  indexes:   {', '.join(str(p) for p in indexes)}", file=file)


def _require_file(path: Path, *, what: str, hint: str) -> None:
    if path.is_file():
        return
    _cli().die(PROG, f"missing {what}: {path}", hint)


def _discover_elfs(
    out_dir: Path,
    package: str,
    *,
    arch: str | None,
) -> list[Path]:
    """Find prebuilt ELF twins for *package* under *out_dir* (no build)."""
    names: list[str] = []
    if arch:
        names.append(f"{package}.{arch}.elf")
    machine = os.uname().machine
    if not arch or arch != machine:
        names.append(f"{package}.{machine}.elf")
    names.append(f"{package}.elf")
    found: list[Path] = []
    seen: set[Path] = set()
    for name in names:
        path = out_dir / name
        if not path.is_file():
            continue
        key = path.resolve()
        if key in seen:
            continue
        seen.add(key)
        found.append(path)
    return found


def _validate_publish_inputs(args: argparse.Namespace) -> None:
    """Fail fast before pack/AOT (expensive)."""
    cli = _cli()
    if not args.no_sign:
        if args.key is None:
            cli.die(
                PROG,
                "--key is required to sign (or pass --no-sign for an unsigned debug publish)",
                "Create keys:  python3 tools/wasmmod.py sign gen-pki -o .keys",
                "Then use:     --key .keys/sign/leaf.key.pem --chain .keys/sign/chain.der",
            )
        _require_file(
            args.key,
            what="signing key (--key)",
            hint="Create with: python3 tools/wasmmod.py sign gen-pki -o .keys",
        )
        if args.chain is not None:
            _require_file(
                args.chain,
                what="certificate chain (--chain)",
                hint="Expected next to the key after gen-pki, e.g. .keys/sign/chain.der",
            )
        elif args.cert is not None:
            _require_file(
                args.cert,
                what="leaf certificate (--cert)",
                hint="Or pass --chain .keys/sign/chain.der from gen-pki",
            )
        else:
            print(
                f"{PROG}: warning: no --chain/--cert — signature will have empty MPWS chain",
                file=sys.stderr,
            )

    if args.from_artifacts:
        for p in args.from_artifacts:
            _require_file(p, what="artifact (--from-artifacts)", hint="Pass an existing .wasm / .aotN / .elf path")
    elif args.pack is not None:
        pack = args.pack
        if not (pack.is_file() or pack.is_dir()):
            cli.die(PROG, f"pack path not found: {pack}")
    for elf_path in getattr(args, "elf", None) or []:
        _require_file(elf_path, what="ELF artifact (--elf)", hint="Build with: make -C examples/hello_elf")

    if not args.dry_run:
        url = (args.cdn_url or "").strip()
        token = (args.token or "").strip()
        if url and not token:
            cli.die(
                PROG,
                "--cdn-url was set but token is empty",
                "Export METAL_CDN_TOKEN (or pass --token), e.g. after metal-cdn login",
                "Or omit both flags to use saved metal-cdn login config",
                "Or use --dry-run to build/sign/zlib without uploading",
            )
        if token and not url:
            cli.die(
                PROG,
                "--token was set but --cdn-url / METAL_CDN_URL is empty",
                "Pass --cdn-url (e.g. http://127.0.0.1:8000/cdn) or set METAL_CDN_URL",
                "Or omit both flags to use saved metal-cdn login config",
            )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "pack",
        nargs="?",
        type=Path,
        help="Pack directory, pack.toml, or .c source (omit with --from-artifacts)",
    )
    ap.add_argument(
        "--from-artifacts",
        nargs="+",
        type=Path,
        help="Existing naked .wasm / .aotN / .elf files (skip pack/AOT; still sign+zlib unless --no-sign)",
    )
    ap.add_argument(
        "--elf",
        nargs="+",
        type=Path,
        default=[],
        help=(
            "Extra .elf packs to sign/zlib/upload beside the Wasm/AOT build. "
            "When omitted, auto-attach out-dir/<package>.elf and .<arch>.elf if present; "
            "use --no-elf to skip"
        ),
    )
    ap.add_argument(
        "--no-elf",
        action="store_true",
        help="Do not attach ELF twins (skip auto-discover and --elf)",
    )
    ap.add_argument("--package", help="CDN package name (default: pack.toml name / artifact stem)")
    ap.add_argument("--version", help="Package version (default: pack.toml version)")
    ap.add_argument("-o", "--out-dir", type=Path, default=Path("packs"), help="Build output dir")
    ap.add_argument(
        "--aot",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Compile AOT via wamrc (default: on). Use --no-aot for a faster pack-only loop",
    )
    ap.add_argument("--wamrc", default=os.environ.get("WAMRC", "wamrc"))
    ap.add_argument("--arch", help="Arch infix for AOT/ELF CDN names (e.g. x86_64)")
    ap.add_argument("--key", type=Path, help="ECDSA leaf key PEM")
    ap.add_argument("--chain", type=Path, help="Certificate chain DER (leaf first)")
    ap.add_argument("--cert", type=Path, help="Leaf cert DER (if no --chain)")
    ap.add_argument("--no-sign", action="store_true", help="Skip signing (debug only)")
    ap.add_argument("--no-zlib", action="store_true", help="Upload naked signed artifacts")
    ap.add_argument("--also-naked", action="store_true", help="Upload zlib and naked copies")
    ap.add_argument("--cdn-url", default=os.environ.get("METAL_CDN_URL"))
    ap.add_argument("--token", default=os.environ.get("METAL_CDN_TOKEN"))
    ap.add_argument("--claim", action="store_true", help="Claim package before publish")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--no-lead", action="store_true")
    ap.add_argument("--no-pin", action="store_true")
    ap.add_argument("--description")
    ap.add_argument("--homepage")
    ap.add_argument("--license")
    ap.add_argument("--maintainer-email", help="Author email (default: pack.toml author/maintainer)")
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Build/sign/zlib only; print upload list and exit",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Print full CDN publish response as JSON on stdout",
    )
    ap.add_argument(
        "--pack-arg",
        action="append",
        default=[],
        help="Extra arg forwarded to `wasmmod pack` (repeatable)",
    )
    args = ap.parse_args(argv)

    if not args.from_artifacts and args.pack is None:
        ap.error("pack path required (or pass --from-artifacts)")
    if args.no_elf and args.elf:
        ap.error("pass --elf or --no-elf, not both")

    _validate_publish_inputs(args)

    package = args.package
    version = args.version
    aot_version: int | None = None
    naked: list[Path] = []
    manifest_meta: dict[str, Any] = {}

    if args.from_artifacts:
        naked = [p.resolve() for p in args.from_artifacts]
        if package is None:
            package = naked[0].name.split(".")[0]
        if version is None:
            ap.error("--version required with --from-artifacts")
        for p in naked:
            m = re.search(r"\.aot(\d+)(?:\.zlib)?$", p.name)
            if m:
                aot_version = int(m.group(1))
    else:
        pack_arg = args.pack.resolve()
        manifest_meta = _read_manifest_meta(pack_arg)
        if package is None:
            package = manifest_meta.get("name")
        if version is None:
            version = manifest_meta.get("version")
        if version is None:
            ap.error("--version required (not found in pack.toml)")
        if package is None:
            # Fall back to out stem
            package = pack_arg.stem if pack_arg.is_file() else pack_arg.name

        args.out_dir.mkdir(parents=True, exist_ok=True)
        out_wasm = args.out_dir / f"{package}.wasm"
        wasm_path, aot_path, aot_version = _run_pack(
            pack_arg,
            out_wasm=out_wasm,
            package=package,
            version=version,
            aot=args.aot,
            wamrc=args.wamrc,
            extra_pack_args=list(args.pack_arg),
        )
        naked = [wasm_path]
        if aot_path is not None:
            naked.append(aot_path)

    assert package and version

    elf_paths: list[Path] = []
    if not args.no_elf:
        if args.elf:
            elf_paths = list(args.elf)
        else:
            already_elf = {
                p.resolve()
                for p in naked
                if p.suffix == ".elf" or ".elf." in p.name
            }
            # Auto-attach prebuilt twins (demos: make packs / packs-wasm).
            elf_paths = [
                p
                for p in _discover_elfs(args.out_dir, package, arch=args.arch)
                if p.resolve() not in already_elf
            ]
            if elf_paths:
                print(
                    "auto-elf: " + ", ".join(str(p) for p in elf_paths),
                    file=sys.stderr,
                )
            elif not already_elf and not args.from_artifacts:
                print(
                    f"{PROG}: note: no ELF twin under {args.out_dir}/ "
                    f"({package}.elf); build with make -C examples/{package}_elf "
                    "or pass --elf PATH (use --no-elf to silence)",
                    file=sys.stderr,
                )

    for elf_path in elf_paths:
        ep = elf_path.resolve()
        _require_file(ep, what="ELF artifact (--elf)", hint="Build with: make -C examples/hello_elf")
        naked.append(_stage_copy(ep, args.out_dir))

    # When --arch will rename AOT/ELF, stage any remaining sources into out_dir first.
    if args.arch:
        staged_naked: list[Path] = []
        for p in naked:
            if ".aot" in p.name or p.name.endswith(".elf") or ".elf." in p.name:
                staged_naked.append(_stage_copy(p, args.out_dir))
            else:
                staged_naked.append(p)
        naked = staged_naked

    description = args.description or manifest_meta.get("description") or manifest_meta.get("comment")
    homepage = args.homepage or manifest_meta.get("homepage")
    license_s = args.license or manifest_meta.get("license")
    maintainer = args.maintainer_email or manifest_meta.get("maintainer_email")
    deps = manifest_meta.get("deps") if isinstance(manifest_meta.get("deps"), dict) else {}
    do_sign = not args.no_sign
    do_zlib = not args.no_zlib

    upload = stage_artifacts(
        naked,
        key=args.key,
        chain=args.chain,
        cert=args.cert,
        do_sign=do_sign,
        do_zlib=do_zlib,
        also_naked=args.also_naked,
        arch=args.arch,
    )

    print("upload candidates:", file=sys.stderr)
    for f in upload:
        try:
            from pymergetic.metal.cdn_client.format import human_size

            sz = human_size(f.stat().st_size)
        except ImportError:
            sz = f"{f.stat().st_size}B"
        print(f"  {f} ({sz})", file=sys.stderr)

    if args.dry_run:
        print("dry-run: skipping CDN upload", file=sys.stderr)
        for f in upload:
            print(f)
        return 0

    result = upload_files(
        upload,
        package=package,
        version=version,
        cdn_url=args.cdn_url,
        token=args.token,
        aot_version=aot_version,
        lead=not args.no_lead,
        pin=not args.no_pin,
        force=args.force,
        claim=args.claim,
        description=description,
        homepage=homepage,
        license=license_s,
        deps=deps,
        maintainer_email=maintainer,
    )
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_publish_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli().invoke(main, prog=PROG))
