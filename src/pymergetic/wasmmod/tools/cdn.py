
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
Remote metal-cdn index / lookup / download (pip-style host tooling).

  tools/wasmmod.py cdn list
  tools/wasmmod.py cdn search hello
  tools/wasmmod.py cdn show hello
  tools/wasmmod.py cdn index
  tools/wasmmod.py cdn closure hello
  tools/wasmmod.py cdn get hello -o ./packs [--unwrap]

Uses ``pymergetic-metal-cdn-client`` + optional ``~/.config/metal-cdn/config.json``,
or ``--cdn-url`` / ``--token`` / ``METAL_CDN_URL`` / ``METAL_CDN_TOKEN``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
PROG = "wasmmod cdn"


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


def _client(args: argparse.Namespace) -> tuple[Any, type[BaseException]]:
    cli = _cli()
    cdn = cli.require_cdn_client(PROG)
    CdnClient = cdn.CdnClient
    ClientError = cdn.ClientError

    url = args.cdn_url or os.environ.get("METAL_CDN_URL")
    token = args.token or os.environ.get("METAL_CDN_TOKEN")
    if url:
        client = CdnClient(url, token=token)
    else:
        try:
            # Token optional — public list/show/get work anonymously when the CDN allows.
            client = CdnClient.from_config(require_token=False)
        except ClientError as exc:
            cli.die_client(
                exc,
                prog=PROG,
                extra_hints=["Set --cdn-url / METAL_CDN_URL or run: metal-cdn login --url …"],
            )
            raise SystemExit(1)
    cli.warn_experimental(client, prog=PROG)
    return client, ClientError


def _channel_query(channel: str) -> tuple[str, str | None]:
    """Return (list_channel_param, pin_version_or_None)."""
    if channel == "lead":
        return "lead", None
    if channel.startswith("@"):
        return channel, channel[1:]
    # bare version → pin
    return f"@{channel}", channel


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def _fmt_summary(row: dict[str, Any]) -> str:
    name = row.get("name", "?")
    ver = row.get("version", "?")
    arts = row.get("artifact_count", "?")
    flags: list[str] = []
    if row.get("yanked"):
        flags.append("yanked")
    if row.get("deprecated"):
        flags.append("deprecated")
    flag_s = f" [{', '.join(flags)}]" if flags else ""
    desc = row.get("description") or ""
    desc_s = f"  {desc}" if desc else ""
    return f"{name:28} {ver:12} arts={arts}{flag_s}{desc_s}"


def _cdn_fail(exc: BaseException) -> int:
    return _cli().report_client(exc, prog=PROG)


def cmd_list(args: argparse.Namespace) -> int:
    client, err_t = _client(args)
    ch, _ = _channel_query(args.channel)
    try:
        rows = client.list_packages(channel=ch)
    except err_t as exc:
        return _cdn_fail(exc)
    if args.json:
        _print_json(rows)
        return 0
    if not rows:
        print("(no packages)")
        return 0
    for row in rows:
        if isinstance(row, dict):
            print(_fmt_summary(row))
        else:
            print(row)
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    client, err_t = _client(args)
    ch, _ = _channel_query(args.channel)
    try:
        rows = client.search(args.query, channel=ch)
    except err_t as exc:
        return _cdn_fail(exc)
    if args.json:
        _print_json(rows)
        return 0
    if not rows:
        print("(no matches)")
        return 0
    for row in rows:
        if isinstance(row, dict):
            print(_fmt_summary(row))
        else:
            print(row)
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    client, err_t = _client(args)
    ch, _ = _channel_query(args.channel)
    try:
        entry = client.get_package(args.package, channel=ch)
    except err_t as exc:
        return _cdn_fail(exc)
    if args.json:
        _print_json(entry)
        return 0
    print(f"Name: {args.package}")
    print(f"Version: {entry.get('version')}")
    print(f"Channel: {ch}")
    if entry.get("aot_version") is not None:
        print(f"AOT format: {entry['aot_version']}")
    if entry.get("description"):
        print(f"Summary: {entry['description']}")
    if entry.get("homepage"):
        print(f"Home-page: {entry['homepage']}")
    if entry.get("license"):
        print(f"License: {entry['license']}")
    if entry.get("maintainer_email"):
        print(f"Maintainer: {entry['maintainer_email']}")
    if entry.get("yanked"):
        print(f"Yanked: {entry.get('yank_reason') or True}")
    if entry.get("deprecated"):
        print(f"Deprecated: successor={entry.get('successor')}")
    deps = entry.get("deps") or {}
    if deps:
        print("Requires:")
        for k, v in sorted(deps.items()):
            print(f"  {k} {v}")
    arts = entry.get("artifacts") or []
    print(f"Artifacts ({len(arts)}):")
    for art in arts:
        if isinstance(art, dict):
            fn = art.get("path") or art.get("filename") or art.get("name") or "?"
            kind = art.get("kind", "")
            enc = art.get("encoding", "")
            size = art.get("size")
            extra = " ".join(str(x) for x in (kind, enc, f"{size}B" if size is not None else "") if x)
            print(f"  {fn}" + (f"  ({extra})" if extra else ""))
        else:
            print(f"  {art}")
    contents = entry.get("contents") or {}
    if contents:
        # API returns JSON; accept either flat dict or model_dump shape.
        print("Contents:")
        if contents.get("name"):
            print(f"  Pack-name: {contents['name']}")
        if contents.get("pkg_version"):
            print(f"  Pack-version: {contents['pkg_version']}")
        print(f"  Signed: {contents.get('signed')}")
        print(
            f"  Has-pack: {contents.get('has_pack')}  Has-source: {contents.get('has_source')}"
        )
        pf = contents.get("pack_files") or []
        if pf:
            print(f"  Pack-files ({len(pf)}):")
            for p in pf[:40]:
                print(f"    {p}")
            if len(pf) > 40:
                print(f"    … +{len(pf) - 40} more")
        sf = contents.get("source_files") or []
        if sf:
            print(f"  Source-files ({len(sf)}):")
            for p in sf[:40]:
                print(f"    {p}")
            if len(sf) > 40:
                print(f"    … +{len(sf) - 40} more")
        ex = contents.get("exports") or []
        if ex:
            print(f"  Exports: {', '.join(str(e) for e in ex)}")
    return 0


def cmd_index(args: argparse.Namespace) -> int:
    client, err_t = _client(args)
    _, pin = _channel_query(args.channel)
    try:
        data = client.get_index(version=pin)
    except err_t as exc:
        return _cdn_fail(exc)
    _print_json(data)
    return 0


def cmd_closure(args: argparse.Namespace) -> int:
    client, err_t = _client(args)
    _, pin = _channel_query(args.channel)
    try:
        data = client.closure(args.package, version=pin)
    except err_t as exc:
        return _cdn_fail(exc)
    if args.json:
        _print_json(data)
        return 0
    order = data.get("order") or data.get("packages") or data
    if isinstance(order, list):
        for item in order:
            if isinstance(item, dict):
                print(f"{item.get('name', '?')}=={item.get('version', '?')}")
            else:
                print(item)
    else:
        _print_json(data)
    return 0


def _pick_artifacts(
    entry: dict[str, Any],
    *,
    prefer_zlib: bool,
    aot_only: bool,
    wasm_only: bool,
) -> list[str]:
    arts = entry.get("artifacts") or []
    names: list[str] = []
    for art in arts:
        if isinstance(art, dict):
            fn = str(art.get("path") or art.get("filename") or art.get("name") or "")
        else:
            fn = str(art)
        if not fn:
            continue
        fn = Path(fn).name
        is_aot = ".aot" in fn
        is_wasm = fn.endswith((".wasm", ".wasm.zlib"))
        if aot_only and not is_aot:
            continue
        if wasm_only and not is_wasm:
            continue
        names.append(fn)

    if prefer_zlib:
        zlib_names = [n for n in names if n.endswith(".zlib")]
        # Drop naked twin when zlib exists
        stems = {n[: -len(".zlib")] for n in zlib_names}
        names = [n for n in names if n.endswith(".zlib") or n not in stems]
    return names


def cmd_get(args: argparse.Namespace) -> int:
    client, err_t = _client(args)
    ch, pin = _channel_query(args.channel)
    try:
        entry = client.get_package(args.package, channel=ch)
    except err_t as exc:
        return _cdn_fail(exc)

    names = _pick_artifacts(
        entry,
        prefer_zlib=not args.raw,
        aot_only=args.aot_only,
        wasm_only=args.wasm_only,
    )
    if args.artifact:
        names = [args.artifact]
    if not names:
        _cli().report(PROG, "no matching artifacts on package")
        return 1

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    zmod = None
    if args.unwrap:
        zmod = _load("wasmmod_zlib")

    for name in names:
        try:
            dl = client.download_artifact(name, version=pin)
        except err_t as exc:
            return _cli().report_client(exc, prog=f"{PROG} get", extra_hints=[f"artifact={name}"])
        if dl.not_modified or dl.data is None:
            _cli().report(PROG, f"empty download for {name}")
            return 1
        data = dl.data
        dest_name = name
        if args.unwrap and name.endswith(".zlib"):
            if zmod is None:
                _cli().die(PROG, "unwrap requested but zlib helper missing")
                raise SystemExit(1)
            unwrap = zmod  # narrowed non-None for type checkers
            try:
                data = unwrap.unwrap_bytes(data)
            except ValueError as exc:
                _cli().report(PROG, f"unwrap failed for {name}: {exc}")
                return 1
            dest_name = name[: -len(".zlib")]
        dest = out_dir / Path(dest_name).name
        dest.write_bytes(data)
        print(f"{dest} ({len(data)}B)")
    return 0


def _default_artifact(entry: dict[str, Any], artifact: str | None) -> str:
    if artifact:
        return artifact
    names = _pick_artifacts(entry, prefer_zlib=True, aot_only=False, wasm_only=False)
    if not names:
        raise ValueError("no artifacts on package")
    return names[0]


def cmd_inspect(args: argparse.Namespace) -> int:
    client, err_t = _client(args)
    ch, pin = _channel_query(args.channel)
    try:
        entry = client.get_package(args.package, channel=ch)
        filename = _default_artifact(entry, args.artifact)
        data = client.inspect_artifact_remote(filename, version=pin)
    except err_t as exc:
        return _cdn_fail(exc)
    except ValueError as exc:
        _cli().report(PROG, str(exc))
        return 1
    if args.json:
        _print_json(data)
        return 0
    print(f"{args.package}  artifact={filename}  channel={ch}")
    print(
        f"kind={data.get('kind')} encoding={data.get('encoding')} signed={data.get('signed')}"
    )
    pack = data.get("pack") or {}
    if pack:
        print(f"pack {pack.get('name')} v{pack.get('version')}")
        for f in pack.get("files") or []:
            print(f"  pack/{f.get('path')}")
    source = data.get("source") or {}
    if source:
        print(f"source {source.get('name')} {source.get('pkg_version') or ''}".rstrip())
        for f in source.get("files") or []:
            print(f"  src/{f.get('path')}")
    if data.get("sig"):
        s = data["sig"]
        print(f"sig format={s.get('format')} len={s.get('sig_len')}")
    if data.get("has_dwarf") is not None:
        print(f"has_dwarf={data.get('has_dwarf')}")
    syms = data.get("symbols") or []
    if syms:
        print(f"symbols ({len(syms)}):")
        for s in syms[:24]:
            print(
                f"  {s.get('kind', '?'):6} +0x{int(s.get('offset') or 0):04x} "
                f"sz={s.get('size', 0)}  {s.get('name')}"
            )
        if len(syms) > 24:
            print(f"  … +{len(syms) - 24} more")
    else:
        # Aggregate inspect may omit symbols; hit /symbols when available.
        try:
            remote = client.list_symbols_remote(filename, version=pin)
        except Exception:
            remote = []
        if remote:
            print(f"symbols ({len(remote)}):")
            for s in remote[:24]:
                print(
                    f"  {s.get('kind', '?'):6} +0x{int(s.get('offset') or 0):04x} "
                    f"sz={s.get('size', 0)}  {s.get('name')}"
                )
    return 0


def cmd_files(args: argparse.Namespace) -> int:
    client, err_t = _client(args)
    ch, pin = _channel_query(args.channel)
    try:
        entry = client.get_package(args.package, channel=ch)
        filename = _default_artifact(entry, args.artifact)
        data = client.inspect_artifact_remote(filename, version=pin)
    except err_t as exc:
        return _cdn_fail(exc)
    except ValueError as exc:
        _cli().report(PROG, str(exc))
        return 1
    rows: list[str] = []
    pack = data.get("pack") or {}
    for f in pack.get("files") or []:
        rows.append(f"pack\t{f.get('path')}")
    source = data.get("source") or {}
    for f in source.get("files") or []:
        rows.append(f"source\t{f.get('path')}")
    if args.json:
        _print_json({"artifact": filename, "files": rows})
        return 0
    for row in rows:
        print(row)
    return 0


def cmd_cat(args: argparse.Namespace) -> int:
    client, err_t = _client(args)
    ch, pin = _channel_query(args.channel)
    try:
        entry = client.get_package(args.package, channel=ch)
        filename = _default_artifact(entry, args.artifact)
        view = client.get_embedded_file(filename, args.path, version=pin)
    except err_t as exc:
        return _cdn_fail(exc)
    except ValueError as exc:
        _cli().report(PROG, str(exc))
        return 1
    if view.get("binary") or view.get("text") is None:
        _cli().report(
            PROG,
            f"binary embedded file ({view.get('size', '?')} B)",
            "Use: wasmmod cdn hex … or wasmmod cdn extract … -o …",
        )
        return 1
    sys.stdout.write(str(view["text"]))
    if not str(view["text"]).endswith("\n"):
        sys.stdout.write("\n")
    return 0


def cmd_hex(args: argparse.Namespace) -> int:
    client, err_t = _client(args)
    ch, pin = _channel_query(args.channel)
    try:
        entry = client.get_package(args.package, channel=ch)
        filename = _default_artifact(entry, args.artifact)
        body = client.download_embedded_file(filename, args.path, version=pin)
    except err_t as exc:
        return _cdn_fail(exc)
    except ValueError as exc:
        _cli().report(PROG, str(exc))
        return 1
    color = sys.stdout.isatty() and not args.no_color
    print(_cli().local_hexdump(body, limit=args.limit, color=color))
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    client, err_t = _client(args)
    ch, pin = _channel_query(args.channel)
    out_dir = Path(args.out)
    try:
        entry = client.get_package(args.package, channel=ch)
        filename = _default_artifact(entry, args.artifact)
        data = client.inspect_artifact_remote(filename, version=pin)
    except err_t as exc:
        return _cdn_fail(exc)
    except ValueError as exc:
        _cli().report(PROG, str(exc))
        return 1

    paths: list[str] = []
    section = args.section
    if section in ("source", "all"):
        source = data.get("source") or {}
        paths.extend(str(f.get("path")) for f in (source.get("files") or []) if f.get("path"))
    if section in ("pack", "all"):
        pack = data.get("pack") or {}
        for f in pack.get("files") or []:
            p = f.get("path")
            if p and str(p) not in paths:
                paths.append(str(p))

    if not paths:
        _cli().report(PROG, "no embedded paths to extract")
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)
    for rel in paths:
        try:
            body = client.download_embedded_file(filename, rel, version=pin)
        except err_t as exc:
            return _cli().report_client(exc, prog=PROG, extra_hints=[f"path={rel}"])
        dest = out_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
        print(f"{dest} ({len(body)}B)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--cdn-url", default=os.environ.get("METAL_CDN_URL"))
    ap.add_argument("--token", default=os.environ.get("METAL_CDN_TOKEN"))
    ap.add_argument(
        "--channel",
        default="lead",
        help="lead, @0.1.0, or bare pin version (default: lead)",
    )
    ap.add_argument("--json", action="store_true", help="Machine-readable output")

    sub = ap.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="List packages on the channel (pip list / index)")
    p_list.set_defaults(func=cmd_list)

    p_search = sub.add_parser("search", help="Search package names/descriptions")
    p_search.add_argument("query")
    p_search.set_defaults(func=cmd_search)

    p_show = sub.add_parser("show", help="Show package metadata + artifacts (pip show)")
    p_show.add_argument("package")
    p_show.set_defaults(func=cmd_show)

    p_index = sub.add_parser("index", help="Dump device index.json for the channel")
    p_index.set_defaults(func=cmd_index)

    p_closure = sub.add_parser("closure", help="Dependency install order for a package")
    p_closure.add_argument("package")
    p_closure.set_defaults(func=cmd_closure)

    p_get = sub.add_parser("get", help="Download package artifacts (pip download)")
    p_get.add_argument("package")
    p_get.add_argument("-o", "--out", default="packs", help="Output directory")
    p_get.add_argument("--artifact", help="Download a single filename only")
    p_get.add_argument("--aot-only", action="store_true")
    p_get.add_argument("--wasm-only", action="store_true")
    p_get.add_argument(
        "--raw",
        action="store_true",
        help="Include naked artifacts even when .zlib twins exist",
    )
    p_get.add_argument(
        "--unwrap",
        action="store_true",
        help="Unwrap MPZL .zlib to naked .wasm/.aot/.elf on disk",
    )
    p_get.set_defaults(func=cmd_get)

    p_inspect = sub.add_parser("inspect", help="Inspect a remote package artifact")
    p_inspect.add_argument("package")
    p_inspect.add_argument("--artifact", help="Artifact filename (default: first zlib/wasm)")
    p_inspect.set_defaults(func=cmd_inspect)

    p_files = sub.add_parser("files", help="List embedded pack/source paths")
    p_files.add_argument("package")
    p_files.add_argument("--artifact", help="Artifact filename")
    p_files.set_defaults(func=cmd_files)

    p_cat = sub.add_parser("cat", help="Print an embedded text file")
    p_cat.add_argument("package")
    p_cat.add_argument("path", help="Embedded relative path")
    p_cat.add_argument("--artifact", help="Artifact filename")
    p_cat.set_defaults(func=cmd_cat)

    p_hex = sub.add_parser("hex", help="Hex-dump an embedded file")
    p_hex.add_argument("package")
    p_hex.add_argument("path", help="Embedded relative path")
    p_hex.add_argument("--artifact", help="Artifact filename")
    p_hex.add_argument("--limit", type=int, default=4096)
    p_hex.add_argument("--no-color", action="store_true")
    p_hex.set_defaults(func=cmd_hex)

    p_extract = sub.add_parser("extract", help="Extract embedded files to a directory")
    p_extract.add_argument("package")
    p_extract.add_argument("-o", "--out", default="extracted", help="Output directory")
    p_extract.add_argument("--artifact", help="Artifact filename")
    p_extract.add_argument(
        "--section",
        choices=("source", "pack", "all"),
        default="all",
        help="Which embedded tree to pull (default: all)",
    )
    p_extract.set_defaults(func=cmd_extract)

    args = ap.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(_cli().invoke(main, prog=PROG))
