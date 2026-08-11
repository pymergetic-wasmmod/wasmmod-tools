"""Shared CLI error helpers for wasmmod host tools.

  from .cliutil import die, die_client, invoke

  def main() -> int:
      die("wasmmod publish", "missing key", "Create with: …")

  if __name__ == "__main__":
      raise SystemExit(invoke(main, prog="wasmmod publish"))
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable
from typing import Any, NoReturn

# Bump when wasmmod starts requiring a newer client symbol/contract.
CLIENT_MIN_VERSION = "0.1.0a3"


def _cdn_errors():
    try:
        from pymergetic.wasmmod.cdn_client import errors as err
    except ImportError:
        return None
    return err


def format_error(prog: str, message: str, *hints: str) -> str:
    err = _cdn_errors()
    if err is not None:
        return err.format_error(prog, message, *hints)
    lines = [f"{prog}: {message}"]
    for hint in hints:
        if hint:
            lines.append(f"  {hint}")
    return "\n".join(lines)


def report(prog: str, message: str, *hints: str) -> None:
    print(format_error(prog, message, *hints), file=sys.stderr)


def die(prog: str, message: str, *hints: str) -> NoReturn:
    raise SystemExit(format_error(prog, message, *hints))


def _parse_version(value: str) -> tuple[int, ...]:
    """Best-effort PEP 440-ish compare for a.b.c[aN|bN|rcN]."""
    base = value.split("+", 1)[0].split(".dev", 1)[0]
    m = re.match(
        r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:(a|b|rc)(\d+))?$",
        base,
        re.IGNORECASE,
    )
    if not m:
        return (0,)
    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    pre_tag = (m.group(4) or "").lower()
    pre_n = int(m.group(5) or 0)
    # Final releases sort after pre: a=1, b=2, rc=3, final=99
    pre_rank = {"a": 1, "b": 2, "rc": 3}.get(pre_tag, 99)
    return (major, minor, patch, pre_rank, pre_n if pre_tag else 0)


def client_version_ok(installed: str, minimum: str = CLIENT_MIN_VERSION) -> bool:
    if os.environ.get("WASMMOD_SKIP_CLIENT_VERSION") == "1":
        return True
    if installed.endswith("+unknown"):
        return True
    return _parse_version(installed) >= _parse_version(minimum)


def require_cdn_client(prog: str) -> Any:
    """Import ``pymergetic.wasmmod.cdn_client`` or die with install / upgrade hints."""
    try:
        from pymergetic.wasmmod import cdn_client
    except ImportError:
        die(
            prog,
            "install pymergetic-wasmmod-cdn-client",
            "pip install -r requirements-publish.txt",
        )
    ver = getattr(cdn_client, "__version__", "0.0.0+unknown")
    if not client_version_ok(ver):
        die(
            prog,
            f"pymergetic-wasmmod-cdn-client {ver} is too old (need >={CLIENT_MIN_VERSION})",
            f"pip install -U 'pymergetic-wasmmod-cdn-client>={CLIENT_MIN_VERSION}'",
        )
    return cdn_client


def warn_experimental(client: Any, *, prog: str) -> None:
    """Best-effort check of CDN ``GET /status`` experimental flag."""
    try:
        status = client.status()
    except Exception:
        return
    if not isinstance(status, dict) or not status.get("experimental"):
        return
    msg = status.get("experimental_message") or (
        "Experimental CDN: data may be wiped before go-live — not for production."
    )
    report(prog, msg, "Server flag WASMMOD_CDN_EXPERIMENTAL (set false after go-live)")


def local_hexdump(
    data: bytes, *, width: int = 16, limit: int | None = 4096, color: bool = False
) -> str:
    """Prefer ``cdn_client.format.hexdump``; tiny offline fallback otherwise."""
    try:
        from pymergetic.wasmmod.cdn_client.format import hexdump

        return hexdump(data, width=width, limit=limit, color=color)
    except ImportError:
        blob = data if limit is None else data[:limit]
        lines: list[str] = []
        for i in range(0, len(blob), width):
            chunk = blob[i : i + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08x}  {hex_part}  |{ascii_part}|")
        if limit is not None and len(data) > limit:
            lines.append(f"… showing {limit} of {len(data)} bytes")
        return "\n".join(lines)


def report_client(
    exc: BaseException,
    *,
    prog: str,
    force: bool = False,
    extra_hints: list[str] | None = None,
) -> int:
    err = _cdn_errors()
    if err is not None and isinstance(exc, err.ClientError):
        return err.report_client_error(
            exc, prog=prog, force=force, extra_hints=extra_hints
        )
    report(prog, str(exc), *(extra_hints or ()))
    return 1


def die_client(
    exc: BaseException,
    *,
    prog: str,
    force: bool = False,
    extra_hints: list[str] | None = None,
) -> NoReturn:
    err = _cdn_errors()
    if err is not None and isinstance(exc, err.ClientError):
        err.die_client(exc, prog=prog, force=force, extra_hints=extra_hints)
    die(prog, str(exc), *(extra_hints or []))


def invoke(main_fn: Callable[[], Any], *, prog: str = "wasmmod") -> int:
    err = _cdn_errors()
    if err is not None:
        return err.invoke(main_fn, prog=prog)

    try:
        return int(main_fn())
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        if code:
            print(str(code), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        report(prog, "interrupted")
        return 130
    except Exception as exc:
        report(
            prog,
            f"unexpected error: {exc}",
            "Set WASMMOD_DEBUG=1 for a traceback",
        )
        return 1
