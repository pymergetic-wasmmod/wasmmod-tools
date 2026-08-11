
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
face-export-discovery, v1: **C only**.

Regex-scans ``__impl__.c`` files for ``PM_MOD_EXPORT_C(module, export_name,
impl_fn, c_type_signature)`` call sites (see ``src/pymergetic/wasmmod/guest.h`` for the
macro itself — currently a declarative no-op, real slot-backed registration
is the separate, later ``pm-mod-export-macro`` work).

``PM_MOD_EXPORT_RS`` / Rust discovery is explicitly out of scope this pass
(no Rust example is being converted yet).
"""

from __future__ import annotations

import re
from pathlib import Path

_CALL_PREFIX_RE = re.compile(
    r"PM_MOD_EXPORT_C\s*\(\s*"
    r"([A-Za-z_][\w.]*)\s*,\s*"  # module
    r"([A-Za-z_]\w*)\s*,\s*"  # export_name
    r"([A-Za-z_]\w*)\s*,",  # impl_fn
)

# C type → is it representable as a Wasm i32 in the compact legacy sig tag?
# (Anything not in this table — floats, 64-bit ints, structs by value, …
# falls back to SIG_AUTO via manifest_to_build()'s own sig_tag(), which is
# exactly what "no sig" (None) already means to it.)
_I32_LIKE_TYPES = {
    "void*",
    "int",
    "unsignedint",
    "unsigned",
    "int32_t",
    "uint32_t",
    "char",
    "unsignedchar",
    "short",
    "unsignedshort",
    "long",  # wasm32: 32-bit
    "unsignedlong",
    "bool",
    "size_t",
}


def _normalize_type(t: str) -> tuple[str, bool]:
    """Strip cv-qualifiers/whitespace; return (key, is_pointer)."""
    t = t.strip()
    is_pointer = "*" in t
    t = t.replace("*", "")
    for qual in ("const", "volatile", "struct"):
        t = re.sub(rf"\b{qual}\b", "", t)
    t = re.sub(r"\s+", "", t)
    if is_pointer:
        return "void*", True
    return t, False


def _is_i32_like(c_type: str) -> bool:
    key, is_pointer = _normalize_type(c_type)
    if is_pointer:
        return True
    return key in _I32_LIKE_TYPES


def _split_top_level_commas(s: str) -> list[str]:
    out: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(s):
        if ch in "([<":
            depth += 1
        elif ch in ")]>":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return out


def parse_c_signature(sig_text: str) -> str | None:
    """``int(void)`` / ``int(int, int)`` → compact legacy sig string
    (``i32``, ``i32_i32_i32``, …) if every param + the result is i32-like,
    else ``None`` (caller omits ``sig`` → manifest_to_build's own
    ``sig_tag()`` falls back to ``SIG_AUTO``, which is always correct, just
    not compact)."""
    m = re.match(r"^(.+)\(([^()]*)\)\s*$", sig_text.strip())
    if not m:
        return None
    ret_type, args_text = m.group(1).strip(), m.group(2).strip()

    args_text_norm = args_text.replace(" ", "")
    if args_text_norm in ("", "void"):
        params: list[str] = []
    else:
        params = [p for p in _split_top_level_commas(args_text) if p.strip()]

    ret_ok = ret_type.replace(" ", "") == "void" or _is_i32_like(ret_type)
    if not ret_ok:
        return None
    if any(not _is_i32_like(p) for p in params):
        return None

    n_result_tokens = 0 if ret_type.replace(" ", "") == "void" else 1
    total = len(params) + n_result_tokens
    if total == 0:
        # A void(void) export has no numeric-shape sig at all; leave it to
        # SIG_AUTO (the loader introspects the real, empty Wasm type).
        return None
    return "_".join(["i32"] * total)


def scan_c_exports(c_files: list[Path]) -> list[tuple[str, str, str, str | None]]:
    """Scan ``__impl__.c`` files for ``PM_MOD_EXPORT_C`` call sites.

    Returns ``[(module, export_name, impl_fn, sig_or_None), …]``.
    """
    out: list[tuple[str, str, str, str | None]] = []
    for path in c_files:
        text = path.read_text()
        for m in _CALL_PREFIX_RE.finditer(text):
            module, export_name, impl_fn = m.group(1), m.group(2), m.group(3)
            i = m.end()
            depth = 1
            sig_start = i
            n = len(text)
            while i < n and depth > 0:
                if text[i] == "(":
                    depth += 1
                elif text[i] == ")":
                    depth -= 1
                i += 1
            if depth != 0:
                raise SystemExit(
                    f"wasm_pack: {path}: unterminated PM_MOD_EXPORT_C(...) call "
                    f"(module={module!r})"
                )
            sig_text = text[sig_start : i - 1].strip()
            sig = parse_c_signature(sig_text)
            out.append((module, export_name, impl_fn, sig))
    return out
