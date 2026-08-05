"""Unit tests for wasmmod cdn artifact picking (no network)."""

from __future__ import annotations

from pymergetic.wasmmod.tools import cdn as mod


def test_pick_prefers_zlib() -> None:
    entry = {
        "artifacts": [
            {"path": "hello.wasm", "kind": "wasm", "encoding": "raw"},
            {"path": "hello.wasm.zlib", "kind": "wasm", "encoding": "mpzl"},
            {"path": "hello.aot6", "kind": "aot", "encoding": "raw"},
            {"path": "hello.aot6.zlib", "kind": "aot", "encoding": "mpzl"},
        ]
    }
    names = mod._pick_artifacts(entry, prefer_zlib=True, aot_only=False, wasm_only=False)
    assert names == ["hello.wasm.zlib", "hello.aot6.zlib"]


def test_pick_aot_only_raw() -> None:
    entry = {
        "artifacts": [
            {"path": "hello.wasm.zlib"},
            {"path": "hello.aot6"},
            {"path": "hello.aot6.zlib"},
        ]
    }
    names = mod._pick_artifacts(entry, prefer_zlib=False, aot_only=True, wasm_only=False)
    assert names == ["hello.aot6", "hello.aot6.zlib"]
