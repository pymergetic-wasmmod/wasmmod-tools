# wasmmod-tools

Host-side tooling for [wasmmod](https://github.com/pymergetic/wasmmod): pack, sign,
ELF helpers, and external inspect (shared with metal-cdn).

Runtime / MicroPython code stays in wasmmod (`extmod/wasmmod`). This repo is the
shared PyPI surface (`pymergetic-wasmmod-tools`) that metal-cdn and host CLIs
depend on — not a copy of the guest loader.

See os-sdk `packages/wasmmod-tools` (sibling of `metal-cdn` / `metalpython`).
