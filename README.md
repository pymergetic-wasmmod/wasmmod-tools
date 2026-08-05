# wasmmod-tools

Host-side tooling for [wasmmod](https://github.com/pymergetic/wasmmod): pack, sign,
ELF helpers, inspect, publish, CDN CLI.

PyPI: **`pymergetic-wasmmod-tools`** · import: **`pymergetic.wasmmod.tools`**

```sh
# current releases are alphas — always use --pre
pip install --pre 'pymergetic-wasmmod-tools[cdn,inspect]'
export WASMMOD_ROOT=/path/to/wasmmod   # for pack / read / examples
wasmmod pack examples/hello -o hello.wasm
wasmmod inspect hello.wasm
wasmmod --help
```

Editable (os-sdk):

```sh
pip install -e '../wasmmod-tools[cdn,inspect]'
```

PEP 420: `pymergetic` / `wasmmod` are namespaces; `tools` is the leaf package.

## Trusted Publishing

| Field | Value |
|-------|--------|
| PyPI Project Name | `pymergetic-wasmmod-tools` |
| Owner | `pymergetic` |
| Repository | `wasmmod-tools` |
| Workflow name | `publish-pypi-tools.yml` |
| Environment | *(empty / any)* |
