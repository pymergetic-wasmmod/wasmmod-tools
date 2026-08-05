# wasmmod-tools

Host-side tooling for [wasmmod](https://github.com/pymergetic/wasmmod): pack, sign,
ELF helpers, inspect, publish, CDN CLI.

PyPI: **`pymergetic-wasmmod-tools`** · import: **`pymergetic.wasmmod.tools`**

| Component | Role | Repo |
|-----------|------|------|
| wasmmod | Runtime + pack tree (`pymergetic-wasmmod`) | [pymergetic/wasmmod](https://github.com/pymergetic/wasmmod) · `main` |
| **wasmmod-tools** | **This repo** — host CLI | [pymergetic/wasmmod-tools](https://github.com/pymergetic/wasmmod-tools) · `main` |
| wasmmod-test | External pack/CDN consumer sample | [pymergetic/wasmmod-test](https://github.com/pymergetic/wasmmod-test) · `main` |
| metal-cdn | CDN server + client | [pymergetic/metal-cdn](https://github.com/pymergetic/metal-cdn) · `main` |
| metalpython `wasmmod` | Clean upy host + submodule (upstream-shaped) | [metalpython/tree/wasmmod](https://github.com/pymergetic/metalpython/tree/wasmmod) |
| metalpython `master` | Metal product µPy; **base = `wasmmod` tip** | [metalpython/tree/master](https://github.com/pymergetic/metalpython/tree/master) |

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
