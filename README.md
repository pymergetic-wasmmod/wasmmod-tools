# wasmmod-tools

Host-side tooling for [wasmmod](https://github.com/pymergetic-wasmmod/wasmmod): pack, sign,
ELF helpers, inspect, publish, CDN CLI.

PyPI: **`pymergetic-wasmmod-tools`** · import: **`pymergetic.wasmmod.tools`**

| Component | Role | Repo |
|-----------|------|------|
| wasmmod | Runtime + pack tree (`pymergetic-wasmmod`) | [pymergetic-wasmmod/wasmmod](https://github.com/pymergetic-wasmmod/wasmmod) · `main` |
| **wasmmod-tools** | **This repo** — host CLI | [pymergetic-wasmmod/wasmmod-tools](https://github.com/pymergetic-wasmmod/wasmmod-tools) · `main` |
| wasmmod-test | External pack/CDN consumer sample | [pymergetic-wasmmod/wasmmod-test](https://github.com/pymergetic-wasmmod/wasmmod-test) · `main` |
| wasmmod-cdn | CDN server + client | [pymergetic-wasmmod/wasmmod-cdn](https://github.com/pymergetic-wasmmod/wasmmod-cdn) · `main` |
| metalpython | Metal product µPy — rebuilt on the wasmmod engine | [pymergetic/metalpython](https://github.com/pymergetic/metalpython) · `main` |

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
