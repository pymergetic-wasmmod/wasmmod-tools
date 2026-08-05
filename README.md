# wasmmod-tools

Host-side tooling for [wasmmod](https://github.com/pymergetic/wasmmod): ELF helpers
and pack inspect (shared with [metal-cdn](https://github.com/pymergetic/metal-cdn)).

PyPI: **`pymergetic-wasmmod-tools`** · import: **`pymergetic.wasmmod.tools`**

```sh
pip install pymergetic-wasmmod-tools
python -c "from pymergetic.wasmmod.tools import elf, inspect"
wasmmod-inspect --help
```

PEP 420 layout: `pymergetic` / `wasmmod` are namespace packages; `tools` is the leaf.

## Release (Trusted Publishing)

| Field | Value |
|-------|--------|
| PyPI Project Name | `pymergetic-wasmmod-tools` |
| Owner | `pymergetic` |
| Repository | `wasmmod-tools` |
| Workflow name | `publish-pypi-tools.yml` |
| Environment | *(empty / any)* |

```sh
git tag -a v0.1.0a1 -m "v0.1.0a1"
git push origin main && git push origin v0.1.0a1
```
