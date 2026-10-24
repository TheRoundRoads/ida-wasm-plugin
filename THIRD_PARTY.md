# References and third-party material

The plugin implementation is original Python code under the repository's MIT
license. No Ghidra Java/SLEIGH source or Hex-Rays SDK source is bundled or ported.

Architectural and semantic references:

- [nneonneo/ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin/):
  repository licensed GPL-3.0; consulted its README and WasmFunctionAnalysis
  source to understand typed stack analysis and virtual-register approaches.
- [WebAssembly core specification](https://webassembly.github.io/spec/core/):
  binary format, validation, instruction semantics, and control-stack behavior.
- [Hex-Rays IDAPython documentation](https://python.docs.hex-rays.com/):
  plugin actions, custom viewers, database hooks, file-region mapping and netnodes.
  The locally installed IDA 9.0 Python API documentation/examples were also consulted.
- [WebAssembly/wabt](https://github.com/WebAssembly/wabt): Apache-2.0;
  external development/test tools, not redistributed with the plugin.

Public test binaries in `samples/public/` come from
[mdn/webassembly-examples](https://github.com/mdn/webassembly-examples), pinned at
commit `49a0e4ce800c64f5365e56745b53163bc252c25a`. That repository's CC0-1.0 license
is retained verbatim as `samples/public/mdn-LICENSE`. URLs and SHA-256 digests are
recorded in `samples/public/manifest.json`. These binaries are not in the plugin
installation archive. They are only parsed/decompiled by default; no host imports
from downloaded samples are executed by the tests.

`samples/core.wat` and the generated testing fixtures are original project material
under MIT. `samples/core.wasm` is built from that WAT using WABT with debug names.
