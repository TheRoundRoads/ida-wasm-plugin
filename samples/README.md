# Samples

`core.wat` is an original fixture for arithmetic, loops, block results, branching,
memory, selection, direct calls and names. Regenerate its binary with:

```sh
wat2wasm --debug-names samples/core.wat -o samples/core.wasm
```

Six public binaries are pinned in `public/manifest.json` from MDN's
[webassembly-examples](https://github.com/mdn/webassembly-examples) repository.
They exercise imports, globals, memory, tables, names, and a larger
Emscripten-generated Sobel image-processing module. The Sobel file contains 48
functions (including 15 imports) in 14,139 bytes. The source repository license is
retained in `public/mdn-LICENSE` (CC0-1.0).

Fetch the exact versions again and verify their hashes with:

```sh
python3 tools/fetch_samples.py
```

Only generated test modules are executed for behavioral comparison. Public
samples are used for static decompilation and IDA integration tests.

`navigation.wat` / `navigation.wasm` cover punctuation-adjacent call names and
runtime-global read/write cross-references. Regenerate with:

```sh
wat2wasm --debug-names samples/navigation.wat -o samples/navigation.wasm
```
