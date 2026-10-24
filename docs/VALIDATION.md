# Validation

Verified locally on Linux with IDA Pro **9.0**, its built-in Wasm loader/processor,
IDAPython, WABT and a C compiler. Windows/macOS and newer IDA releases use the
same Python APIs but have not been exercised here.

## Automated core checks

Run `python3 -m pytest -q` with pytest and WABT installed. Tests cover:

- Every scalar numeric opcode, including conversions, sign-extension and
  saturating truncation, and every MVP memory instruction.
- Structured blocks, nested if/else, loops, branch tables, function-label branches,
  branch-carried stack values and polymorphic unreachable code.
- Globals, imports, calls, conservative table target resolution and invalidation
  of inferred constant indices across calls that may change globals.
- Side-effect ordering, eager selection, local snapshots, scalar memory access,
  and conservative named stack slots.
- Invalid signed/unsigned LEB128, bounds, truncated sections, type mismatches,
  unsupported features, cancellation, naming and expression-depth limits.
- All six pinned public Wasm files; all their functions decompile successfully.

Execution tests compile rendered pseudocode with a **limited test-only helper
harness** and compare it to `wasm-interp`. Both C-style and explicit output are checked with optimization on and off: 166
numeric/float-bit cases, 42 control-flow/call/memory cases, and one recovered stack
frame per combination, plus six effect-order checks and 24 nested-loop checks:
**866 result comparisons**. These comparisons verify
selected behaviors, not full runtime equivalence for every helper. Numeric opcode
coverage tests otherwise validate decoding, typing and rendering.

## Real IDA checks

```sh
python3 tools/validate_ida.py --gui samples/core.wasm \
  samples/public/mdn-wasm-sobel-change.wasm
```

This runs IDA's GUI with Qt's offscreen platform in temporary databases, then
reopens each saved database in a fresh headless IDA process. Checks cover:

- Registered actions and plugin loading through IDA's actual plugin loader; the plugin does not replace `ida_hexrays.decompile`.
- Every function's file-offset/database-address mapping and pseudocode source map.
- Database function renames, instruction patches and restoration, and rejection
  of structural metadata patches.
- Viewer creation, refresh, disassembly navigation, local renaming, module export,
  closing and reopening, action/hook cleanup.
- Actual Qt Tab key events in both directions, scoped to Wasm views; Enter and
  double-click call following using actual identifier columns (no mocked
  `GetCurrentWord`); Escape/Alt-Left cursor restoration.
- Go to address using IDA's dialog API, function source positioning, typed global
  database identities, kernel read/write xrefs, xref chooser routing, global renames,
  patch re-indexing, and preservation of unrelated user xrefs.
- Original-module and local-name persistence after database reopening.

Dialog inputs are supplied programmatically for repeatability. Offscreen GUI
checks exercise real widgets and API calls; they do not replace manual checks of
appearance, mouse hit-testing, operating-system shortcuts, or platform-specific
window behavior.

## Known limits

Natural loops and branch-table destinations are restructured into C loops,
`continue`, and switch bodies. Complex multi-level exits retain labeled branches.
Stack recovery handles straight-line frames and leaves uncertain cases explicit.
No native type/aggregate recovery or recompilable output guarantee is provided.
Unsupported modern Wasm features are documented in the README and diagnosed.

## Large user-supplied sample

The provided `crux/extension/main.wasm` is 5,836,781 bytes with 3,275 functions
(including 20 imports). Representative functions and the two largest function
bodies were decompiled without errors. The largest two bodies produce tens of
thousands of lines and can take tens of seconds each; full-module decompilation
has not been claimed. The input is not redistributed.

Reproduce targeted GUI checks with:

```sh
python3 tools/validate_ida.py --gui --timeout 600 \
  --functions 20,361,1393,1394,1395 --follow 1393:1387 /path/to/main.wasm
python3 tools/validate_sample.py /path/to/main.wasm \
  --functions 20,21,22,50,100,275,361,1331,1387,1393,1394,1395
```

`validate_sample.py` writes reviewable function output and a SHA-256-tagged JSON
report in `dist/sample-review/`. The source file is never modified.

## Native SDK boundary and newer IDA versions

[Native integration findings](NATIVE_INTEGRATION.md) distinguish the custom viewer
from genuine Hex-Rays API support and record the supported native-control test.
`tools/check_sdk_compat.py` checks the public APIs used by this plugin against
9.2/9.3/9.4 official SDK snapshots. Only IDA 9.0 is available for runtime validation
here; later-version source checks do not replace their runtime integration tests.
