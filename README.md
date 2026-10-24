# Wasm decompiler for IDA 9.0+

An independent IDAPython decompiler for WebAssembly. Open a `.wasm` using IDA's
built-in loader, place the cursor inside a function, and press **Tab**.
The plugin displays C-like pseudocode with instruction navigation, function and
local renaming, conservative stack recovery, and export.

No Hex-Rays decompiler, Ghidra installation, native SDK, or Python dependencies
are needed. Python 3.9+ and IDA Pro's built-in `wasm` processor are required.
The core and CLI also run without IDA. This remains a custom pseudocode viewer,
**not a native Hex-Rays backend**: `ida_hexrays.decompile()` does not support Wasm
through this plugin, and no text proxy is substituted for `cfunc_t`. See the
[investigated native API limitation](docs/NATIVE_INTEGRATION.md).

## Install

Extract `dist/ida-wasm-decompiler-0.3.0.zip` into IDA's **user plugins** directory,
with this layout (all support files stay inside the package):

```text
plugins/
├── ida_wasm_decompiler.py
└── wasm_decompiler/
    ├── __init__.py
    ├── ... other Python modules ...
    ├── LICENSE
    ├── README.md
    ├── THIRD_PARTY.md
    └── docs/
```

Typical
locations are `~/.idapro/plugins` on Linux/macOS and `%APPDATA%\Hex-Rays\IDA Pro\plugins`
on Windows. Use `ida_diskio.get_user_idadir()` in IDA's Python console to find
the actual user directory, then append `plugins`. Restart IDA.

Alternatively, copy the entry-point file and package directory directly from
this repository. Do not install the repository as a processor or loader module.
To uninstall, remove those two entries and restart IDA.

## Use

- **Tab**: toggle between Wasm disassembly and the current function's pseudocode.
  This binding applies only to Wasm disassembly and the plugin's own view; other
  architectures, the Python console, and other IDA widgets keep their bindings.
- **Enter** or **double-click** a function name: decompile it in the **same viewer**.
- **Escape / Alt-Left**: return to the caller, restoring the cursor. **Alt-Right**
  moves forward. With no history, Escape returns to disassembly.
- **Edit → Plugins → Wasm decompiler** also opens the current function.
- **G**: open IDA's **Go to address or symbol** dialog. A code destination opens
  its containing function's pseudocode; a data address opens the IDA data view.
- **X**: cross-references to the function/global under the cursor, using IDA's xref
  chooser. Selecting a code reference opens its caller in pseudocode. For local
  variables, show their uses within this function.
- **J**: jump to the current line's underlying Wasm instruction in disassembly.
- **N**: rename the function, global or local under the cursor. Function/global
  renames update IDA; local names are stored in the database.
- **R**: refresh after database edits. Patches and renames invalidate the analysis
  cache; existing views update on refresh or reopening.
- **E**: export the current function. The viewer context menu also offers whole-module
  export and a C stack-pointer global override (`auto` restores detection).

Globals live in a typed `.wasm_globals` analysis segment with real IDA read/write
references. This segment models runtime globals; it is not Wasm linear memory or
the file's encoded initializer section. If IDA already owns a `global_N` name,
the new identity uses `wasm_global_N`; use the name shown in the pseudocode. You can query these references with normal
IDAPython APIs:

```python
import ida_idaapi, ida_name, idautils
ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "global_0")
refs = list(idautils.XrefsTo(ea))
```

Cancellation is available through IDA's wait box. Failed functions show diagnostics
and do not prevent other functions from being exported. Imported functions have
signatures but no bodies.

The original module is compressed into a private database netnode on first use,
so reopening the database does not require the original file. If it is unavailable
before first use, select a matching original file; its SHA-256 must match IDA's
record. Module metadata and locals must remain structurally unchanged. Instruction
patches are read from IDA and revalidated; rebuild/reload a module to change its layout.

## Supported features and limits

- All WebAssembly 1.0 scalar instructions: integers, floats, conversions, memory,
  globals, direct and indirect calls, structured branches, and tables.
- Sign-extension and saturating float-to-integer instructions.
- Bulk operations: `memory.init`, `data.drop`, `memory.copy`, `memory.fill`,
  `table.init`, `elem.drop`, and `table.copy`, with legacy function-index elements.
- Function/parameter/local names, imports/exports, data/element segment metadata,
  signatures, start functions, source offsets, and deterministic fallback names.
- Constant indirect calls resolve only for private, unimported, unexported tables
  with statically known elements and no table-modifying instructions anywhere in
  the module. Uncertain calls retain explicit type and table checks.
- Stack recovery recognizes balanced, straight-line fixed frames in mutable i32
  globals. Named stack locals remain **memory-backed aliases**, preserving memory
  effects and traps. Branching frames, calls, escaping frame pointers, packed or
  overlapping accesses retain explicit memory operations.

Multi-value/type-index block signatures, general reference instructions, SIMD,
atomics/threads, exceptions, tail calls, memory64, multiple memories/tables, GC,
and component modules produce explicit unsupported diagnostics. Unknown instruction
encodings stop that function; unsupported module-level types stop module parsing.
The reader limits modules to 64 MiB, vectors to one million entries, locals to
100,000 per function, and instructions to one million per function.

Output defaults to **C-oriented pseudocode**: casts, arithmetic, typed memory
accesses, ordinary loops, `continue`, and switch cases with their bodies attached.
Control-flow-aware optimization removes dead writes, unused locals and temporary
copies. Complex multi-level exits retain labels; unavailable source types and
function names are not invented.

For example, the core fixture's factorial decompiles as:

```c
uint32_t factorial(uint32_t n) {
    uint32_t acc;
    acc = 1;
    while (n) {
        acc = acc * n;
        n = n - 1;
    }
    return acc;
}
```

This is **inspection pseudocode**, not a standalone native C program. Pointer
notation refers to checked, little-endian Wasm linear memory. Integer operations
retain their Wasm widths, wrapping and traps even when displayed using C operators.
Exceptional operations (e.g. checked float truncations and indirect calls) retain
explicit intrinsics. See [presentation and helper semantics](docs/HELPERS.md).
Use `--explicit-wasm` or `Options(c_style=False)` for the explicit semantic form.
Native C aggregate types and original-source recovery are outside this release.

## Standalone CLI and Python API

```sh
python3 -m wasm_decompiler samples/core.wasm
python3 -m wasm_decompiler samples/core.wasm -f 1 -o factorial.c
python3 -m wasm_decompiler samples/core.wasm --json -o analysis.json
python3 -m wasm_decompiler input.wasm --stack-pointer 0 --no-optimize
python3 -m wasm_decompiler input.wasm --explicit-wasm
```

An optional `pip install .` installs the `wasm-decompile` CLI. It does not install
into IDA. Exit status is nonzero for invalid/unsupported functions; JSON results
include individual diagnostics, line-to-file-offset mappings, and symbol references.

```python
from wasm_decompiler import parse_module, decompile_function, Options
module = parse_module(open("input.wasm", "rb").read())
result = decompile_function(module, 0, Options())  # indices include imports
print(result.text)
print(result.source_map, result.diagnostics)
```

`decompile_function` also accepts function-name overrides, local-name overrides,
and a cancellation callback. `decompile_module` isolates per-function failures;
`export_text` emits module prototypes, globals, and the requested results.

## Validation

Development tests require pytest, WABT (`wat2wasm`, `wasm-interp`), and a C compiler:

```sh
python3 -m pytest -q
python3 tools/validate_ida.py --ida-dir /home/kali/ida-pro-9.0 --gui
python3 tools/validate_ida.py --gui samples/navigation.wasm
python3 tools/validate_ida.py --gui samples/public/mdn-wasm-sobel-change.wasm
python3 tools/check_sdk_compat.py
python3 tools/package_plugin.py
```

See [validation details](docs/VALIDATION.md) for tested environments and remaining
compatibility limits. Downloaded sample versions, hashes, and retrieval instructions
are in the repository's `samples/` directory. Reference projects and sample licenses are
listed in [THIRD_PARTY.md](THIRD_PARTY.md).
