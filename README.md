# IDA Wasm Decompiler

An IDAPython plugin for **IDA Pro 9.0+** that turns WebAssembly into C-like
pseudocode. It provides function navigation, renaming, Go to address, global
cross-references, and export. A standalone CLI and Python API are also included.

The plugin uses its own pseudocode viewer. It **does not add Wasm support to
`ida_hexrays.decompile()` or return Hex-Rays `cfunc_t` objects**. See the
[native integration findings](docs/NATIVE_INTEGRATION.md) for the tested API boundary.

## Requirements

- IDA Pro 9.0 or newer, with its built-in WebAssembly loader and processor.
- IDAPython with Python 3.9 or newer.

Plugin use requires no additional Python packages, Ghidra installation, native
SDK, or Hex-Rays decompiler. Runtime checks were performed on Linux with IDA 9.0;
selected public APIs were also checked against the official 9.2–9.4 SDKs. Other
platforms and later IDA releases have not been runtime-tested here.

## Installation

### 1. Build the installation archive

```sh
git clone https://github.com/TheRoundRoads/ida-wasm-plugin.git
cd ida-wasm-plugin
python3 tools/package_plugin.py
```

This creates `dist/ida-wasm-decompiler-0.3.0.zip`. The ZIP builder uses only Python's
standard library; generated archives are not committed to the repository. If you
already have the installation ZIP, skip this step. On Windows, use `py` instead
of `python3` if that is your Python launcher.

### 2. Find IDA's user plugins directory

Run this in IDA's Python console:

```python
from pathlib import Path
import ida_diskio
print(Path(ida_diskio.get_user_idadir()) / "plugins")
```

Typical locations are `~/.idapro/plugins` on Linux/macOS and
`%APPDATA%\Hex-Rays\IDA Pro\plugins` on Windows. Use the path printed by IDA if it
differs, and create the `plugins` directory if needed.

### 3. Extract and restart

Close IDA, then extract the **contents** of the ZIP into that plugins directory:

```text
plugins/
├── ida_wasm_decompiler.py
└── wasm_decompiler/
    ├── __init__.py
    ├── ... Python modules ...
    ├── README.md
    ├── LICENSE
    ├── THIRD_PARTY.md
    └── docs/
```

Only the entry-point Python file belongs directly in `plugins/`. Keep the package
and its support files together; do not put an extra repository or ZIP-name folder
around these two entries. Restart IDA after installation or an upgrade.

To upgrade, replace those same entries with the new archive's contents. To
uninstall, remove `ida_wasm_decompiler.py` and `wasm_decompiler/`, then restart IDA.
Settings and analysis already saved in databases remain in those databases.

## Usage

1. Open a `.wasm` file with IDA's built-in WebAssembly loader.
2. Let IDA finish its initial analysis.
3. Place the cursor inside a function and press **Tab**. The plugin can also be
   opened through **Edit → Plugins → Wasm decompiler**.
4. Follow function names with **Enter** or a **double-click**. The same viewer
   displays the callee; **Escape** returns to the caller and restores the cursor.

| Key | Action |
| --- | --- |
| **Tab** | Toggle between disassembly and pseudocode. |
| **Enter / double-click** | Follow a function in the same viewer; follow globals to their database identity. |
| **Escape / Alt-Left** | Go back; Escape returns to disassembly when there is no history. |
| **Alt-Right** | Go forward through pseudocode history. |
| **G** | Open IDA's Go to address/symbol dialog. Code destinations open pseudocode; data destinations open the data view. |
| **X** | Show references to the function/global under the cursor; show in-function uses for a local. |
| **J** | Jump to the current line's underlying Wasm instruction. |
| **N** | Rename the function, global, or local under the cursor. |
| **R** | Refresh after database edits. |
| **E** | Export the current function's pseudocode. |

The viewer's context menu also provides **module export**, refresh, navigation,
and a **C stack pointer** override. Enter a mutable i32 global index for the stack
pointer, or `auto` to restore automatic detection. Tab applies to Wasm disassembly
and this plugin's viewer; other architectures and IDA widgets keep their bindings.

### Globals and cross-references

Runtime globals receive typed database identities in an owned `.wasm_globals`
segment. These are analysis identities, separate from Wasm linear memory and the
file's encoded initializer bytes. If IDA already owns `global_N`, the new identity
uses `wasm_global_N`; use the name displayed in pseudocode.

References are real IDA read/write xrefs and can be queried with normal IDAPython:

```python
import ida_idaapi
import ida_name
import idautils

# Substitute the exact global name displayed in pseudocode.
ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "wasm_global_0")
if ea != ida_idaapi.BADADDR:
    refs = list(idautils.XrefsTo(ea))
```

Function/global renames update IDA names. Local renames and plugin settings are
stored in the database. Instruction patches invalidate analysis and rebuild
plugin-owned references while preserving unrelated user references. Existing
pseudocode views update on refresh or reopening.

### Export and saved databases

Use **E** for one function or the context menu for a module export. Failed
functions include diagnostics without preventing other functions from exporting.
Imported functions have signatures but no bodies. Long operations expose IDA's
cancellation wait box; initial indexing and very large functions may take time.

The original module is cached in a private database netnode on first use. A saved
database can subsequently reopen without the original file. If the original is
missing before first use, select a matching input file when prompted. Structural
changes to module metadata or locals require rebuilding and reloading the module;
instruction-byte patches are read from the IDB and revalidated.

## Standalone use

The CLI runs without IDA, from the repository root:

```sh
python3 -m wasm_decompiler samples/core.wasm
python3 -m wasm_decompiler samples/core.wasm -f 1 -o factorial.c
python3 -m wasm_decompiler samples/core.wasm --json -o analysis.json
python3 -m wasm_decompiler input.wasm --stack-pointer 0
python3 -m wasm_decompiler input.wasm --explicit-wasm --no-optimize
```

`-f` selects a function index **including imported functions**. JSON output includes
source maps, symbol references, and diagnostics. Invalid or unsupported functions
produce a nonzero exit status. An optional `python3 -m pip install .` installs the
`wasm-decompile` command; it does not install the IDA plugin.

```python
from pathlib import Path
from wasm_decompiler import Options, parse_module, decompile_function

module = parse_module(Path("input.wasm").read_bytes())
result = decompile_function(module, 0, Options())
print(result.text)
print(result.source_map, result.diagnostics)
```

## Supported features and limitations

The core supports Wasm 1.0 scalar instructions, sign extension, saturating
float-to-integer conversions, and bulk memory/table operations with legacy
function-index elements. It recovers expressions, loops, switch bodies, and
conservative stack slots. Complex exits retain labels. Constant indirect calls
resolve only when a private, immutable table proves the target.

Output is **inspection pseudocode**, not a standalone native C program. Pointer
notation denotes checked, little-endian Wasm memory. Integer operations retain
Wasm wrapping and trap semantics; exceptional operations can retain explicit
intrinsics. Original aggregate types and source code are not recovered.

Multi-value/type-index blocks, general reference instructions, SIMD, atomics,
exceptions, tail calls, memory64, multiple memories/tables, GC, and component
modules are unsupported and produce diagnostics. Resource limits are 64 MiB per
module, one million entries per vector, one million instructions per function,
and 100,000 locals per function.

Further details:

- [C presentation and helper semantics](docs/HELPERS.md)
- [Native Hex-Rays API boundary and IDA compatibility](docs/NATIVE_INTEGRATION.md)
- [Validation coverage and known limits](docs/VALIDATION.md)

## Development and validation

Core tests require **pytest**, **WABT** (`wat2wasm`, `wasm-interp`), and a **C
compiler**. Install those with your environment's package manager, then run:

```sh
python3 -m pytest -q
python3 tools/validate_ida.py --ida-dir /path/to/ida-pro --gui samples/navigation.wasm
python3 tools/check_sdk_compat.py
python3 tools/package_plugin.py
```

The IDA check uses temporary databases and an isolated user directory. The SDK
check downloads official headers and checks API presence; it is not runtime
validation of those IDA versions. Pinned public fixtures, hashes, licenses, and
retrieval instructions are documented in the repository's `samples/` directory.

## License

The plugin is licensed under [MIT](LICENSE). See [third-party material and
references](THIRD_PARTY.md) for sample licenses and architectural references.
