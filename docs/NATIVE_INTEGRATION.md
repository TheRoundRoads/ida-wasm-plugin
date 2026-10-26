# Native Hex-Rays API boundary

This plugin remains an independent Wasm decompiler and custom IDA viewer.
It **does not** make `ida_hexrays.decompile(wasm_ea)` return a `cfunc_t` or
`cfuncptr_t`. It does not replace that function, change the database processor
to x86, or claim that its IR is Hex-Rays ctree. The separate
`ida_wasm_decompiler.decompile(ea)` API returns a Wasm-specific text and metadata
snapshot with selected familiar methods, not a native Hex-Rays object.

This boundary was investigated explicitly in IDA Pro 9.0 using the same installed
native engine for two inputs:

| Input processor | `init_hexrays_plugin()` | Explicit x64 backend load | Native result |
|---|---|---|---|
| Wasm | False | Refused | No native engine available for this processor |
| x64 (`metapc`) | True | Not needed | Genuine `ida_hexrays.cfuncptr_t`, native pseudocode |

The native control was a compiled function `int native_probe(int a, int b)` which
returned `a+b`. Thus the installed engine works on its supported processor; the
Wasm failure is an architecture limitation, not evidence of an absent license.
`tools/hexrays_probe.py` reproduces these checks in an isolated IDA database.

## Public SDK limitations

- Hex-Rays documents `microcode_filter_t` as extending unsupported instructions
  **within an otherwise supported architecture**. It is not a public interface
  for registering an entirely new decompiler frontend:
  [official Hex-Rays explanation](https://community.hex-rays.com/t/implementing-custom-risc-v-extensions/599).
- The [IDA 9.0 decompiler limitations](https://docs.hex-rays.com/9.0/user-guide/decompiler/limit)
  list native processor-specific decompilers and do not include Wasm.
- Although `create_empty_mba()` and `create_cfunc()` exist, the
  [IDAPython API](https://python.docs.hex-rays.com/ida_hexrays/index.html)
  requires successful `init_hexrays_plugin()` before using decompiler functions.
  Those factories cannot bootstrap a supported native backend inside a Wasm
  database. A C++ plugin does not remove this backend requirement.

A translated native companion database would provide genuine native cfunc objects
at translated addresses. That alternative was declined in favor of preserving the
original Wasm database. No companion database is generated.

## What is integrated with IDA

- Calls resolve through function identities and actual source-file/database
  address mappings; punctuation in custom-viewer words is not treated as a name.
- `G` uses IDA's address/symbol dialog. Code destinations open pseudocode at the
  corresponding source location; data destinations open IDA disassembly/data views.
- Globals have typed, named database identities in an owned `.wasm_globals`
  segment, separate from linear memory and encoded initializer bytes.
- IDA macro instructions may combine several Wasm operations into one item.
  References attach to its actual head. A macro that both reads and writes one
  global is represented by a write reference, since IDA has one data-xref type
  per source/destination pair.
- Existing loader symbols are preserved. If `global_N` is already taken, the
  runtime identity uses `wasm_global_N` instead.
- Read/write xrefs are actual IDA kernel references, accessible through
  `idautils.XrefsTo`, `DataRefsTo`, and IDA's standard xref UI. Patches rebuild
  plugin-owned references while preserving unrelated loader/user references.
- `X` invokes IDA's xref chooser for functions/globals. Selecting a code reference
  decompiles its containing function. Local uses are listed within the pseudocode;
  these locals do not pretend to be Hex-Rays lvars or ctree nodes.
- Global names/types and references persist in the IDB. Renaming a global in IDA
  updates the displayed pseudocode and subsequent exports.

## IDA version compatibility

The implementation targets IDA **9.0 and newer** through public IDAPython APIs.
There are no binary patches, architecture impersonation, SDK structure offsets,
or a `version == 900` implementation path. The production plugin does not import
PyQt or PySide; its UI uses IDAPython's native custom-viewer and chooser APIs.

Runtime validation is available locally for IDA 9.0. The additional data/xref,
address-dialog and viewer-action APIs were checked in the official **9.2, 9.3 and
9.4 SDK snapshots** with `tools/check_sdk_compat.py`. Its JSON report explicitly
records source API availability, not runtime validation on those versions.
Newer IDA installations should run the same `tools/validate_ida.py` integration
checks; SDK availability alone is not a claim that every newer release was tested.
