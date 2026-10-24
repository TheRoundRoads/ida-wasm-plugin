# C presentation and semantic notation

Version 0.2 displays the typed IR using C syntax by default. The explicit semantic
form remains available with `--explicit-wasm` / `Options(c_style=False)`.

- Loads/stores display as `*(uint32_t *)(memory + address + offset)`
  with the appropriate accessed type and signedness. These are **checked,
  little-endian Wasm accesses**, including unaligned accesses; the notation is not
  permission to substitute unchecked native C pointer dereferences.
- Narrow/widen operations use casts, scalar operations use operators, rotate/count
  operations use intrinsics, and ordinary finite float constants display directly.
  Integer results retain their Wasm width and wrapping. Integer division and float
  conversions retain Wasm trap behavior, even where a native C expression has
  different exceptional behavior. NaN payloads and reinterpretations use intrinsics.
- Bulk memory copy/fill display as `memmove`/`memset` within linear memory, with
  Wasm bounds checks and segment state still implied by the underlying IR.
- Recovered stack slots display as typed pointer locals whose dereferences alias
  their original linear memory. They remain checked on access.
- `__indirect_call(type, table, index, args...)` retains bounds/null/type checks;
  `__trap()` never returns. Other `__...` intrinsics correspond to the semantic
  operations described below, with the `wasm_` prefix replaced by `__`.
- Expression forwarding preserves dependencies, side-effect order and eager
  selection. Calls/loads are not folded into conditional `select` operands.

The readable representation targets analysis, not recompilation. The execution
suite supplies a test-only harness for the subset used in native comparisons.

## Explicit helper semantics

Helpers are semantic notation in the output, not a bundled executable runtime.
Their names correspond to Wasm instruction names with `.` replaced by `_`.
Operands appear in Wasm evaluation order. Each helper returns the instruction's
result, or has no result for stores and bulk operations. A trap terminates
execution of the current Wasm invocation; it is not a recoverable C return value.

The authoritative semantics are the [WebAssembly instruction specification](https://webassembly.github.io/spec/core/exec/instructions.html).
Types `uint32_t` and `uint64_t` hold integer **bit patterns**, not inferred source
language signedness. `float` and `double` represent Wasm f32 and f64.

## Numeric instructions

- Integer add/subtract/multiply and bitwise operations render directly with
  unsigned-width operands. Their results wrap to the destination width.
- Equality and unsigned comparisons render directly. Signed comparisons use
  `wasm_as_i32_signed(bits)` or `wasm_as_i64_signed(bits)` to interpret the same
  bits as a two's-complement signed integer, without changing those bits.
- Shift helpers mask the shift count to 5/6 bits; signed right shifts sign-extend.
  Rotates, leading/trailing zero counts, and population counts follow Wasm exactly,
  including zero inputs and zero rotate counts.
- Signed/unsigned division traps on a zero divisor. Signed division also traps
  for minimum-signed divided by -1. Signed remainder of that pair is zero.
- Conversion helpers identify source, destination, and signedness in their names.
  Truncating conversions trap on NaN and out-of-range values. `trunc_sat` variants
  saturate and map NaN to zero. Reinterpretations preserve bits.
- `wasm_f32_from_bits(bits)` / `wasm_f64_from_bits(bits)` construct the exact
  encoded float constant, including NaN payloads, infinities, and signed zero.
- Float arithmetic, comparisons, rounding, min/max, and conversions retain Wasm's
  precision, signed-zero, NaN, and rounding rules. `nearest` uses ties to even.
  NaN results may use any representation the Wasm specification permits.
- `wasm_trap()` represents `unreachable` and never returns.

`select` renders as a conditional expression only after its inputs have already
been evaluated. Inlining permits only pure, nontrapping operations; effectful
operands, including loads and calls, stay eagerly evaluated.

## Memory and stack slots

- `wasm_i32_load(address, offset)` and other loads calculate the effective address
  as **unsigned wasm32 address + unsigned immediate offset without wrapping the
  sum**. They bounds-check the entire accessed range and load little-endian bytes.
  Packed loads sign- or zero-extend as named. Alignment immediates are validated
  but do not change behavior; unaligned accesses remain valid.
- Stores use `(address, offset, value)`, perform the same bounds checks, and write
  the named low-width little-endian bytes. Every access can trap independently.
- `wasm_memory_size(memory_index)` returns pages (64 KiB each).
  `wasm_memory_grow(memory_index, delta)` returns the old page count, or all-one
  i32 bits on failure. Linear memory storage can change on growth.
- `wasm_stack_bind_i32(address, offset)` creates a **memory-backed slot descriptor**,
  not a copied value or a native pointer. It records the effective-address inputs
  without accessing memory or trapping. The corresponding `wasm_stack_slot_i32`
  type identifies such a descriptor. f32/i64/f64 variants follow the same rule.
- `wasm_stack_load_i32(slot)` and `wasm_stack_store_i32(slot, value)` access the
  original linear memory through that descriptor, with the same load/store checks.
  Slots remain aliases if other accesses touch those bytes. They never become
  independent scalar storage.

The conservative stack pass requires a balanced SP decrement/restore, fixed
nonoverlapping full-width slots inside the allocated frame, no control-flow
boundaries or calls, and no recognized frame-pointer escape. It does not remove
SP updates or prove native C types.

## Calls and bulk operations

- Direct calls use recovered module signatures and sanitized identifiers.
- `wasm_call_indirect(type_index, table_index, element_index, args...)` checks
  table bounds, a non-null element, and exact runtime function-type equality,
  then invokes that function. These checks trap on failure. It returns the
  signature's result when present.
- `wasm_memory_init(data_index, memory_index, destination, source, length)`,
  `wasm_memory_copy(destination_memory, source_memory, destination, source, length)`,
  and `wasm_memory_fill(memory_index, destination, byte_value, length)` use the
  original Wasm segment state and bounds semantics. Copies permit overlap.
- `wasm_table_init(element_index, table_index, destination, source, length)` and
  `wasm_table_copy(destination_table, source_table, destination, source, length)`
  follow the corresponding table semantics, including overlap and bounds checks.
- `wasm_data_drop(data_index)` / `wasm_elem_drop(element_index)` update segment
  availability for subsequent operations; repeated dropping is permitted.

Generated C-like text is intended for inspection. The test suite supplies a
limited native helper harness to compare selected output against WABT; that
harness is not a general Wasm runtime or part of the plugin.
