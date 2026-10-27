from pathlib import Path

from wasm_decompiler import decompile_function, export_text, parse_module
from wasm_decompiler.display import apply_display


ROOT = Path(__file__).resolve().parents[1]


def test_display_edits_preserve_wasm_and_target_one_literal():
    module = parse_module((ROOT / 'samples/core.wasm').read_bytes())
    original_bytes = bytes(module.data)
    original = decompile_function(module, 1)
    settings = {
        'display_types': {
            'returns': {'1': 'unsigned long'},
            'locals': {'1': {'0': 'const uint32_t', '1': 'signed int'}},
            'globals': {'0': 'signed int'},
        },
        'comments': {'1': {'3': {'indented': 'saved note', 'block': 'more detail'}}},
        'number_formats': {'1': {'3:0': {'value': 1, 'mode': 'hex'}}},
    }
    shown = apply_display(original, module, settings)
    assert shown.text.startswith('unsigned long factorial(const uint32_t n)')
    assert 'signed int acc;' in shown.text
    assert '// saved note' in shown.text and '/* more detail */' in shown.text
    assert 'acc = 0x1;' in shown.text
    assert 'n = n - 1;' in shown.text
    assert original.text.count('0x1') == 0
    assert bytes(module.data) == original_bytes
    assert shown.source_map and all(line in shown.display_lines for line in shown.source_map)
    exported = export_text(module, [shown], display_types=settings['display_types'])
    assert 'signed int global_0;' in exported
    assert 'unsigned long factorial(const uint32_t arg_0);' in exported
    assert 'acc = 0x1;' in exported


def test_global_display_type_in_function():
    module = parse_module((ROOT / 'samples/public/mdn-js-api-examples-global.wasm').read_bytes())
    original = decompile_function(module, 0)
    shown = apply_display(original, module, {
        'display_types': {'globals': {'0': 'signed int'}},
    })
    assert 'extern signed int global_0;' in shown.text
    assert 'extern signed int' not in original.text
