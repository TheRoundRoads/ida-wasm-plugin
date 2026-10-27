"""Persistent, presentation-only edits to Wasm pseudocode."""
from dataclasses import replace
import re

from .decompile import C_TYPES


INTEGER = re.compile(r'(?<![\w.])(?:0x[0-9a-fA-F]+|\d+)(?:ULL|ull|u)?(?![\w.])')


def numbers(line):
    """Integer tokens with positions and values in one uncolored source line."""
    for ordinal, match in enumerate(INTEGER.finditer(line)):
        raw = match.group()
        digits = re.sub(r'(?:ULL|ull|u)$', '', raw)
        value = int(digits, 16 if digits.lower().startswith('0x') else 10)
        yield ordinal, match.start(), match.end(), value, raw


def format_number(value, raw, mode):
    suffix = re.search(r'(?:ULL|ull|u)$', raw)
    suffix = suffix.group() if suffix else ''
    if mode == 'hex':
        return hex(value) + suffix
    if mode == 'dec':
        return str(value) + suffix
    if mode == 'char':
        chars = {0: r'\0', 9: r'\t', 10: r'\n', 13: r'\r', 39: r"\'", 92: r'\\'}
        char = chars.get(value, chr(value) if 32 <= value < 127 else None)
        return "'" + char + "'" if char is not None else raw
    return raw


def apply_display(result, module, settings):
    """Decorate a core Result without changing its typed IR or module bytes."""
    index = result.function_index
    function = module.functions[index]
    signature = module.signature(function)
    type_settings = settings.get('display_types', {})
    local_types = type_settings.get('locals', {}).get(str(index), {})
    return_type = type_settings.get('returns', {}).get(str(index))
    global_types = type_settings.get('globals', {})
    by_local = {symbol['index']: name for name, symbol in result.symbols.items()
                if symbol['kind'] == 'local'}
    for i in range(len(signature.params)):
        by_local.setdefault(i, function.local_names.get(i, f'arg_{i}'))
    lines = result.text.splitlines()
    if not lines:
        return result
    if return_type or any(str(i) in local_types for i in range(len(signature.params))):
        args = ', '.join(
            f'{local_types.get(str(i), C_TYPES[typ])} {by_local[i]}'
            for i, typ in enumerate(signature.params)
        ) or 'void'
        ending = '; /* imported */' if function.imported else ' {'
        shown_return = return_type or (C_TYPES[signature.results[0]] if signature.results else 'void')
        lines[0] = f'{shown_return} {result.name}({args}){ending}'
    for i, typ in enumerate(function.locals, len(signature.params)):
        override = local_types.get(str(i))
        name = by_local.get(i)
        if override and name:
            pattern = re.compile(r'^(\s*)' + re.escape(C_TYPES[typ]) + r'(?=\s+' + re.escape(name) + r'\b)')
            lines = [pattern.sub(lambda match: match[1] + override, line) for line in lines]

    formats = settings.get('number_formats', {}).get(str(index), {})
    spans = {}
    for line_number, line in enumerate(lines, 1):
        matches = list(numbers(line)) if line_number in result.source_map else []
        if not matches:
            continue
        edited, cursor, positions = [], 0, []
        for ordinal, start, end, value, raw in matches:
            edit = formats.get(f'{line_number}:{ordinal}', {})
            shown = format_number(value, raw, edit['mode']) if edit.get('value') == value else raw
            edited.append(line[cursor:start])
            shown_start = sum(map(len, edited))
            edited.append(shown)
            positions.append((shown_start, shown_start + len(shown), line_number, ordinal, value, raw))
            cursor = end
        edited.append(line[cursor:])
        lines[line_number - 1] = ''.join(edited)
        spans[line_number] = positions

    globals_used = sorted((symbol['index'], name) for name, symbol in result.symbols.items()
                          if symbol['kind'] == 'global' and str(symbol['index']) in global_types)
    globals_lines = [f'    extern {global_types[str(i)]} {name};' for i, name in globals_used]
    comments = settings.get('comments', {}).get(str(index), {})
    rendered, source_map, display_lines, number_spans = [], {}, {}, {}
    for base_line, line in enumerate(lines, 1):
        if base_line == 2:
            for declaration in globals_lines:
                rendered.append(declaration)
                display_lines[len(rendered)] = None
        comment = comments.get(str(base_line), {})
        indent = re.match(r'\s*', line)[0]
        for kind in ('block', 'indented'):
            value = comment.get(kind)
            if value:
                parts = value.replace('*/', '* /').splitlines() or ['']
                if kind == 'block':
                    markers = ([indent + '/* ' + parts[0] + ' */'] if len(parts) == 1 else
                               [indent + '/* ' + parts[0]] +
                               [indent + ' * ' + part for part in parts[1:-1]] +
                               [indent + ' * ' + parts[-1] + ' */'])
                else:
                    markers = [indent + '// ' + part for part in parts]
                for marker in markers:
                    rendered.append(marker)
                    display_lines[len(rendered)] = base_line
        rendered.append(line)
        final_line = len(rendered)
        display_lines[final_line] = base_line
        if base_line in result.source_map:
            source_map[final_line] = result.source_map[base_line]
        if base_line in spans:
            number_spans[final_line] = spans[base_line]
    return replace(result, text='\n'.join(rendered), source_map=source_map,
                   display_lines=display_lines, number_spans=number_spans)
