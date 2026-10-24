"""C-oriented presentation of the typed IR (not a native-memory execution ABI)."""
import math
import re
import struct

TYPES = {'i32':'uint32_t','i64':'uint64_t','f32':'float','f64':'double'}
SIGNED = {'i32':'int32_t','i64':'int64_t'}


def unparen(text):
    if not (text.startswith('(') and text.endswith(')')):
        return text
    depth = 0
    for i,c in enumerate(text):
        depth += (c == '(') - (c == ')')
        if depth == 0 and i != len(text)-1:
            return text
    return text[1:-1]


def literal(value):
    text = str(value)
    if re.fullmatch(r'\d+(?:u|ull)',text):
        n = int(text.rstrip('ul'))
        suffix = 'ULL' if text.endswith('ull') and n > 0xffffffff else ''
        return (hex(n) if n >= 4096 else str(n))+suffix
    return text


def memory_ref(op, address, offset):
    t,kind = op.split('.')
    match = re.search(r'(?:load|store)(8|16|32)',kind)
    width = int(match[1]) if match else int(t[1:])
    ctype = TYPES[t] if not match else ('int' if kind.endswith('_s') else 'uint')+str(width)+'_t'
    # Linear-memory address arithmetic: the immediate is added without wrapping.
    at = f'memory + {address}'
    if offset != '0':
        at += ' + '+offset
    ref = f'*({ctype} *)({at})'
    if match and '.load' in op:
        ref = f'({TYPES[t]})({ref})'
    return ref


def render(expr):
    op = expr.op
    if op == 'var':
        return str(expr.value)
    if op == 'const':
        return literal(expr.value)
    a = [render(x) for x in expr.args]
    if op == 'truth':
        return f'!!({unparen(a[0])})'
    if op == 'not':
        return f'!({unparen(a[0])})'
    if op == 'call':
        return f'{expr.value}({", ".join(unparen(x) for x in a)})'
    if op == 'select':
        return f'({unparen(a[2])} ? {unparen(a[0])} : {unparen(a[1])})'
    if '.load' in op:
        return memory_ref(op,*a)
    if '.store' in op:
        return memory_ref(op,a[0],a[1])+' = '+unparen(a[2])
    if op.startswith('stack_bind_'):
        return f'({TYPES[op[-3:]]} *)(memory + {a[0]} + {a[1]})'
    if op.startswith('stack_load_'):
        return '*'+a[0]
    if op.startswith('stack_store_'):
        return '*'+a[0]+' = '+unparen(a[1])
    if op == 'trap':
        return '__trap()'
    if op == 'memory.copy':
        return f'memmove(memory + {a[2]}, memory + {a[3]}, {a[4]})'
    if op == 'memory.fill':
        return f'memset(memory + {a[1]}, {a[2]}, {a[3]})'
    if op == 'call_indirect':
        # Signature/table checks stay intrinsic; arguments remain ordinary C expressions.
        return f'__indirect_call({", ".join(unparen(x) for x in a)})'
    if '.' not in op:
        return f'__{op}({", ".join(a)})'
    t,kind = op.split('.')
    if kind == 'from_bits':
        bits = int(expr.args[0].value,0)
        number = struct.unpack('<f' if t == 'f32' else '<d',bits.to_bytes(4 if t == 'f32' else 8,'little'))[0]
        if math.isfinite(number):
            # Python's decimal repr roundtrips both widths, preserving signed zero.
            return repr(number)+('f' if t == 'f32' else '')
        return f'__{t}_bits({a[0]})'
    if kind == 'eqz':
        return f'({a[0]} == 0)'
    relation = kind.split('_')[0]
    if relation in ('eq','ne','lt','gt','le','ge'):
        symbol = {'eq':'==','ne':'!=','lt':'<','gt':'>','le':'<=','ge':'>='}[relation]
        if kind.endswith('_s'):
            a = [f'({SIGNED[t]}){x}' for x in a]
        return f'({a[0]} {symbol} {a[1]})'
    binary = {'add':'+','sub':'-','mul':'*','and':'&','or':'|','xor':'^','div':'/','div_u':'/','div_s':'/',
              'rem_u':'%','rem_s':'%','shl':'<<','shr_u':'>>','shr_s':'>>'}
    if kind in binary:
        if t in ('i32','i64') and kind in ('shl','shr_u','div_u','rem_u') and expr.args[0].op == 'const':
            a[0] = f'({TYPES[t]}){a[0]}'
        if kind.endswith('_s'):
            a[0] = f'({SIGNED[t]}){a[0]}'
            if not kind.startswith('shr'):
                a[1] = f'({SIGNED[t]}){a[1]}'
        if kind in ('shl','shr_u','shr_s'):
            a[1] = f'({unparen(a[1])} & {31 if t=="i32" else 63})'
        return f'({a[0]} {binary[kind]} {a[1]})'
    if kind.startswith(('rotl','rotr','clz','ctz','popcnt')):
        return f'__{kind}{t[1:]}({", ".join(unparen(x) for x in a)})'
    if kind == 'wrap_i64':
        return f'(uint32_t){a[0]}'
    if kind.startswith('extend_i32'):
        return f'({TYPES[t]})'+(f'(int64_t)(int32_t){a[0]}' if kind.endswith('_s') else a[0])
    if kind.startswith(('extend8','extend16','extend32')):
        width = re.search(r'\d+',kind)[0]
        return f'({TYPES[t]})(int{width}_t){a[0]}'
    if kind.startswith(('convert','demote','promote')):
        return f'({TYPES[t]})'+(f'({SIGNED[kind.split("_")[1]]})' if kind.endswith('_s') else '')+a[0]
    if kind == 'neg':
        return f'(-{a[0]})'
    if kind in ('abs','ceil','floor','trunc','nearest','sqrt','copysign'):
        name = {'abs':'fabs','nearest':'nearbyint'}.get(kind,kind)+('f' if t=='f32' else '')
        return f'{name}({", ".join(unparen(x) for x in a)})'
    # Retain explicit intrinsics where casts or ordinary C calls lose essential
    # semantics: checked float truncation, NaN-sensitive min/max, reinterprets, etc.
    return f'__{op.replace(".","_")}({", ".join(unparen(x) for x in a)})'


def expression(expr):
    return unparen(render(expr))


def condition(expr):
    while expr.op in ('truth','i64.extend_i32_s','i64.extend_i32_u'):
        expr = expr.args[0]
    if expr.op in ('i32.eqz','i64.eqz','not'):
        return f'!({condition(expr.args[0])})'
    return expression(expr)
