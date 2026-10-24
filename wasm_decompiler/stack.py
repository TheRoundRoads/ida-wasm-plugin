"""Conservative compiler stack recovery using memory-backed named slots.

Slots remain aliases of linear memory, so recovery preserves traps and aliasing.
The first version handles balanced straight-line frames with no calls/branches.
"""
from .binary import WasmError
from .ir import Expr, Statement, var


def recover(module, function, statements, options):
    explicit = options.stack_pointer
    if explicit is not None and (not isinstance(explicit,int) or not 0 <= explicit < len(module.globals)):
        raise WasmError('stack-pointer global override out of bounds', function.code_offset)
    if explicit is not None and (module.globals[explicit]['type'] != 'i32' or not module.globals[explicit]['mutable']):
        raise WasmError('stack pointer must be a mutable i32 global', function.code_offset)
    candidates = ([explicit] if explicit is not None else
                  [i for i,g in enumerate(module.globals) if g['type'] == 'i32' and g['mutable']])
    if any(s.boundary and not s.prefix.startswith('return') for s in statements):
        return statements,[],None
    if any(s.expr and contains_forbidden(s.expr) for s in statements):
        return statements,[],None
    for sp in candidates:
        found = recover_candidate(statements,sp)
        if found:
            transformed,declarations = found
            return transformed,declarations,f'Recovered {len(declarations)} memory-backed C stack slots from global_{sp}'
    return statements,[],None


def contains_forbidden(expr):
    return expr.op in ('call','call_indirect','memory.grow','memory.init','memory.copy','memory.fill') or any(contains_forbidden(x) for x in expr.args)


def number(text):
    try:
        return int(str(text).rstrip('ulUL'),0)
    except ValueError:
        return None


def recover_candidate(statements, sp):
    env = {f'global_{sp}':(1,0)}  # affine (coefficient of initial SP, constant)
    accesses, updates = [],[]

    def affine(expr):
        if expr.op == 'var':
            return env.get(expr.value)
        if expr.op == 'const':
            n = number(expr.value)
            return (0,n) if n is not None else None
        if expr.op in ('i32.add','i32.sub'):
            left,right = affine(expr.args[0]),affine(expr.args[1])
            if left is not None and right is not None:
                sign = -1 if expr.op.endswith('sub') else 1
                return (left[0]+sign*right[0], left[1]+sign*right[1])
        return None

    for i,s in enumerate(statements):
        if s.expr and ('.load' in s.expr.op or '.store' in s.expr.op):
            e = s.expr
            # Full-width scalar accesses only; packed or mixed accesses stay explicit.
            if e.op.split('.')[1] not in ('load','store'):
                return None
            address,offset = affine(e.args[0]), number(e.args[1].value)
            if address is None or address[0] != 1 or offset is None:
                return None
            if '.store' in e.op:
                stored = affine(e.args[2])
                if stored is not None and stored[0]:
                    return None
            t = e.op[:3]
            key = (address[1],offset,t)
            accesses.append((i,key,address[1]+offset))
        if s.dest:
            value = affine(s.expr)
            # Returning/storing a frame pointer is an escape, except SP restoration.
            if s.dest.startswith('global_') and s.dest != f'global_{sp}' and value and value[0]:
                return None
            env[s.dest] = value
            if s.dest == f'global_{sp}':
                updates.append(value)
        if s.prefix.startswith('return') and s.expr:
            value = affine(s.expr)
            if value and value[0]:
                return None
    if len(updates) != 2 or updates[0] is None or updates[1] != (1,0):
        return None
    if updates[0][0] != 1 or updates[0][1] >= 0 or not accesses:
        return None
    size = -updates[0][1]
    keys = []
    for _,key,offset in accesses:
        width = int(key[2][1:])//8
        if not -size <= offset <= -width:
            return None
        if key not in keys:
            keys.append(key)
    # Reject overlapping distinct slots; keep byte-level memory representation.
    ranges = sorted((base+off,base+off+int(t[1:])//8) for base,off,t in keys)
    if any(a[1] > b[0] for a,b in zip(ranges,ranges[1:])):
        return None
    names = {key:f'stack_local_{i}' for i,key in enumerate(keys)}
    declarations = [f'wasm_stack_slot_{key[2]} {names[key]};' for key in keys]
    by_index = {i:key for i,key,_ in accesses}
    bound, transformed = set(),[]
    for i,s in enumerate(statements):
        if i in by_index:
            key,e = by_index[i],s.expr
            name,t = names[key],key[2]
            if key not in bound:
                transformed.append(Statement(s.offset,name,Expr('stack_bind_'+t,e.args[:2]),indent=s.indent,origins=set(s.origins)))
                bound.add(key)
            s.expr = Expr('stack_'+('load_' if '.load' in e.op else 'store_')+t,
                          (var(name),) + (e.args[2:] if '.store' in e.op else ()))
        transformed.append(s)
    return transformed,declarations
