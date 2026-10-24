"""Resolve only private, immutable MVP function tables and constant indices."""
from .binary import decode, WasmError
from .ir import Expr


def private_table(module, cancelled):
    if hasattr(module,'_private_table'):
        return module._private_table
    module._private_table = None
    if not module.tables or module.tables[0]['imported']:
        return None
    if any(kind == 1 for _,kind,_ in module.exports):
        return None
    try:
        if any(i.name.startswith('table.') for f in module.functions if not f.imported for i in decode(f, cancelled)):
            return None
    except WasmError as exc:
        if exc.code == 'cancelled':
            raise
        return None
    entries = {}
    for element in module.elements:
        if element['mode'] != 'active':
            continue
        if element['offset'][0] != 'i32':
            return None
        base = element['offset'][1] & 0xffffffff
        if base + len(element['functions']) > module.tables[0]['limits'][0]:
            return None
        entries.update((base+i,idx) for i,idx in enumerate(element['functions']))
    module._private_table = entries
    return entries


def resolve(module, statements, names, symbols, cancelled=lambda: False):
    table = private_table(module, cancelled)
    if table is None:
        return
    constants = {}

    def value(expr):
        if expr.op == 'var':
            return constants.get(expr.value)
        if expr.op == 'const':
            try:
                return int(str(expr.value).rstrip('ulUL'),0)
            except ValueError:
                pass
        return None

    for s in statements:
        if s.boundary:
            constants.clear()
        if s.expr and s.expr.op == 'call_indirect':
            type_id, table_id, index, *args = s.expr.args
            idx = value(index)
            target = table.get(idx) if idx is not None else None
            if (target is not None and value(table_id) == 0 and
                    module.signature(module.functions[target]) == module.types[value(type_id)]):
                s.expr = Expr('call',tuple(args),names[target])
                symbols[names[target]] = dict(kind='function',index=target)
        if s.expr and s.expr.op in ('call', 'call_indirect'):
            # Calls may change mutable globals used by subsequent table indices.
            constants.clear()
        if s.dest:
            constants[s.dest] = value(s.expr)
