"""Collect source-offset references without importing IDA."""
from .binary import decode, WasmError


def collect_references(module, cancelled=lambda:False):
    references, diagnostics = [],[]
    for function in module.functions:
        if function.imported:
            continue
        try:
            instructions = decode(function,cancelled)
        except WasmError as exc:
            if exc.code == 'cancelled':
                raise
            diagnostics.append(dict(function=function.index,**exc.diagnostic()))
            continue
        for instruction in instructions:
            if instruction.name in ('global.get','global.set'):
                index = instruction.args[0]
                if index < len(module.globals):
                    references.append((instruction.offset,'read' if instruction.name=='global.get' else 'write',index))
            elif instruction.name == 'call':
                index = instruction.args[0]
                if index < len(module.functions):
                    references.append((instruction.offset,'call',index))
    return references,diagnostics
