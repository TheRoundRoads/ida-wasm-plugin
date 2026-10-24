"""C-like decompilation from validated Wasm; independent of IDA."""
from dataclasses import dataclass, field
import re
from .binary import WasmError
from .analysis import analyze, numeric_signature
from .ir import Expr, Statement, var, const, slot, unique_names

C_TYPES = {'i32':'uint32_t', 'i64':'uint64_t', 'f32':'float', 'f64':'double'}


@dataclass
class Options:
    stack_pointer: object = None
    recover_stack: bool = True
    optimize: bool = True
    c_style: bool = True


@dataclass
class Result:
    function_index: int
    name: str
    text: str = ''
    source_map: dict = field(default_factory=dict)
    symbols: dict = field(default_factory=dict)
    diagnostics: list = field(default_factory=list)
    helpers: list = field(default_factory=list)
    statements: list = field(default_factory=list, repr=False)

    @property
    def success(self):
        return not any(d['code'] != 'info' for d in self.diagnostics)

    def to_dict(self):
        return {k:getattr(self,k) for k in self.__dataclass_fields__ if k != 'statements'}


def function_names(module, overrides=None):
    overrides = overrides or {}
    return unique_names([overrides.get(f.index, f.name or f'func_{f.index}') for f in module.functions])


def prototype(module, f, names, locals_=None):
    sig = module.signature(f)
    args = ', '.join(f'{C_TYPES[t]} {(locals_ or [f"arg_{i}" for i in range(len(sig.params))])[i]}' for i,t in enumerate(sig.params)) or 'void'
    return f'{C_TYPES[sig.results[0]] if sig.results else "void"} {names[f.index]}({args})'


def decompile_function(module, index, options=None, names=None, local_names=None, cancelled=lambda: False):
    if index < 0 or index >= len(module.functions):
        raise WasmError('function index out of bounds')
    options = options or Options()
    names = function_names(module, names)
    f, result = module.functions[index], Result(index, names[index])
    if f.imported:
        result.text = prototype(module, f, names) + '; /* imported */'
        return result
    try:
        analysis = analyze(module, f, cancelled)
        sig = module.signature(f)
        locals_ = unique_names([(local_names or {}).get(i, f.local_names.get(i, f'arg_{i}' if i < len(sig.params) else f'local_{i}')) for i in range(len(sig.params)+len(f.locals))], reserved=names)
        statements, indent = [], 1
        insns = analysis.instructions
        branch_labels = {target.end for ins in insns for target in ins.targets if target.kind != 'loop'}
        loop_labels = {target.start for ins in insns for target in ins.targets if target.kind == 'loop'}

        def emit(ins, expr=None, dest='', prefix='', suffix=';', boundary=False):
            statement = Statement(ins.offset, dest, expr, prefix, suffix, indent,
                                  {slot(t,d) for d,t in enumerate(ins.after) if t}, {ins.offset}, boundary)
            if prefix.startswith('return'):
                statement.live_after = set()
            statements.append(statement)
            return statement

        def raw(ins, text, boundary=True):
            return emit(ins, prefix=text, suffix='', boundary=boundary)

        def top(ins, delta=1):
            d = len(ins.before)-delta
            return var(slot(ins.before[d], d))

        def assign(ins, expression):
            d = len(ins.after)-1
            emit(ins, expression, slot(ins.after[d], d))

        def jump(ins, target, types, condition=None):
            nonlocal indent
            if condition:
                emit(ins, condition, prefix='if (', suffix=') {', boundary=True)
                indent += 1
            count = len(target.label_types)
            # Parallel moves: destinations are below or equal to sources.
            for k,t in enumerate(target.label_types):
                src = len(types)-count+k
                if src != target.height+k:
                    emit(ins, var(slot(t,src)), slot(t,target.height+k), boundary=True)
            if target.kind == 'function':
                value = var(slot(target.results[0],0)) if target.results else None
                emit(ins, value, prefix='return ' if value else 'return', suffix=';', boundary=True)
            else:
                text = f'goto label_{"loop" if target.kind == "loop" else "end"}_{target.start};'
                raw(ins, text)
            if condition:
                indent -= 1
                raw(ins, '}')

        for n, ins in enumerate(insns):
            if n % 256 == 0 and cancelled():
                raise WasmError('decompilation cancelled', ins.offset, 'cancelled')
            name, a = ins.name, ins.args
            structural = name in ('block','loop','if','else','end')
            if n not in analysis.reachable and not structural:
                continue
            if name in ('block','loop','if'):
                if name == 'if':
                    # An unreachable IF is printed with a false condition, never read undefined slots.
                    condition = top(ins) if n in analysis.reachable else const('0 /* unreachable */')
                    emit(ins, condition, prefix='if (', suffix=') {', boundary=True)
                elif name == 'loop':
                    raw(ins, 'do {')
                else:
                    raw(ins, '{')
                indent += 1
                if name == 'loop' and n in loop_labels:
                    raw(ins, f'label_loop_{n}:;')
            elif name == 'else':
                indent -= 1
                raw(ins, '} else {')
                indent += 1
            elif name == 'end':
                frame = ins.frame
                if frame.kind == 'function':
                    if n in analysis.reachable:
                        value = var(slot(frame.results[0],0)) if frame.results else None
                        emit(ins, value, prefix='return ' if value else 'return', suffix=';', boundary=True)
                    continue
                indent -= 1
                raw(ins, '} while (0);' if frame.kind == 'loop' else '}')
                if n in branch_labels:
                    raw(ins, f'label_end_{frame.start}:;')
            elif name in ('br','return'):
                jump(ins, ins.targets[0], ins.before)
            elif name == 'br_if':
                jump(ins, ins.targets[0], ins.before[:-1], top(ins))
            elif name == 'br_table':
                emit(ins, top(ins), prefix='switch (', suffix=') {', boundary=True)
                indent += 1
                for k,target in enumerate(ins.targets):
                    raw(ins, f'case {k}:' if k < len(ins.targets)-1 else 'default:')
                    indent += 1
                    jump(ins, target, ins.before[:-1])
                    indent -= 1
                indent -= 1
                raw(ins, '}')
            elif name == 'unreachable':
                emit(ins, Expr('trap'))
            elif name in ('nop','drop'):
                pass
            elif name == 'select':
                assign(ins, Expr('select', (top(ins,3),top(ins,2),top(ins))))
            elif name == 'local.get':
                assign(ins, var(locals_[a[0]]))
            elif name in ('local.set','local.tee'):
                emit(ins, top(ins), locals_[a[0]])
            elif name == 'global.get':
                assign(ins, var(f'global_{a[0]}'))
            elif name == 'global.set':
                emit(ins, top(ins), f'global_{a[0]}')
            elif name.endswith('.const'):
                value = a[0]
                t = name[:3]
                if t.startswith('i'):
                    value = str(value & ((1 << int(t[1:]))-1)) + ('u' if t == 'i32' else 'ull')
                    assign(ins, const(value))
                else:
                    assign(ins, Expr(t+'.from_bits', (const('0x'+bytes.fromhex(value)[::-1].hex()),)))
            elif name in ('call','call_indirect'):
                signature = module.signature(module.functions[a[0]]) if name == 'call' else module.types[a[0]]
                start = len(ins.before)-len(signature.params)-(name == 'call_indirect')
                args = tuple(var(slot(t,start+k)) for k,t in enumerate(signature.params))
                if name == 'call':
                    expression = Expr('call', args, names[a[0]])
                    result.symbols[names[a[0]]] = {'kind':'function','index':a[0]}
                else:
                    expression = Expr('call_indirect', (const(a[0]),const(a[1]),top(ins))+args)
                if signature.results:
                    assign(ins, expression)
                else:
                    emit(ins, expression)
            elif '.load' in name:
                assign(ins, Expr(name, (top(ins), const(a[1]))))
            elif '.store' in name:
                emit(ins, Expr(name, (top(ins,2),const(a[1]),top(ins))))
            elif name in ('memory.size','memory.grow'):
                assign(ins, Expr(name, (const(a[0]),) + ((top(ins),) if name == 'memory.grow' else ())))
            elif name in ('memory.init','data.drop','memory.copy','memory.fill','table.init','elem.drop','table.copy'):
                operands = tuple(const(x) for x in a)
                if name not in ('data.drop','elem.drop'):
                    operands += (top(ins,3),top(ins,2),top(ins))
                emit(ins, Expr(name, operands))
            else:
                inputs, _ = numeric_signature(name)
                assign(ins, Expr(name, tuple(top(ins,k) for k in range(len(inputs),0,-1))))
        from .tables import resolve
        resolve(module, statements, names, result.symbols, cancelled)
        entry_live = set(locals_)
        if options.optimize:
            from .flow import cleanup
            statements, entry_live = cleanup(statements, cancelled)
        declarations = []
        recovery_info = None
        if options.recover_stack:
            statements, declarations, recovery_info = recover_stack(module, f, statements, options)
        if recovery_info:
            result.diagnostics.append(dict(code='info', offset=f.code_offset, message=recovery_info))
        if options.c_style:
            from .flow import prettify
            statements = prettify(statements)
            declarations = [re.sub(r'wasm_stack_slot_(i32|i64|f32|f64)',lambda m:C_TYPES[m[1]]+' *',d) for d in declarations]
        body = [s.render(options.c_style) for s in statements]
        # Declare only virtual registers still present after optimization.
        used = set(re.findall(r'\bv(\d+)_(i32|i64|f32|f64)\b', '\n'.join(body)))
        header = [prototype(module, f, names, locals_) + ' {']
        rendered = '\n'.join(body)
        for i,t in enumerate(f.locals, len(sig.params)):
            if re.search(r'\b'+re.escape(locals_[i])+r'\b',rendered):
                initial = ' = 0' if locals_[i] in entry_live else ''
                header.append(f'    {C_TYPES[t]} {locals_[i]}{initial};')
        for d,t in sorted(used, key=lambda x:(int(x[0]),x[1])):
            header.append(f'    {C_TYPES[t]} v{d}_{t};')
        header.extend('    '+line for line in declarations)
        for line,s in enumerate(statements, len(header)+1):
            result.source_map[line] = sorted(s.origins | {s.offset})
        result.text = '\n'.join(header + body + ['}'])
        if options.c_style:
            used_names = set(names) | set(locals_)
            aliases = {}
            for key in sorted(used,key=lambda x:(int(x[0]),x[1])):
                n = len(aliases)+1
                name = f'tmp{n}'
                while name in used_names:
                    n += 1
                    name = f'tmp{n}'
                used_names.add(name)
                aliases[f'v{key[0]}_{key[1]}'] = name
            result.text = re.sub(r'\bv\d+_(?:i32|i64|f32|f64)\b',lambda m:aliases[m[0]],result.text)
        result.helpers = sorted(set(re.findall(r'\b(?:wasm_|__)[a-zA-Z0-9_]+(?=\()', result.text)))
        for i,name in enumerate(locals_):
            result.symbols[name] = {'kind':'local','index':i}
        for global_index in {int(i) for i in re.findall(r'\bglobal_(\d+)\b',result.text)}:
            result.symbols[f'global_{global_index}'] = {'kind':'global','index':global_index}
        result.statements = statements
    except WasmError as exc:
        result.diagnostics.append(exc.diagnostic())
    return result


def recover_stack(module, function, statements, options):
    from .stack import recover
    return recover(module, function, statements, options)


def decompile_module(module, options=None, names=None, cancelled=lambda: False):
    results = []
    for f in module.functions:
        if cancelled():
            results.append(Result(f.index, f.name, diagnostics=[dict(code='cancelled',offset=f.code_offset,message='module export cancelled')]))
            break
        results.append(decompile_function(module,f.index,options,names,cancelled=cancelled))
    return results


def export_text(module, results, names=None, global_names=None):
    fnames = function_names(module, names)
    global_names = global_names or {}
    lines = ['/* C-like Wasm pseudocode. Memory accesses denote checked little-endian linear memory. */', '#include <stdint.h>', '']
    for i,g in enumerate(module.globals):
        lines.append(f'{C_TYPES[g["type"]]} {global_names.get(i, f'global_{i}')}; /* '+('imported' if g['imported'] else f'initializer: {g["init"]}')+' */')
    lines.extend(prototype(module,f,fnames)+';' for f in module.functions)
    for result in results:
        lines.append('')
        lines.extend(f'/* {d["code"]} at 0x{d["offset"]:x}: {d["message"].replace("*/", "* /")} */' for d in result.diagnostics)
        lines.append(result.text)
    return '\n'.join(lines)+'\n'
