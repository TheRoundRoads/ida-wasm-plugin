"""Typed stack validation and explicit branch resolution."""
from dataclasses import dataclass
import re
from .binary import WasmError, decode


@dataclass(eq=False)
class Frame:
    kind: str
    height: int
    results: tuple
    start: int
    end: int = -1
    alternative: int = -1
    unreachable: bool = False

    @property
    def label_types(self):
        return () if self.kind == 'loop' else self.results


def numeric_signature(name):
    t, op = name.split('.')
    conversion = re.search(r'(?:wrap|trunc(?:_sat)?|extend|convert|demote|promote|reinterpret)_(i32|i64|f32|f64)', op)
    if conversion:
        return [conversion[1]], [t]
    if op == 'eqz':
        return [t], ['i32']
    if op.split('_')[0] in ('eq','ne','lt','gt','le','ge'):
        return [t,t], ['i32']
    unary = ('clz','ctz','popcnt','abs','neg','ceil','floor','trunc','nearest','sqrt','extend8_s','extend16_s','extend32_s')
    return ([t] if op in unary else [t,t]), [t]


def memory_width(name):
    t, op = name.split('.')
    match = re.search(r'(?:load|store)(8|16|32)', op)
    return int(match[1]) // 8 if match else int(t[1:]) // 8


@dataclass
class Analysis:
    instructions: list
    root: Frame
    reachable: set
    slots: set


def analyze(module, function, cancelled=lambda: False):
    instructions = decode(function, cancelled)
    sig = module.signature(function)
    locals_ = sig.params + function.locals
    stack, controls = [], [Frame('function', 0, tuple(sig.results), -1)]
    root = controls[0]
    slots = set()

    def error(msg, ins):
        raise WasmError(msg, ins.offset)

    def index(values, idx, ins, description):
        if idx >= len(values):
            error(f'{description} index {idx} out of bounds', ins)
        return values[idx]

    def pop(t, ins):
        f = controls[-1]
        if len(stack) == f.height and f.unreachable:
            return t
        if len(stack) <= f.height:
            error('operand stack underflow', ins)
        actual = stack.pop()
        if t is not None and actual is not None and actual != t:
            error(f'type mismatch: expected {t}, got {actual}', ins)
        return actual if actual is not None else t

    def pops(types, ins):
        return [pop(t, ins) for t in reversed(types)][::-1]

    def dead():
        del stack[controls[-1].height:]
        controls[-1].unreachable = True

    for n, ins in enumerate(instructions):
        if n % 256 == 0 and cancelled():
            raise WasmError('analysis cancelled', ins.offset, 'cancelled')
        if not controls:
            error('instructions after function END', ins)
        ins.before = tuple(stack)
        name, a = ins.name, ins.args
        if name in ('block','loop','if'):
            if name == 'if':
                pop('i32', ins)
            frame = Frame(name, len(stack), a, n)
            controls.append(frame)
            ins.frame = frame
        elif name == 'else':
            frame = controls[-1]
            if frame.kind != 'if' or frame.alternative != -1:
                error('ELSE without matching IF', ins)
            pops(frame.results, ins)
            if len(stack) != frame.height:
                error('unexpected values at ELSE', ins)
            frame.alternative, frame.unreachable = n, False
            ins.frame = frame
        elif name == 'end':
            frame = controls[-1]
            pops(frame.results, ins)
            if len(stack) != frame.height:
                error('unexpected values at END', ins)
            if frame.kind == 'if' and frame.alternative == -1 and frame.results:
                error('result-producing IF requires ELSE', ins)
            controls.pop()
            frame.end, ins.frame = n, frame
            stack.extend(frame.results)
        elif name in ('br', 'br_if', 'br_table', 'return'):
            if name in ('br_if', 'br_table'):
                pop('i32', ins)
            targets = [root] if name == 'return' else [index(list(reversed(controls)), depth, ins, 'branch depth') for depth in a]
            types = targets[0].label_types
            if any(f.label_types != types for f in targets):
                error('branch table label types differ', ins)
            pops(types, ins)
            ins.targets = targets
            if name == 'br_if':
                stack.extend(types)
            else:
                dead()
        elif name == 'unreachable':
            dead()
        elif name == 'nop':
            pass
        elif name == 'drop':
            pop(None, ins)
        elif name == 'select':
            pop('i32', ins)
            t2, t1 = pop(None, ins), pop(None, ins)
            if t1 is not None and t2 is not None and t1 != t2:
                error('SELECT operands differ', ins)
            stack.append(t1 or t2)
        elif name.startswith('local.'):
            t = index(locals_, a[0], ins, 'local')
            if name != 'local.get':
                pop(t, ins)
            if name != 'local.set':
                stack.append(t)
        elif name.startswith('global.'):
            g = index(module.globals, a[0], ins, 'global')
            if name == 'global.get':
                stack.append(g['type'])
            else:
                if not g['mutable']:
                    error('write to immutable global', ins)
                pop(g['type'], ins)
        elif name in ('call', 'call_indirect'):
            if name == 'call':
                signature = module.signature(index(module.functions, a[0], ins, 'function'))
            else:
                signature = index(module.types, a[0], ins, 'type')
                index(module.tables, a[1], ins, 'table')
                pop('i32', ins)
            pops(signature.params, ins)
            stack.extend(signature.results)
        elif name in ('memory.size', 'memory.grow'):
            index(module.memories, a[0], ins, 'memory')
            if name == 'memory.grow':
                pop('i32', ins)
            stack.append('i32')
        elif '.load' in name or '.store' in name:
            index(module.memories, 0, ins, 'memory')
            if a[0] > memory_width(name).bit_length() - 1:
                error('memory alignment exceeds natural alignment', ins)
            t = name[:3]
            if '.store' in name:
                pops(['i32', t], ins)
            else:
                pop('i32', ins)
                stack.append(t)
        elif name in ('memory.init','data.drop','memory.copy','memory.fill','table.init','elem.drop','table.copy'):
            if name in ('memory.init','data.drop'):
                if module.data_count is None:
                    error('data-index instruction requires data count section', ins)
                index(module.segments, a[0], ins, 'data segment')
            if name in ('table.init','elem.drop'):
                index(module.elements, a[0], ins, 'element segment')
            if name in ('memory.init', 'table.init'):
                index(module.memories if name.startswith('memory') else module.tables, a[1], ins, 'memory/table')
            if name in ('memory.copy','table.copy'):
                for idx in a:
                    index(module.memories if name.startswith('memory') else module.tables, idx, ins, 'memory/table')
            if name == 'memory.fill':
                index(module.memories, a[0], ins, 'memory')
            if name not in ('data.drop','elem.drop'):
                pops(['i32']*3, ins)
        elif name.endswith('.const'):
            stack.append(name[:3])
        else:
            inputs, outputs = numeric_signature(name)
            pops(inputs, ins)
            stack.extend(outputs)
        ins.after = tuple(stack)
        for types in (ins.before, ins.after):
            slots.update((t, depth) for depth, t in enumerate(types) if t is not None)
    if controls:
        raise WasmError('missing function END', function.code_offset + len(function.code))

    def destination(frame):
        return frame.start + 1 if frame.kind == 'loop' else frame.end + 1

    reachable, todo = set(), [0]
    while todo:
        n = todo.pop()
        if n >= len(instructions) or n in reachable:
            continue
        reachable.add(n)
        ins = instructions[n]
        if ins.name in ('br','return','br_table'):
            successors = [destination(f) for f in ins.targets]
        elif ins.name == 'br_if':
            successors = [n+1, destination(ins.targets[0])]
        elif ins.name == 'if':
            f = ins.frame
            successors = [n+1, f.alternative+1 if f.alternative != -1 else f.end+1]
        elif ins.name == 'else':
            successors = [ins.frame.end+1]
        elif ins.name == 'unreachable':
            successors = []
        else:
            successors = [n+1]
        todo.extend(successors)
    return Analysis(instructions, root, reachable, slots)
