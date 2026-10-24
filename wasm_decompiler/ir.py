"""Small typed expression IR and source-preserving statement representation."""
from dataclasses import dataclass, field
import re


def slot(t, depth):
    return f'v{depth}_{t}'


@dataclass(frozen=True)
class Expr:
    op: str
    args: tuple = ()
    value: object = None
    depth: int = field(init=False, compare=False, default=1)

    def __post_init__(self):
        object.__setattr__(self, 'depth', 1 + max((a.depth for a in self.args), default=0))

    @property
    def pure(self):
        # Only these operations are safe to inline without changing traps or FP behavior.
        simple = self.op in ('var','const','select','not','truth')
        numeric = self.op.startswith(('i32.','i64.','f32.','f64.'))
        nontrapping = numeric and not any(x in self.op for x in ('.load','.store','.div_s','.div_u','.rem_', '.trunc_f'))
        return (simple or nontrapping) and all(a.pure for a in self.args)

    def count(self, name):
        return int(self.op == 'var' and self.value == name) + sum(a.count(name) for a in self.args)

    def replace(self, name, expression):
        if self.op == 'var' and self.value == name:
            return expression
        return Expr(self.op, tuple(a.replace(name, expression) for a in self.args), self.value)

    def render(self):
        if self.op == 'truth':
            return f'(!!{self.args[0].render()})'
        if self.op == 'not':
            return f'(!{self.args[0].render()})'
        if self.op in ('var','const'):
            return str(self.value)
        a = [x.render() for x in self.args]
        if self.op in ('i32.eqz','i64.eqz'):
            return f'({a[0]} == 0)'
        if '.' in self.op and self.op[:3] in ('i32','i64'):
            kind = self.op.split('.')[1]
            relation = kind.split('_')[0]
            if relation in ('eq','ne','lt','gt','le','ge'):
                symbol = {'eq':'==','ne':'!=','lt':'<','gt':'>','le':'<=','ge':'>='}[relation]
                if kind.endswith('_s'):
                    a = [f'wasm_as_{self.op[:3]}_signed({x})' for x in a]
                return f'({a[0]} {symbol} {a[1]})'
        if self.op == 'select':
            return f'({a[2]} ? {a[0]} : {a[1]})'
        if self.op in ('i32.add','i32.sub','i32.mul','i64.add','i64.sub','i64.mul','i32.and','i32.or','i32.xor','i64.and','i64.or','i64.xor'):
            symbol = {'add':'+','sub':'-','mul':'*','and':'&','or':'|','xor':'^'}[self.op.split('.')[1]]
            return f'({a[0]} {symbol} {a[1]})'
        if self.op == 'call':
            return f'{self.value}({", ".join(a)})'
        return f'wasm_{self.op.replace(".", "_")}({", ".join(a)})'


def var(name):
    return Expr('var', value=name)


def const(value):
    return Expr('const', value=value)


@dataclass
class Statement:
    offset: int
    dest: str = ''
    expr: object = None
    prefix: str = ''
    suffix: str = ';'
    indent: int = 1
    live_after: set = field(default_factory=set)
    origins: set = field(default_factory=set)
    boundary: bool = False

    def render(self, c_style=False):
        content = (self.dest + ' = ' if self.dest else self.prefix)
        if self.expr:
            if c_style:
                from .readable import expression, condition
                content += condition(self.expr) if self.prefix in ('if (','while (') else expression(self.expr)
            else:
                content += self.expr.render()
        return '    ' * self.indent + content + self.suffix


def optimize(statements):
    """Inline adjacent pure producers only when their virtual register dies there.

    No effectful operation moves, and block boundaries stop propagation.
    """
    result = []
    for statement in statements:
        while result and statement.expr:
            prev = result[-1]
            if (prev.boundary or not prev.dest.startswith('v')
                    or not prev.expr or prev.expr.depth + statement.expr.depth > 64
                    or not prev.expr.pure or prev.indent != statement.indent
                    or statement.expr.count(prev.dest) != 1
                    or (prev.dest in statement.live_after and statement.dest != prev.dest)):
                break
            statement.expr = statement.expr.replace(prev.dest, prev.expr)
            statement.origins |= prev.origins | {prev.offset}
            result.pop()
        result.append(statement)
    return result


def identifier(name, default):
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name or default)
    if not name or name[0].isdigit():
        name = '_' + name
    reserved = {'if','else','while','do','switch','case','default','return','break','continue','goto','int','float','double','void','long','short','char','unsigned','signed','const','static','struct','union','enum','sizeof','for','auto','register','volatile','restrict','typedef','extern','inline','_Bool'}
    if name in reserved or name.startswith(('v','wasm_','label_','stack_','global_')):
        name = 'user_' + name
    return name


def unique_names(candidates, reserved=()):
    used, names = set(reserved), []
    for i, candidate in enumerate(candidates):
        base = identifier(candidate, f'func_{i}')
        name, suffix = base, 1
        while name in used:
            name, suffix = f'{base}_{suffix}', suffix+1
        names.append(name)
        used.add(name)
    return names
