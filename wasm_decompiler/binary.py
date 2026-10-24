"""Bounded WebAssembly binary reader. No IDA or third-party dependencies."""
from dataclasses import dataclass, field


class WasmError(ValueError):
    def __init__(self, message, offset=0, code='invalid'):
        self.message, self.offset, self.code = message, offset, code
        super().__init__(f'{code} at 0x{offset:x}: {message}')

    def diagnostic(self):
        return dict(code=self.code, offset=self.offset, message=self.message)


class Reader:
    def __init__(self, data, base=0):
        self.data, self.pos, self.base = memoryview(data), 0, base

    @property
    def offset(self):
        return self.base + self.pos

    def fail(self, message, code='invalid'):
        raise WasmError(message, self.offset, code)

    def take(self, count):
        if count < 0 or count > len(self.data) - self.pos:
            self.fail('truncated binary')
        start = self.pos
        self.pos += count
        return bytes(self.data[start:self.pos])

    def byte(self):
        return self.take(1)[0]

    def leb(self, bits=32, signed=False):
        start, value = self.offset, 0
        for i in range((bits + 6) // 7):
            b = self.byte()
            value |= (b & 127) << (7 * i)
            if not b & 128:
                width = 7 * (i + 1)
                if signed and b & 64:
                    value -= 1 << width
                low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
                if not low <= value <= high:
                    raise WasmError(f'LEB128 exceeds {bits} bits', start)
                return value
        raise WasmError('unterminated or oversized LEB128', start)

    def u(self):
        return self.leb()

    def count(self):
        n = self.u()
        if n > 1_000_000 or n > len(self.data) - self.pos:
            self.fail('vector count exceeds remaining bytes or resource limit')
        return n

    def string(self):
        try:
            return self.take(self.u()).decode('utf-8')
        except UnicodeDecodeError:
            self.fail('invalid UTF-8 name')

    def sub(self, count):
        base = self.offset
        return Reader(self.take(count), base)

    def done(self):
        if self.pos != len(self.data):
            self.fail('unexpected trailing bytes')


TYPES = {0x7f: 'i32', 0x7e: 'i64', 0x7d: 'f32', 0x7c: 'f64'}


def valtype(r):
    b = r.byte()
    if b not in TYPES:
        r.fail(f'unsupported value type 0x{b:02x}', 'unsupported')
    return TYPES[b]


@dataclass
class Signature:
    params: list
    results: list


@dataclass
class Function:
    index: int
    type_index: int
    name: str = ''
    import_module: str = ''
    import_name: str = ''
    imported: bool = False
    body: bytes = b''
    body_offset: int = 0
    locals: list = field(default_factory=list)
    code: bytes = b''
    code_offset: int = 0
    local_names: dict = field(default_factory=dict)


@dataclass
class Module:
    data: bytes
    types: list = field(default_factory=list)
    functions: list = field(default_factory=list)
    globals: list = field(default_factory=list)
    tables: list = field(default_factory=list)
    memories: list = field(default_factory=list)
    exports: list = field(default_factory=list)
    elements: list = field(default_factory=list)
    segments: list = field(default_factory=list)
    start: object = None
    data_count: object = None
    warnings: list = field(default_factory=list)

    def signature(self, function):
        return self.types[function.type_index]


def limits(r, memory=False):
    flags = r.u()
    if flags not in (0, 1):
        r.fail('shared, memory64, or extended limits', 'unsupported')
    minimum = r.u()
    maximum = r.u() if flags else None
    if maximum is not None and maximum < minimum:
        r.fail('maximum limit is smaller than minimum')
    if memory and (minimum > 65536 or (maximum is not None and maximum > 65536)):
        r.fail('memory exceeds wasm32 limit')
    return minimum, maximum


def tabletype(r):
    if r.byte() != 0x70:
        r.fail('only MVP funcref tables are supported', 'unsupported')
    return limits(r)


def globaltype(r):
    t, mutable = valtype(r), r.byte()
    if mutable not in (0, 1):
        r.fail('invalid global mutability')
    return t, bool(mutable)


def initexpr(r):
    op = r.byte()
    if op in (0x41, 0x42):
        value = ('i32' if op == 0x41 else 'i64', r.leb(32 if op == 0x41 else 64, True))
    elif op in (0x43, 0x44):
        value = ('f32' if op == 0x43 else 'f64', r.take(4 if op == 0x43 else 8))
    elif op == 0x23:
        value = ('global', r.u())
    else:
        r.fail(f'unsupported initializer opcode 0x{op:02x}', 'unsupported')
    if r.byte() != 0x0b:
        r.fail('initializer must end with END')
    return value


def check_init(m, expr, expected, offset):
    t, value = expr
    if t == 'global':
        if value >= len(m.globals) or not m.globals[value]['imported'] or m.globals[value]['mutable']:
            raise WasmError('initializer must reference an immutable imported global', offset)
        t = m.globals[value]['type']
    if t != expected:
        raise WasmError('initializer type mismatch', offset)


def parse_module(data):
    if len(data) > 64 * 1024 * 1024:
        raise WasmError('module exceeds 64 MiB resource limit')
    r = Reader(data)
    if r.take(8) != b'\0asm\x01\0\0\0':
        r.fail('expected WebAssembly core version 1 header', 'unsupported')
    m, seen, previous, defined = Module(bytes(data)), set(), 0, []
    names = []
    rank = {i: i for i in range(1, 10)}
    rank.update({12: 10, 10: 11, 11: 12})
    while r.pos < len(r.data):
        section = r.byte()
        s = r.sub(r.u())
        if section == 0:
            if s.string() == 'name':
                names.append(s)
            continue
        if section not in rank:
            s.fail(f'unknown section {section}', 'unsupported')
        if section in seen or rank[section] < previous:
            s.fail('duplicate or out-of-order section')
        seen.add(section)
        previous = rank[section]
        if section == 1:
            for _ in range(s.count()):
                if s.byte() != 0x60:
                    s.fail('non-function or recursive type', 'unsupported')
                params = [valtype(s) for _ in range(s.count())]
                results = [valtype(s) for _ in range(s.count())]
                if len(results) > 1:
                    s.fail('multi-value function signature', 'unsupported')
                m.types.append(Signature(params, results))
        elif section == 2:
            for _ in range(s.count()):
                mod, name, kind = s.string(), s.string(), s.byte()
                if kind == 0:
                    m.functions.append(Function(len(m.functions), s.u(), name, mod, name, True))
                elif kind == 1:
                    m.tables.append(dict(limits=tabletype(s), imported=True, name=f'{mod}.{name}'))
                elif kind == 2:
                    m.memories.append(dict(limits=limits(s, True), imported=True, name=f'{mod}.{name}'))
                elif kind == 3:
                    t, mutable = globaltype(s)
                    m.globals.append(dict(type=t, mutable=mutable, imported=True, name=f'{mod}.{name}', init=None))
                else:
                    s.fail(f'unknown import kind {kind}')
        elif section == 3:
            defined = [s.u() for _ in range(s.count())]
            for t in defined:
                m.functions.append(Function(len(m.functions), t))
        elif section == 4:
            for _ in range(s.count()):
                m.tables.append(dict(limits=tabletype(s), imported=False))
        elif section == 5:
            for _ in range(s.count()):
                m.memories.append(dict(limits=limits(s, True), imported=False))
        elif section == 6:
            for _ in range(s.count()):
                t, mutable = globaltype(s)
                expr = initexpr(s)
                check_init(m, expr, t, s.offset)
                m.globals.append(dict(type=t, mutable=mutable, imported=False, init=expr))
        elif section == 7:
            for _ in range(s.count()):
                m.exports.append((s.string(), s.byte(), s.u()))
        elif section == 8:
            m.start = s.u()
        elif section == 9:
            for _ in range(s.count()):
                flags = s.u()
                if flags not in range(4):
                    s.fail('reference-expression element segment', 'unsupported')
                table = s.u() if flags == 2 else 0
                offset = initexpr(s) if flags in (0, 2) else None
                if flags and s.byte() != 0:
                    s.fail('invalid element kind')
                funcs = [s.u() for _ in range(s.count())]
                if offset:
                    check_init(m, offset, 'i32', s.offset)
                    if table >= len(m.tables):
                        s.fail('element table index out of bounds')
                m.elements.append(dict(mode=('active' if offset else 'passive' if flags == 1 else 'declarative'), table=table, offset=offset, functions=funcs))
        elif section == 10:
            n = s.count()
            if n != len(defined):
                s.fail('function/code count mismatch')
            for f in m.functions[len(m.functions)-n:] if n else []:
                body = s.sub(s.u())
                f.body_offset, f.body = body.base, bytes(body.data)
                for _ in range(body.count()):
                    count, t = body.u(), valtype(body)
                    if count > 100000 or len(f.locals) + count > 100000:
                        body.fail('local count resource limit')
                    f.locals.extend([t] * count)
                f.code_offset = body.offset
                f.code = body.take(len(body.data) - body.pos)
        elif section == 11:
            for _ in range(s.count()):
                flags = s.u()
                if flags not in (0, 1, 2):
                    s.fail('invalid data segment flags')
                memory = s.u() if flags == 2 else 0
                offset = initexpr(s) if flags != 1 else None
                if offset:
                    check_init(m, offset, 'i32', s.offset)
                    if memory >= len(m.memories):
                        s.fail('data memory index out of bounds')
                m.segments.append(dict(memory=memory, offset=offset, data=s.take(s.u())))
        elif section == 12:
            m.data_count = s.u()
        s.done()
    if defined and 10 not in seen:
        r.fail('missing code section')
    if len(m.memories) > 1 or len(m.tables) > 1:
        r.fail('multiple memories or tables', 'unsupported')
    if m.data_count is not None and m.data_count != len(m.segments):
        r.fail('data count mismatch')
    for f in m.functions:
        if f.type_index >= len(m.types):
            r.fail('function type index out of bounds')
    export_names = set()
    for name, kind, index in m.exports:
        if name in export_names or kind > 3:
            r.fail('duplicate export name or invalid export kind')
        export_names.add(name)
        target = [m.functions, m.tables, m.memories, m.globals][kind]
        if index >= len(target):
            r.fail('export index out of bounds')
        if kind == 0 and not target[index].name:
            target[index].name = name
    for elem in m.elements:
        if any(i >= len(m.functions) for i in elem['functions']):
            r.fail('element function index out of bounds')
    if m.start is not None:
        if m.start >= len(m.functions) or m.signature(m.functions[m.start]) != Signature([], []):
            r.fail('invalid start function signature or index')
    for nr in names:
        try:
            while nr.pos < len(nr.data):
                kind, sub = nr.byte(), nr.sub(nr.u())
                if kind == 1:
                    for _ in range(sub.count()):
                        idx, name = sub.u(), sub.string()
                        if idx < len(m.functions):
                            m.functions[idx].name = name
                elif kind == 2:
                    for _ in range(sub.count()):
                        idx = sub.u()
                        for _ in range(sub.count()):
                            local, name = sub.u(), sub.string()
                            if idx < len(m.functions):
                                m.functions[idx].local_names[local] = name
        except WasmError as e:
            m.warnings.append(e.diagnostic())
    return m


SIMPLE = {0x00:'unreachable', 0x01:'nop', 0x02:'block', 0x03:'loop', 0x04:'if',
          0x05:'else', 0x0b:'end', 0x0c:'br', 0x0d:'br_if', 0x0e:'br_table',
          0x0f:'return', 0x10:'call', 0x11:'call_indirect', 0x1a:'drop', 0x1b:'select',
          0x20:'local.get', 0x21:'local.set', 0x22:'local.tee', 0x23:'global.get', 0x24:'global.set',
          0x3f:'memory.size', 0x40:'memory.grow', 0x41:'i32.const', 0x42:'i64.const', 0x43:'f32.const', 0x44:'f64.const'}
MEMORY = ('i32.load i64.load f32.load f64.load i32.load8_s i32.load8_u i32.load16_s i32.load16_u '
          'i64.load8_s i64.load8_u i64.load16_s i64.load16_u i64.load32_s i64.load32_u '
          'i32.store i64.store f32.store f64.store i32.store8 i32.store16 i64.store8 i64.store16 i64.store32').split()
SIMPLE.update({0x28+i:n for i,n in enumerate(MEMORY)})
NUMERIC = ('i32.eqz i32.eq i32.ne i32.lt_s i32.lt_u i32.gt_s i32.gt_u i32.le_s i32.le_u i32.ge_s i32.ge_u '
'i64.eqz i64.eq i64.ne i64.lt_s i64.lt_u i64.gt_s i64.gt_u i64.le_s i64.le_u i64.ge_s i64.ge_u '
'f32.eq f32.ne f32.lt f32.gt f32.le f32.ge f64.eq f64.ne f64.lt f64.gt f64.le f64.ge '
'i32.clz i32.ctz i32.popcnt i32.add i32.sub i32.mul i32.div_s i32.div_u i32.rem_s i32.rem_u i32.and i32.or i32.xor i32.shl i32.shr_s i32.shr_u i32.rotl i32.rotr '
'i64.clz i64.ctz i64.popcnt i64.add i64.sub i64.mul i64.div_s i64.div_u i64.rem_s i64.rem_u i64.and i64.or i64.xor i64.shl i64.shr_s i64.shr_u i64.rotl i64.rotr '
'f32.abs f32.neg f32.ceil f32.floor f32.trunc f32.nearest f32.sqrt f32.add f32.sub f32.mul f32.div f32.min f32.max f32.copysign '
'f64.abs f64.neg f64.ceil f64.floor f64.trunc f64.nearest f64.sqrt f64.add f64.sub f64.mul f64.div f64.min f64.max f64.copysign '
'i32.wrap_i64 i32.trunc_f32_s i32.trunc_f32_u i32.trunc_f64_s i32.trunc_f64_u i64.extend_i32_s i64.extend_i32_u i64.trunc_f32_s i64.trunc_f32_u i64.trunc_f64_s i64.trunc_f64_u '
'f32.convert_i32_s f32.convert_i32_u f32.convert_i64_s f32.convert_i64_u f32.demote_f64 f64.convert_i32_s f64.convert_i32_u f64.convert_i64_s f64.convert_i64_u f64.promote_f32 '
'i32.reinterpret_f32 i64.reinterpret_f64 f32.reinterpret_i32 f64.reinterpret_i64 i32.extend8_s i32.extend16_s i64.extend8_s i64.extend16_s i64.extend32_s').split()
SIMPLE.update({0x45+i:n for i,n in enumerate(NUMERIC)})
SAT = 'i32.trunc_sat_f32_s i32.trunc_sat_f32_u i32.trunc_sat_f64_s i32.trunc_sat_f64_u i64.trunc_sat_f32_s i64.trunc_sat_f32_u i64.trunc_sat_f64_s i64.trunc_sat_f64_u'.split()
BULK = {8:('memory.init',2),9:('data.drop',1),10:('memory.copy',2),11:('memory.fill',1),12:('table.init',2),13:('elem.drop',1),14:('table.copy',2)}


@dataclass
class Instruction:
    offset: int
    end_offset: int
    name: str
    args: tuple = ()
    before: tuple = ()
    after: tuple = ()
    frame: object = None
    targets: list = field(default_factory=list)


def decode(f, cancelled=lambda: False):
    r, instructions = Reader(f.code, f.code_offset), []
    while r.pos < len(r.data):
        if len(instructions) % 256 == 0 and cancelled():
            raise WasmError('decoding cancelled', r.offset, 'cancelled')
        if len(instructions) >= 1_000_000:
            r.fail('instruction count resource limit')
        off, op, args = r.offset, r.byte(), ()
        if op == 0xfc:
            sub = r.u()
            if sub < 8:
                name = SAT[sub]
            elif sub in BULK:
                name, count = BULK[sub]
                args = tuple(r.u() for _ in range(count))
            else:
                raise WasmError(f'unsupported 0xfc opcode {sub}', off, 'unsupported')
        elif op not in SIMPLE:
            raise WasmError(f'unsupported opcode 0x{op:02x}', off, 'unsupported')
        else:
            name = SIMPLE[op]
            if name in ('block', 'loop', 'if'):
                b = r.leb(33, True)
                if b == -64:
                    args = ()
                elif b in (-1, -2, -3, -4):
                    args = (TYPES[b & 0x7f],)
                else:
                    raise WasmError('type-index block signature (multi-value)', off, 'unsupported')
            elif name == 'br_table':
                args = tuple(r.u() for _ in range(r.count())) + (r.u(),)
            elif op in (0x0c, 0x0d, 0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x3f, 0x40):
                args = (r.u(),)
            elif name == 'call_indirect':
                args = (r.u(), r.u())
            elif 0x28 <= op <= 0x3e:
                args = (r.u(), r.u())
            elif op in (0x41, 0x42):
                args = (r.leb(32 if op == 0x41 else 64, True),)
            elif op in (0x43, 0x44):
                args = (r.take(4 if op == 0x43 else 8).hex(),)
        instructions.append(Instruction(off, r.offset, name, args))
    return instructions
