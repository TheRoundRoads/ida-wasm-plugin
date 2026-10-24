"""Bit-width-aware, nontrapping expression simplification."""
from .ir import Expr, const


def integer(expr):
    if expr.op != 'const':
        return None
    try:
        return int(str(expr.value).rstrip('ulUL'),0)
    except ValueError:
        return None


def value(n,t):
    return const(str(n & ((1 << int(t[1:]))-1))+('u' if t=='i32' else 'ull'))


def narrow(expr):
    n = integer(expr)
    if n is not None:
        return value(n,'i32')
    if expr.op in ('i64.extend_i32_s','i64.extend_i32_u'):
        return expr.args[0]
    if expr.op.startswith('i64.load') and expr.op != 'i64.load':
        kind = expr.op.split('.')[1]
        mapped = 'load' if kind.startswith('load32') else kind
        return Expr('i32.'+mapped,expr.args)
    if expr.op in ('i64.add','i64.sub','i64.mul','i64.and','i64.or','i64.xor'):
        return Expr('i32'+expr.op[3:],tuple(narrow(a) for a in expr.args))
    return Expr('i32.wrap_i64',(expr,))


def simplify(expr):
    if expr is None:
        return None
    args = tuple(simplify(a) for a in expr.args)
    e = Expr(expr.op,args,expr.value)
    if e.op == 'i32.wrap_i64':
        return narrow(args[0])
    t,_,op = e.op.partition('.')
    if t not in ('i32','i64'):
        return e
    if op == 'eqz':
        inner = args[0]
        while inner.op in ('i64.extend_i32_s','i64.extend_i32_u'):
            inner = inner.args[0]
        if inner.op.endswith('.eqz'):
            return Expr('truth',inner.args)
        if inner.op == 'truth':
            return Expr('i32.eqz',inner.args)
        return Expr(t+'.eqz',(inner,))
    nums = [integer(a) for a in args]
    if op.startswith('extend_i32') and nums and nums[0] is not None:
        n = nums[0] & 0xffffffff
        if op.endswith('_s') and n & 0x80000000:
            n -= 1<<32
        return value(n,t)
    if op in ('add','sub','mul','and','or','xor') and all(n is not None for n in nums):
        a,b = nums
        n = {'add':lambda:a+b,'sub':lambda:a-b,'mul':lambda:a*b,'and':lambda:a&b,'or':lambda:a|b,'xor':lambda:a^b}[op]()
        return value(n,t)
    if len(args)==2 and nums[1]==0 and op in ('add','sub','or','xor'):
        return args[0]
    if len(args)==2 and nums[1]==1 and op == 'mul':
        return args[0]
    return e
