"""Control-flow-aware cleanup of the register IR before presentation."""
from collections import deque
from dataclasses import replace
import re
from .ir import Expr, Statement

REGISTER = re.compile(r'v\d+_(?:i32|i64|f32|f64)$')


def variables(expr):
    if expr is None:
        return set()
    if expr.op == 'var':
        return {expr.value}
    return set().union(*(variables(a) for a in expr.args)) if expr.args else set()


def structure(statements):
    """Pair generated braces and collect switch cases, including else arms."""
    frames, starts, ends = [], {}, {}
    for i,s in enumerate(statements):
        text = s.prefix
        if text == '} else {':
            frames[-1]['else'] = i
        elif text in ('}', '} while (0);'):
            f = frames.pop()
            f['end'] = i
            starts[f['start']], ends[i] = f,f
        elif text in ('{','do {') or (s.expr and s.suffix.endswith('{')) or text == 'while (1) {':
            kind = ('if' if text == 'if (' else 'switch' if text == 'switch (' else
                    'loop' if text in ('do {','while (1) {','while (') else 'block')
            frames.append(dict(start=i,kind=kind,cases=[]))
        elif text.startswith(('case ','default:')):
            for f in reversed(frames):
                if f['kind'] == 'switch':
                    f['cases'].append(i)
                    break
    if frames:
        raise ValueError('unbalanced generated statement blocks')
    return starts,ends


def graph(statements):
    starts,ends = structure(statements)
    labels = {s.prefix[:-2]:i for i,s in enumerate(statements) if s.prefix.endswith(':;')}
    else_ends = {f['else']:f['end'] for f in starts.values() if 'else' in f}
    successors = []
    for i,s in enumerate(statements):
        edge = [i+1] if i+1 < len(statements) else []
        if s.prefix.startswith('goto '):
            edge = [labels[s.prefix[5:-1]]]
        elif s.prefix.startswith('return') or (s.expr and s.expr.op == 'trap'):
            edge = []
        elif i in starts:
            f = starts[i]
            if f['kind'] == 'if':
                edge += [f.get('else',f['end'])+1]
            elif f['kind'] == 'switch':
                edge = [case+1 for case in f['cases']]
        elif s.prefix == '} else {':
            edge = [else_ends[i]+1]
        successors.append([x for x in edge if x < len(statements)])
    return successors


def liveness(statements, cancelled=lambda:False):
    edges = graph(statements)
    predecessors = [[] for _ in statements]
    for i,targets in enumerate(edges):
        for t in targets:
            predecessors[t].append(i)
    reads = [variables(s.expr) for s in statements]
    inside,after = [set() for _ in statements],[set() for _ in statements]
    work = deque(reversed(range(len(statements))))
    queued = set(work)
    visits = 0
    while work:
        visits += 1
        if visits % 1024 == 0 and cancelled():
            from .binary import WasmError
            raise WasmError('data-flow analysis cancelled',code='cancelled')
        i = work.popleft()
        queued.discard(i)
        out = set().union(*(inside[t] for t in edges[i])) if edges[i] else set()
        new = reads[i] | (out - {statements[i].dest})
        after[i] = out
        if new != inside[i]:
            inside[i] = new
            for p in predecessors[i]:
                if p not in queued:
                    work.append(p)
                    queued.add(p)
    return inside,after


def removable(name):
    return bool(name) and not name.startswith('global_')


def cleanup(statements, cancelled=lambda:False):
    """Eliminate dead writes, then forward single-use register expressions safely.

    Dependencies cannot change between definition and use. Loads and calls move
    only into an immediately following consumer with no competing effects or lazy
    selection. This preserves eager evaluation and the ordering of traps/calls.
    """
    if not statements:
        return statements,set()
    for iteration in range(3):
        if cancelled():
            from .binary import WasmError
            raise WasmError('optimization cancelled',code='cancelled')
        from .simplify import simplify
        for s in statements:
            s.expr = simplify(s.expr)
        initial,live = liveness(statements,cancelled)
        clean = []
        for s,out in zip(statements,live):
            s.live_after = out
            if removable(s.dest) and s.dest not in out:
                if s.expr.pure:
                    continue
                # A discarded call/load still executes and can trap.
                s.dest = ''
            clean.append(s)
        statements = clean
        result = []
        for s in statements:
            # Look through a bounded straight-line window; never cross a label or branch.
            if s.expr:
                for j in range(len(result)-1,max(-1,len(result)-33),-1):
                    prev = result[j]
                    if prev.boundary:
                        break
                    if not prev.dest or not REGISTER.fullmatch(prev.dest) or not prev.expr:
                        continue
                    target = prev.dest
                    if target in s.live_after and s.dest != target:
                        continue
                    if s.expr.count(target) != 1 or prev.expr.depth+s.expr.depth > 48:
                        continue
                    between = result[j+1:]
                    deps = variables(prev.expr)
                    if any(p.dest == target or p.dest in deps or (p.expr and p.expr.count(target)) for p in between):
                        continue
                    if any(p.expr and not p.expr.pure for p in between) and any(x.startswith('global_') for x in deps):
                        continue
                    if any(x.startswith('global_') for x in deps) and any(not a.pure for a in s.expr.args):
                        continue
                    if not prev.expr.pure:
                        # Effectful operands cannot become conditional or reorder against another operand.
                        if between or s.expr.op == 'select' or any(not a.pure for a in s.expr.args):
                            continue
                    s.expr = s.expr.replace(target,prev.expr)
                    s.origins |= prev.origins | {prev.offset}
                    result.pop(j)
            result.append(s)
        statements = result
    initial,_ = liveness(statements,cancelled)
    return statements,initial[0] if initial else set()


def negate(expr):
    if expr.op == 'not':
        return expr.args[0]
    if expr.op.endswith('.eqz'):
        return expr.args[0]
    inverse = {'eq':'ne','ne':'eq','lt_s':'ge_s','lt_u':'ge_u','gt_s':'le_s','gt_u':'le_u',
               'le_s':'gt_s','le_u':'gt_u','ge_s':'lt_s','ge_u':'lt_u'}
    t,_,op = expr.op.partition('.')
    if t in ('i32','i64') and op in inverse:
        return Expr(t+'.'+inverse[op],expr.args)
    return Expr('not',(expr,))


def copy_stmt(s, **kwargs):
    return replace(s, origins=set(s.origins), **kwargs)


def prettify(statements):
    """Recover simple natural loops and forward conditional regions.

    Multi-level exits retain gotos. No duplication or speculative condition
    hoisting occurs, so all side effects stay in their original order.
    """
    statements = [copy_stmt(s) for s in statements]
    starts,ends = structure(statements)
    # Wasm blocks have no C-local declarations; remove their visual scaffolding.
    remove,delta = set(),[0]*(len(statements)+1)
    for f in starts.values():
        if f['kind'] == 'block' or (f['kind']=='loop' and not statements[f['start']+1].prefix.startswith('label_loop_')):
            remove.update((f['start'],f['end']))
            delta[f['start']+1] -= 1
            delta[f['end']] += 1
    depth = 0
    flat = []
    for i,s in enumerate(statements):
        depth += delta[i]
        s.indent += depth
        if i not in remove:
            flat.append(s)
    statements = flat
    starts,_ = structure(statements)
    remove, extras, prefix_extras = set(), {}, {}
    for f in sorted(starts.values(), key=lambda x:x['start'], reverse=True):
        if f['kind'] != 'loop':
            continue
        start,end = f['start'],f['end']
        label_index = start+1
        label = statements[label_index].prefix if label_index < end else ''
        loop_label = label[:-2] if label.startswith('label_loop_') else None
        body_start = label_index+1 if loop_label else label_index
        guard = starts.get(body_start)
        tail = statements[end-1] if end > body_start else None
        # while (condition) { body } with a single guard and unconditional backedge.
        canonical = False
        if loop_label and guard and guard['kind'] == 'if' and guard['end'] == body_start+2 and 'else' not in guard:
            exit_jump = statements[body_start+1].prefix
            if exit_jump.startswith('goto ') and tail and tail.prefix == f'goto {loop_label};':
                target = exit_jump[5:-1]+':;'
                # Exiting the immediately following label is exactly loop termination.
                if end+1 < len(statements) and statements[end+1].prefix == target:
                    statements[start].expr = negate(statements[body_start].expr)
                    statements[start].prefix,statements[start].suffix = 'while (',') {'
                    statements[start].origins |= statements[body_start].origins
                    remove.update((body_start,body_start+1,body_start+2,end-1))
                    canonical = True
        if not canonical:
            # do/while(0) faithfully preserves one-shot Wasm loops. Recover an
            # ordinary infinite loop only when its final edge unconditionally repeats.
            if loop_label and tail and tail.prefix == f'goto {loop_label};':
                statements[start].prefix = 'while (1) {'
                remove.add(end-1)
                canonical = True
        if not canonical and loop_label:
            statements[start].prefix = 'while (1) {'
            extras[end] = copy_stmt(statements[end],prefix='break;',indent=statements[end].indent+1)
            canonical = True
        if canonical:
            statements[end].prefix = '}'
            for i in range(body_start,end):
                if statements[i].prefix == f'goto {loop_label};' and i not in remove:
                    nested = any(g['kind']=='loop' and start < g['start'] < i < g['end'] < end for g in starts.values())
                    if not nested:
                        statements[i].prefix = 'continue;'
            if any(s.prefix == f'goto {loop_label};' and i not in remove for i,s in enumerate(statements)):
                # A nested-loop jump must re-evaluate the outer loop condition.
                # Keep its label before the while header, never after the guard.
                prefix_extras[start] = copy_stmt(statements[label_index],indent=statements[start].indent)
            remove.add(label_index)
    expanded = []
    for i,s in enumerate(statements):
        if i in prefix_extras:
            expanded.append(prefix_extras[i])
        if i in extras:
            expanded.append(extras[i])
        if i not in remove:
            expanded.append(s)
    statements = expanded
    # A unique forward exit becomes a conditional region instead of an extra label.
    for _ in range(4):
        starts,_ = structure(statements)
        labels = {s.prefix[:-2]:i for i,s in enumerate(statements) if s.prefix.endswith(':;')}
        counts = {}
        for s in statements:
            if s.prefix.startswith('goto '):
                counts[s.prefix[5:-1]] = counts.get(s.prefix[5:-1],0)+1
        changed = False
        for i,f in starts.items():
            if f['kind'] != 'if' or f['end'] != i+2 or 'else' in f:
                continue
            branch = statements[i+1].prefix
            if not branch.startswith('goto '):
                continue
            name = branch[5:-1]
            j = labels.get(name,-1)
            if j <= i+2 or counts.get(name) != 1 or statements[j].indent != statements[i].indent:
                continue
            # Wrapping may change the meaning of break/continue only for loops,
            # which this transformation does not introduce.
            statements[i].expr = negate(statements[i].expr)
            for s in statements[i+3:j]:
                s.indent += 1
            close = copy_stmt(statements[i+2],indent=statements[i].indent)
            statements = statements[:i+1]+statements[i+3:j]+[close]+statements[j+1:]
            changed = True
            break
        if not changed:
            break
    statements = recover_switches(statements)
    # Remove now-unreferenced labels, and empty fall-through returns in void functions.
    references = {s.prefix[5:-1] for s in statements if s.prefix.startswith('goto ')}
    statements = [s for s in statements if not (s.prefix.endswith(':;') and s.prefix[:-2] not in references)]
    return statements


def recover_switches(statements):
    """Place forward branch-table destinations directly beneath C case labels.

    Keep destination labels when other edges still use them. Original sequential
    fallthrough is retained, including Go's generated resume-state switches.
    """
    for _ in range(16):
        starts,_ = structure(statements)
        labels = {s.prefix[:-2]:i for i,s in enumerate(statements) if s.prefix.endswith(':;')}
        changed = False
        for i,f in sorted(starts.items(), reverse=True):
            if f['kind'] != 'switch':
                continue
            base = statements[i].indent
            parents = [g['end'] for g in starts.values() if g['start'] < i < g['end']]
            stop = min(parents) if parents else len(statements)
            if stop > f['end']+1 and statements[stop-1].prefix == 'break;' and statements[stop-1].indent == base:
                stop -= 1
            destinations,valid = {},True
            for k,case in enumerate(f['cases']):
                next_case = f['cases'][k+1] if k+1 < len(f['cases']) else f['end']
                if next_case != case+2 or not statements[case+1].prefix.startswith('goto '):
                    valid = False
                    break
                target = labels.get(statements[case+1].prefix[5:-1],-1)
                if not f['end'] < target < stop or statements[target].indent != base:
                    valid = False
                    break
                destinations.setdefault(target,[]).append(statements[case])
            if not valid or not destinations:
                continue
            first = min(destinations)
            if any(s.expr or s.dest or not s.prefix.endswith(':;') for s in statements[f['end']+1:first]):
                continue
            # A break aimed at the enclosing loop must remain outside this switch.
            if any(s.prefix=='break;' and s.indent==base for s in statements[first:stop]):
                continue
            moved = []
            for j in range(f['end']+1,stop):
                for case in destinations.get(j,[]):
                    moved.append(copy_stmt(case,indent=base+1))
                moved.append(copy_stmt(statements[j],indent=statements[j].indent+2))
            close = copy_stmt(statements[f['end']],indent=base)
            statements = statements[:i+1]+moved+[close]+statements[stop:]
            changed = True
            break
        if not changed:
            break
    return statements
