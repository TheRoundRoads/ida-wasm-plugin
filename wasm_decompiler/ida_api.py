"""IDAPython-facing Wasm decompilation API; no Hex-Rays backend required."""
from dataclasses import dataclass
from pathlib import Path

import ida_funcs
import ida_idaapi

from . import WasmError
from .decompile import export_text as render_module
from .ida_plugin import get_session


@dataclass(frozen=True)
class WasmPseudocodeLine:
    """A plain pseudocode line and its source addresses, if any."""

    line: str
    ea: int
    eas: tuple
    wasm_offsets: tuple


class WasmPrinter:
    """Text receiver for WasmCFunc.print_func, similar to qstring_printer_t."""

    def __init__(self, func, tags=False):
        if tags:
            raise ValueError('Wasm pseudocode does not provide Hex-Rays color tags')
        self.func = func
        self.with_tags = tags
        self.s = ''

    def get_s(self):
        return self.s


@dataclass(frozen=True)
class WasmCFunc:
    """Snapshot of one Wasm function's decompilation."""

    entry_ea: int
    function_index: int
    name: str
    text: str
    diagnostics: tuple
    symbols: dict
    helpers: tuple
    source_map: dict
    ea_map: dict

    def __str__(self):
        return self.text

    def get_pseudocode(self):
        return tuple(
            WasmPseudocodeLine(line, (eas or (ida_idaapi.BADADDR,))[0], eas,
                               self.source_map.get(number, ()))
            for number, line in enumerate(self.text.splitlines(), 1)
            for eas in (self.ea_map.get(number, ()),)
        )

    def get_warnings(self):
        return self.diagnostics

    def print_func(self, vp):
        if not isinstance(vp, WasmPrinter) or vp.func is not self:
            raise TypeError('print_func requires a WasmPrinter bound to this result')
        vp.s = self.text


def _index_for(session, func):
    if isinstance(func, ida_funcs.func_t):
        ea = func.start_ea
    elif isinstance(func, int) and not isinstance(func, bool):
        ea = func
    else:
        raise TypeError('func must be an effective address or ida_funcs.func_t')
    if ea < 0 or ea == ida_idaapi.BADADDR:
        raise WasmError('invalid function address')
    return session.function_at(ea)


def _result(session, index):
    result = session.result(index)
    for diagnostic in result.diagnostics:
        if diagnostic['code'] != 'info':
            raise WasmError(diagnostic['message'], diagnostic['offset'], diagnostic['code'])
    return result


def _snapshot(session, result):
    function = session.module.functions[result.function_index]
    entry_ea = session.ea(function.code_offset)
    if entry_ea == ida_idaapi.BADADDR:
        raise WasmError('function has no mapped IDA address', function.code_offset)
    source_map = {line: tuple(offsets) for line, offsets in result.source_map.items()}
    ea_map = {
        line: tuple(ea for offset in offsets
                    if (ea := session.ea(offset)) != ida_idaapi.BADADDR)
        for line, offsets in source_map.items()
    }
    return WasmCFunc(
        entry_ea, result.function_index, result.name, result.text,
        tuple(dict(diagnostic) for diagnostic in result.diagnostics),
        {name: dict(symbol) for name, symbol in result.symbols.items()},
        tuple(result.helpers), source_map, ea_map,
    )


def _indices(session, funcs):
    if funcs is None:
        return [function.index for function in session.module.functions if not function.imported]
    return [_index_for(session, func) for func in funcs]


def decompile(func):
    """Decompile the Wasm function containing an IDA address or func_t."""
    session = get_session()
    return _snapshot(session, _result(session, _index_for(session, func)))


def decompile_many(funcs=None):
    """Return decompilations in input order, or all defined functions."""
    session = get_session()
    return [_snapshot(session, _result(session, index)) for index in _indices(session, funcs)]


def export_text(funcs=None):
    """Render selected functions and module declarations as one text document."""
    session = get_session()
    results = [_result(session, index) for index in _indices(session, funcs)]
    return render_module(session.module, results, session.names(), session.global_names())


def export_file(path, funcs=None):
    """Write UTF-8 pseudocode to path and return that Path."""
    destination = Path(path)
    destination.write_text(export_text(funcs), encoding='utf-8')
    return destination
