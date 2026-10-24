"""Run inside IDA with -S to report native Hex-Rays availability honestly.

Set WASM_HEXRAYS_REPORT to an output JSON path. Run once on a Wasm database and
once on a supported native control database to distinguish architecture support
from a missing/unavailable native engine. Does not patch any Hex-Rays API.
"""
import json
import os
from pathlib import Path
import traceback

import ida_auto
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_loader
import ida_pro
import idautils

ida_auto.auto_wait()
report = dict(ida_version=ida_kernwin.get_kernel_version(),processor=ida_ida.inf_get_procname())
try:
    report['initial_init'] = ida_hexrays.init_hexrays_plugin()
    if not report['initial_init']:
        report['explicit_x64_backend_loaded'] = ida_loader.load_plugin('hexx64') is not None
    report['initialized'] = ida_hexrays.init_hexrays_plugin()
    if report['initialized']:
        report['hexrays_version'] = ida_hexrays.get_hexrays_version()
        entries = list(idautils.Functions())
        ea = next((ea for ea in entries if ida_funcs.get_func_name(ea) in ('native_probe','main','run','add')),entries[0])
        failure = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile(ea,failure)
        report['result_type'] = str(type(cfunc))
        report['pseudocode'] = str(cfunc) if cfunc else None
        report['failure'] = str(failure)
except Exception:
    report['error'] = traceback.format_exc()
Path(os.environ['WASM_HEXRAYS_REPORT']).write_text(json.dumps(report,indent=2)+'\n')
ida_pro.qexit(0)
