import argparse
import json
from pathlib import Path
import sys
from . import parse_module, WasmError, Options, decompile_function, decompile_module, export_text


def main():
    parser = argparse.ArgumentParser(description='Decompile WebAssembly into C-like pseudocode')
    parser.add_argument('input', type=Path)
    parser.add_argument('-f','--function', type=int, help='function index including imports')
    parser.add_argument('-o','--output', type=Path)
    parser.add_argument('--json', action='store_true', help='include source maps, symbols and diagnostics')
    parser.add_argument('--stack-pointer', type=int, help='mutable i32 global index')
    parser.add_argument('--no-stack-recovery', action='store_true')
    parser.add_argument('--no-optimize', action='store_true')
    parser.add_argument('--explicit-wasm',action='store_true',help='show semantic helpers instead of C notation')
    args = parser.parse_args()
    try:
        module = parse_module(args.input.read_bytes())
        options = Options(args.stack_pointer, not args.no_stack_recovery, not args.no_optimize, not args.explicit_wasm)
        results = ([decompile_function(module, args.function, options)] if args.function is not None else decompile_module(module,options))
        output = json.dumps(dict(results=[r.to_dict() for r in results], warnings=module.warnings),indent=2) if args.json else export_text(module,results)
        if args.output:
            args.output.write_text(output,encoding='utf-8')
        else:
            print(output)
        if not args.json:
            for result in results:
                for diagnostic in result.diagnostics:
                    print(json.dumps(dict(function=result.function_index,**diagnostic)),file=sys.stderr)
        return int(any(not r.success for r in results))
    except (WasmError,OSError) as exc:
        diagnostic = exc.diagnostic() if isinstance(exc,WasmError) else dict(code='io',message=str(exc))
        print(json.dumps(dict(diagnostics=[diagnostic])),file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
