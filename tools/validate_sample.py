"""Profile representative functions without redistributing a user's Wasm binary."""
import argparse
import hashlib
import json
from pathlib import Path
from time import perf_counter
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from wasm_decompiler import parse_module, decompile_function, Options


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input',type=Path)
    parser.add_argument('--functions',default='')
    parser.add_argument('--output',type=Path,default=Path('dist/sample-review'))
    args = parser.parse_args()
    data = args.input.read_bytes()
    module = parse_module(data)
    indices = [int(i) for i in args.functions.split(',')] if args.functions else sorted({f.index for f in module.functions if not f.imported and len(f.code)<256} & set(range(50)))
    indices = sorted(set(indices) | {i for _,k,i in module.exports if k==0})
    args.output.mkdir(parents=True,exist_ok=True)
    report = dict(input=str(args.input),sha256=hashlib.sha256(data).hexdigest(),functions=len(module.functions),results=[])
    for index in indices:
        start = perf_counter()
        result = decompile_function(module,index)
        stats = dict(index=index,name=result.name,success=result.success,seconds=round(perf_counter()-start,3),lines=len(result.text.splitlines()),gotos=result.text.count('goto '),diagnostics=result.diagnostics)
        report['results'].append(stats)
        (args.output/f'{index}-{result.name}.c').write_text(result.text+'\n')
        print(json.dumps(stats),flush=True)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    return int(any(not row['success'] for row in report['results']))


if __name__ == '__main__':
    raise SystemExit(main())
