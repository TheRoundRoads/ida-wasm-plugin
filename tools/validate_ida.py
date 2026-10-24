"""Exercise the real IDA adapter in isolated temporary databases."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ida-dir',type=Path,default=Path('/home/kali/ida-pro-9.0'))
    parser.add_argument('--functions',help='comma-separated indices for a large module; otherwise check every function')
    parser.add_argument('--follow',help='caller:callee indices for an explicit navigation regression')
    parser.add_argument('--timeout',type=int,default=120)
    parser.add_argument('--gui',action='store_true',help='exercise offscreen GUI widgets as well')
    parser.add_argument('samples',nargs='*',type=Path,default=[ROOT/'samples/core.wasm'])
    args = parser.parse_args()
    for sample in args.samples:
        with tempfile.TemporaryDirectory(prefix='ida-wasm-check-') as work:
            work = Path(work)
            report = work/'report.json'
            (work/'user').mkdir()
            registry = Path.home()/'.idapro/ida.reg'
            if registry.is_file():
                shutil.copy2(registry,work/'user/ida.reg')
            env = dict(os.environ,WASM_TEST_FOLLOW=args.follow or '',WASM_TEST_FUNCTIONS=args.functions or '',IDAUSR=str(work/'user'),WASM_PLUGIN_ROOT=str(ROOT),WASM_TEST_REPORT=str(report),WASM_TEST_GUI=str(int(args.gui)),QT_QPA_PLATFORM='offscreen')
            cmd = [str(args.ida_dir/('ida' if args.gui else 'idat')),'-A','-L'+str(work/'ida.log'),'-S'+str(ROOT/'tools/ida_check.py'),'-o'+str(work/'sample.i64'),str(sample.resolve())]
            p = subprocess.run(cmd,env=env,capture_output=True,timeout=args.timeout)
            if not report.is_file():
                raise RuntimeError(p.stdout.decode(errors='replace')+p.stderr.decode(errors='replace')+(work/'ida.log').read_text(errors='replace'))
            result = json.loads(report.read_text())
            print(sample.name,json.dumps(result,indent=2))
            if not result['ok'] or p.returncode:
                raise SystemExit(1)
            # Reopen the saved database in a fresh IDA process.
            env['WASM_TEST_REOPEN'] = '1'
            reopen_cmd = [str(args.ida_dir/'idat'),'-A','-L'+str(work/'reopen.log'),'-S'+str(ROOT/'tools/ida_check.py'),str(work/'sample.i64')]
            env['WASM_TEST_GUI'] = '0'
            reopened = subprocess.run(reopen_cmd,env=env,capture_output=True,timeout=args.timeout)
            result = json.loads(report.read_text())
            if not result['ok'] or reopened.returncode:
                print(json.dumps(result,indent=2))
                raise SystemExit(1)
            print('  fresh process database reopen: passed')


if __name__ == '__main__':
    main()
