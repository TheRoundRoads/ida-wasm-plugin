"""Build an archive with a single entry-point file at the plugins-directory level."""
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.3.0'


def build(output=None):
    output = Path(output) if output else ROOT/f'dist/ida-wasm-decompiler-{VERSION}.zip'
    output.parent.mkdir(parents=True,exist_ok=True)
    files = [(ROOT/'ida_wasm_decompiler.py','ida_wasm_decompiler.py')]
    files += [(p,p.relative_to(ROOT).as_posix()) for p in sorted((ROOT/'wasm_decompiler').glob('*.py'))]
    files += [(ROOT/name,'wasm_decompiler/'+name) for name in ('README.md','LICENSE','THIRD_PARTY.md')]
    files += [(p,'wasm_decompiler/docs/'+p.name) for p in sorted((ROOT/'docs').glob('*.md'))]
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
        for path,destination in files:
            archive.write(path,destination)
    return output


if __name__ == '__main__':
    print(build())
