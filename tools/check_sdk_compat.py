"""Check public API presence in official newer IDA SDK snapshots.

This is a source-compatibility check, not a substitute for running those IDA
versions. The plugin uses no native ABI offsets or hard-coded SDK version gates.
"""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
APIS = {
    'bytes.hpp':['find_free_chunk','create_data','put_bytes','get_bytes','set_cmt'],
    'segment.hpp':['add_segm','get_segm_by_name','get_segment_cmt','set_segment_cmt','getseg'],
    'name.hpp':['set_name','get_name','get_name_ea'],
    'xref.hpp':['add_dref','del_dref','add_cref','del_cref'],
    'loader.hpp':['get_fileregion_ea','get_fileregion_offset'],
    'kernwin.hpp':['ask_addr','choose_xref','activate_widget','register_action','get_action_shortcut'],
    'typeinf.hpp':['apply_tinfo','BTF_UINT32','BTF_UINT64','BTF_FLOAT','BTF_DOUBLE'],
}
VERSIONS = ['v9.2.0-release','v9.3.0-release','v9.4.0-release']


def check(job):
    version,header = job
    url=f'https://raw.githubusercontent.com/HexRaysSA/ida-sdk/{version}/src/include/{header}'
    text=urllib.request.urlopen(url,timeout=30).read().decode()
    missing=[api for api in APIS[header] if not re.search(r'\b'+api+r'\b',text)]
    return dict(version=version,header=header,url=url,missing=missing)


if __name__ == '__main__':
    with ThreadPoolExecutor(max_workers=7) as pool:
        rows=list(pool.map(check,[(v,h) for v in VERSIONS for h in APIS]))
    output=ROOT/'dist/sdk-api-compatibility.json'
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(dict(kind='header API availability; not runtime validation',results=rows),indent=2)+'\n')
    for version in VERSIONS:
        missing={r['header']:r['missing'] for r in rows if r['version']==version and r['missing']}
        print(version,missing or 'all selected public APIs present')
    raise SystemExit(int(any(r['missing'] for r in rows)))
