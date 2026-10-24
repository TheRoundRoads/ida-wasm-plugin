"""Fetch a pinned public corpus and verify every file against its manifest."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    manifest = json.loads((ROOT/'samples/public/manifest.json').read_text())
    for item in manifest['files']:
        data = urllib.request.urlopen(item['url'], timeout=30).read()
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise RuntimeError('SHA-256 mismatch: '+item['path'])
        destination = ROOT/'samples/public'/item['path']
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(data)
        print(item['path'])


if __name__ == '__main__':
    main()
