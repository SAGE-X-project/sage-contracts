"""Resolve one fixed public compiler as data; never run upstream scripts."""
from pathlib import Path
import hashlib
import urllib.request

ROOT = Path(__file__).resolve().parent
URL = 'https://binaries.soliditylang.org/wasm/soljson-v0.8.20+commit.a1b79de6.js'
DIGEST = '5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657'

def main():
    target = ROOT / 'evidence/soljson.cjs'
    target.parent.mkdir(parents=True, exist_ok=True)
    cache = ROOT.parents[2] / 'research/registry-ed25519/evidence/soljson.cjs'
    if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == DIGEST:
        return
    if cache.is_file() and hashlib.sha256(cache.read_bytes()).hexdigest() == DIGEST:
        data = cache.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=60) as response:
            data = response.read(16777217)
    if len(data) > 16777216 or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('Compiler identity or size mismatch')
    target.write_bytes(data)

if __name__ == '__main__':
    main()
