#!/usr/bin/env python3
"""Preserve published dependency notices without exposing local build paths."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCE, DIST = ROOT / 'build/source', ROOT / 'dist'
PINS = json.loads((ROOT / 'pins.json').read_text())
LICENSE_SHA = '268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5'
URLS = {
    'wasmtime': 'https://raw.githubusercontent.com/bytecodealliance/wasmtime/84f1cbebd7e68ad6385f3438b12cf8b8f10d2f08/LICENSE',
    'wasm-tools': 'https://raw.githubusercontent.com/bytecodealliance/wasm-tools/76927bf4bdbddf4b15f835c5eddfffbdfe3bdbd5/LICENSE-Apache-2.0_WITH_LLVM-exception',
}

def remote_license(kind):
    cache = ROOT / '.cache' / (kind + '-LICENSE.txt')
    if not cache.exists():
        with urllib.request.urlopen(URLS[kind], timeout=60) as response:
            data = response.read(100000)
        if hashlib.sha256(data).hexdigest() != LICENSE_SHA:
            raise SystemExit('Upstream license checksum mismatch')
        cache.write_bytes(data)
    if hashlib.sha256(cache.read_bytes()).hexdigest() != LICENSE_SHA:
        raise SystemExit('Cached license checksum mismatch')
    return cache.read_text()

def main():
    cargo_home = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo')))
    command = ['cargo', '+' + PINS['rust']['version'], 'tree', '--manifest-path', str(SOURCE / 'Cargo.toml'), '-p', 'yara-x-capi', '--locked', '--offline', '--target', PINS['target'], '--no-default-features', '--features', 'capi', '--edges', 'normal', '--prefix', 'none']
    tree = subprocess.check_output(command, cwd=ROOT, text=True)
    selected = {}
    for line in tree.splitlines():
        match = re.match(r'([\w-]+) v([^\s]+)', line)
        if match:
            key = match.groups()
            path = re.search(r'\((/[^)]+)\)', line)
            selected[key] = path.group(1) if path else selected.get(key)
    if not selected:
        raise SystemExit('Cargo tree produced no package inventory')
    sections = ['Third-party Rust dependency notices\nPublished crate license texts are retained below.\n']
    for (name, version), local in sorted(selected.items()):
        if local:
            directory = Path(local)
            if not directory.resolve().is_relative_to(SOURCE.resolve()):
                raise SystemExit('Unexpected workspace dependency')
        else:
            choices = list((cargo_home / 'registry/src').glob('*/' + name + '-' + version))
            if len(choices) != 1:
                raise SystemExit('Missing or ambiguous downloaded crate: ' + name)
            directory = choices[0]
        package = tomllib.loads((directory / 'Cargo.toml').read_text())['package']
        license_id = package.get('license', 'unknown')
        if isinstance(license_id, dict):
            license_id = tomllib.loads((SOURCE / 'Cargo.toml').read_text())['workspace']['package']['license']
        files = sorted(p for p in directory.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')))
        texts = [p.read_text(errors='replace') for p in files]
        note = ''
        if not texts and local:
            texts = [(SOURCE / 'LICENSE').read_text()]
        if not texts and name.startswith(('cranelift-', 'wasmtime-', 'pulley-')) and license_id == 'Apache-2.0 WITH LLVM-exception':
            texts = [remote_license('wasmtime')]
        if not texts and name in ('wasmparser', 'wasm-encoder') and 'Apache-2.0 WITH LLVM-exception' in license_id:
            texts = [remote_license('wasm-tools')]
        if not texts and (name, version) == ('ascii_tree', '0.1.1') and license_id == 'MIT':
            original = (directory / 'Cargo.toml.orig').read_text()
            grant = 'Permission is hereby granted' + (ROOT / 'LICENSE').read_text().split('Permission is hereby granted', 1)[1]
            note = 'The published crate contains no separate license/copyright file; its declared upstream is unavailable. Original publisher metadata and standard MIT terms are retained without inventing copyright attribution.\n'
            texts = ['Original Cargo.toml.orig (verbatim):\n' + original, 'Standard MIT terms:\n' + grant]
        if not texts:
            raise SystemExit('No preserved license text for ' + name + ' ' + version)
        sections.append('\n===== ' + name + ' ' + version + ' — ' + str(license_id) + ' =====\n' + note + '\n'.join(texts))
    DIST.mkdir(exist_ok=True)
    (DIST / 'THIRD_PARTY_NOTICES.txt').write_text('\n'.join(sections))
    shutil.copyfile(SOURCE / 'LICENSE', DIST / 'YARA-X-LICENSE.txt')
    shutil.copyfile(ROOT / 'NOTICE', DIST / 'NOTICE')
    shutil.copyfile(ROOT / 'LICENSE', DIST / 'BUILDER-LICENSE.txt')
    metadata_path = DIST / 'metadata.json'
    metadata = json.loads(metadata_path.read_text())
    metadata['license_notices'] = {'file': 'THIRD_PARTY_NOTICES.txt', 'ascii_tree_0.1.1_original_license_file_absent': True}
    metadata_path.write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')
    files = sorted(p for p in DIST.iterdir() if p.is_file() and p.name != 'SHA256SUMS')
    (DIST / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in files))
    print('Original dependency notices preserved; distribution checksums sealed.')

if __name__ == '__main__':
    main()
