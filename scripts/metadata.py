#!/usr/bin/env python3
"""Write deterministic public build metadata and checksums for generated assets."""
from pathlib import Path
import hashlib
import json
import os

ROOT = Path(__file__).resolve().parents[1]
PINS = json.loads((ROOT / 'pins.json').read_text())
DIST = ROOT / 'dist'
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

metadata = {
    'upstream': {key: PINS['upstream'][key] for key in ('version', 'commit')},
    'source_archive_sha256': PINS['upstream']['sha256'],
    'cargo_lock_sha256': PINS['upstream']['cargo_lock_sha256'],
    'patch_sha256': sha(ROOT / 'patches/android-capi.patch'),
    'binary_sha256': sha(DIST / 'libyara_x_capi.so'),
    'binary_size_bytes': (DIST / 'libyara_x_capi.so').stat().st_size,
    'rust': PINS['rust']['version'], 'ndk': PINS['ndk']['version'],
    'android_api': PINS['android_api'], 'abi': PINS['abi'], 'target': PINS['target'],
    'builder_version': PINS['builder_version'], 'builder_commit': os.environ.get('GITHUB_SHA'),
    'features': ['capi', 'constant-folding', 'exact-atoms', 'fast-regexp'],
    'default_modules_enabled': False,
    'profile': {'release': True, 'opt_level': 1, 'codegen_units': 16, 'debug': 0, 'strip': 'symbols', 'incremental': False, 'jobs': 2},
    'linker': 'aarch64-linux-android24-clang',
    'soname': 'libyara_x_capi.so', 'max_page_size': 16384,
    'path_remapping': {'source': '/src', 'cargo_home': '/cargo', 'target': '/target', 'workspace': '/workspace'},
    'android_runtime_tested_by_this_workflow': False,
}
(DIST / 'metadata.json').write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')
files = sorted(path for path in DIST.iterdir() if path.is_file() and path.name != 'SHA256SUMS')
(DIST / 'SHA256SUMS').write_text(''.join(sha(path) + '  ' + path.name + '\n' for path in files))
