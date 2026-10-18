#!/usr/bin/env python3
"""Prepare checksum-pinned source and an optional pinned Linux NDK installation."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CACHE, BUILD = ROOT / '.cache', ROOT / 'build'
PINS = json.loads((ROOT / 'pins.json').read_text())

def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as file:
        while chunk := file.read(1024 * 1024):
            result.update(chunk)
    return result.hexdigest()

def fetch(url, path, expected):
    if not url.startswith('https://') or not re.fullmatch('[0-9a-f]{64}', expected):
        raise SystemExit('Invalid HTTPS input or SHA-256 pin')
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        partial = path.with_suffix(path.suffix + '.part')
        with urllib.request.urlopen(url, timeout=90) as response, partial.open('wb') as output:
            shutil.copyfileobj(response, output, 1024 * 1024)
        if digest(partial) != expected:
            raise SystemExit('Downloaded archive checksum mismatch: ' + path.name)
        partial.replace(path)
    if digest(path) != expected:
        raise SystemExit('Cached archive checksum mismatch: ' + path.name)

def safe_name(name):
    path = PurePosixPath(name)
    return not path.is_absolute() and '..' not in path.parts and '\\' not in name

def fresh(path):
    if path.parent != BUILD or path.is_symlink():
        raise SystemExit('Refusing unsafe generated-directory cleanup')
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)

def source_extract(archive):
    staging = BUILD / '_source'
    fresh(staging)
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar.getmembers():
            if not safe_name(member.name):
                raise SystemExit('Unsafe source archive member')
        tar.extractall(staging, filter='data')
    items = list(staging.iterdir())
    if len(items) != 1 or not items[0].is_dir():
        raise SystemExit('Unexpected source archive root')
    source = BUILD / 'source'
    fresh(source)
    source.rmdir()
    items[0].rename(source)
    if digest(source / 'Cargo.lock') != PINS['upstream']['cargo_lock_sha256']:
        raise SystemExit('Upstream Cargo.lock does not match its pin')

def ndk_extract(archive):
    staging = BUILD / '_ndk'
    fresh(staging)
    base = staging.resolve()
    links = []
    with zipfile.ZipFile(archive) as package:
        for info in package.infolist():
            if not safe_name(info.filename):
                raise SystemExit('Unsafe NDK archive member')
            destination = staging / info.filename
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                target = package.read(info).decode('utf-8')
                resolved = (destination.parent / target).resolve()
                if os.path.isabs(target) or not resolved.is_relative_to(base):
                    raise SystemExit('Escaping NDK symlink')
                links.append((destination, target))
            elif info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with package.open(info) as source, destination.open('wb') as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                destination.chmod((mode & 0o777) or 0o644)
        for destination, target in links:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.symlink_to(target)
    items = list(staging.iterdir())
    if len(items) != 1 or not items[0].is_dir():
        raise SystemExit('Unexpected NDK archive root')
    ndk = BUILD / 'ndk'
    fresh(ndk)
    ndk.rmdir()
    items[0].rename(ndk)

def main():
    CACHE.mkdir(exist_ok=True)
    BUILD.mkdir(exist_ok=True)
    source = CACHE / 'yara-x-source.tar.gz'
    fetch(PINS['upstream']['url'], source, PINS['upstream']['sha256'])
    source_extract(source)
    external = os.environ.get('ANDROID_NDK_HOME')
    if external:
        ndk = Path(external).resolve()
    else:
        archive = CACHE / 'android-ndk-r30-linux.zip'
        fetch(PINS['ndk']['url'], archive, PINS['ndk']['sha256'])
        ndk_extract(archive)
        ndk = BUILD / 'ndk'
    properties = ndk / 'source.properties'
    if not properties.is_file() or not re.search(r'^Pkg.Revision\s*=\s*' + re.escape(PINS['ndk']['version']) + r'\s*$', properties.read_text(), re.M):
        raise SystemExit('NDK revision does not match its pin')
    tool = ndk / 'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang'
    if not os.access(tool, os.X_OK):
        raise SystemExit('NDK compiler missing executable permission')
    print('Pinned source and NDK prepared; no Android runtime test was performed.')

if __name__ == '__main__':
    main()
