#!/usr/bin/env python3
"""Publish only the fixed, checksum-verified distribution assets; never execute them."""
from pathlib import Path
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
ASSETS = {'libyara_x_capi.so', 'yara_x.h', 'metadata.json', 'SHA256SUMS', 'THIRD_PARTY_NOTICES.txt', 'YARA-X-LICENSE.txt', 'NOTICE', 'BUILDER-LICENSE.txt'}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('Unexpected GitHub API redirect')

OPENER = urllib.request.build_opener(NoRedirect)

def validate():
    pins = json.loads((ROOT / 'pins.json').read_text())
    metadata = json.loads((DIST / 'metadata.json').read_text())
    if metadata['upstream'] != {key: pins['upstream'][key] for key in ('version', 'commit')}:
        raise RuntimeError('Metadata upstream mismatch')
    for key in ('abi', 'target', 'android_api', 'builder_version'):
        if metadata[key] != pins[key]:
            raise RuntimeError('Metadata pin mismatch: ' + key)
    if not re.fullmatch(r'\d+\.\d+\.\d+-android\.\d+', pins['builder_version']):
        raise RuntimeError('Invalid release version')
    if {file.name for file in DIST.iterdir()} != ASSETS:
        raise RuntimeError('Distribution does not match exact allowed asset inventory')
    if (DIST / 'SHA256SUMS').stat().st_size > 32768:
        raise RuntimeError('Oversized checksum manifest')
    checksums = {}
    for line in (DIST / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        if not match or match.group(2) in checksums:
            raise RuntimeError('Malformed checksum manifest')
        checksums[match.group(2)] = match.group(1)
    if set(checksums) != ASSETS - {'SHA256SUMS'}:
        raise RuntimeError('Checksum inventory mismatch')
    for name in sorted(ASSETS):
        file = DIST / name
        if not file.is_file() or file.is_symlink() or file.stat().st_size > 40 * 1024 * 1024:
            raise RuntimeError('Invalid release asset: ' + name)
        if name != 'SHA256SUMS' and hashlib.sha256(file.read_bytes()).hexdigest() != checksums[name]:
            raise RuntimeError('Asset checksum mismatch: ' + name)
    return pins, metadata, checksums

def request(url, token, method='GET', body=None, missing_ok=False, binary=False):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.netloc not in ('api.github.com', 'uploads.github.com'):
        raise RuntimeError('Unexpected API origin')
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'android-yara-engine', 'Authorization': 'Bearer ' + token}
    if body is not None:
        headers['Content-Type'] = 'application/octet-stream' if binary else 'application/json'
    try:
        with OPENER.open(urllib.request.Request(url, data=body, headers=headers, method=method), timeout=90) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        if missing_ok and error.code == 404:
            return None
        raise RuntimeError('GitHub API returned HTTP ' + str(error.code)) from None
    except urllib.error.URLError:
        raise RuntimeError('GitHub API connection failed') from None

def main():
    pins, metadata, checksums = validate()
    if sys.argv[1:] == ['--check-only']:
        print('Exact release asset inventory and checksums verified; no API operation performed.')
        return
    if sys.argv[1:]:
        raise RuntimeError('Unknown argument')
    token = os.environ.get('GITHUB_TOKEN')
    repo = os.environ.get('GITHUB_REPOSITORY', '')
    commit = os.environ.get('GITHUB_SHA', '')
    if not token or not re.fullmatch(r'[\w.-]+/[\w.-]+', repo) or not re.fullmatch('[0-9a-f]{40}', commit):
        raise RuntimeError('Missing job-scoped GitHub identity or token')
    if os.environ.get('GITHUB_REF') != 'refs/heads/main' or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        raise RuntimeError('Publishing is restricted to manual dispatch from main')
    if metadata.get('builder_commit') != commit:
        raise RuntimeError('Build artifact does not belong to this workflow commit')
    tag = 'v' + pins['builder_version']
    base = 'https://api.github.com/repos/' + repo
    if request(base + '/releases/tags/' + tag, token, missing_ok=True) is not None:
        raise RuntimeError('Release already exists; refusing overwrite')
    if request(base + '/git/ref/tags/' + tag, token, missing_ok=True) is not None:
        raise RuntimeError('Tag already exists; refusing overwrite')
    payload = {'tag_name': tag, 'target_commitish': commit, 'name': tag, 'draft': True, 'prerelease': False,
               'body': 'Community build of YARA-X ' + pins['upstream']['version'] + ' C API for Android arm64-v8a / API 24+.\n\nIncludes no JNI wrapper, rule pack, or application. ELF checks are not Android runtime validation. See metadata, SHA256SUMS and original third-party license notices.'}
    release = request(base + '/releases', token, 'POST', json.dumps(payload).encode())
    identifier = release['id']
    upload = release['upload_url'].split('{', 1)[0]
    expected = 'https://uploads.github.com/repos/' + repo + '/releases/' + str(identifier) + '/assets'
    if upload != expected:
        raise RuntimeError('Unexpected release upload endpoint; draft retained')
    for name in sorted(ASSETS):
        data = (DIST / name).read_bytes()
        result = request(upload + '?name=' + urllib.parse.quote(name), token, 'POST', data, binary=True)
        if result.get('size') != len(data) or (result.get('digest') and result['digest'] != 'sha256:' + hashlib.sha256(data).hexdigest()):
            raise RuntimeError('Uploaded asset verification failed; draft retained')
    request(base + '/releases/' + str(identifier), token, 'PATCH', json.dumps({'draft': False}).encode())
    print('Published ' + tag + ' with eight verified assets.')

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Publish stopped: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
