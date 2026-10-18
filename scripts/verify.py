#!/usr/bin/env python3
import hashlib,json,pathlib,re,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1]; D=R/'dist'; p=json.loads((R/'pins.json').read_text())
so=D/'libyara_x_capi.so'; hdr=D/'yara_x.h'; meta=json.loads((D/'metadata.json').read_text())
if not so.is_file() or not hdr.is_file() or hdr.stat().st_size==0: raise SystemExit('Missing shared library or nonempty public header')
ndk=pathlib.Path(__import__('os').environ.get('ANDROID_NDK_HOME',str(R/'build/ndk')))
readelf=ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf'
def run(*a): return subprocess.check_output([str(readelf),*a,str(so)],text=True,stderr=subprocess.STDOUT)
h=run('-h')
if 'ELF64' not in h or 'little endian' not in h.lower() or not re.search(r'Machine:\s+AArch64',h): raise SystemExit('Not ELF64 little-endian AArch64')
ph=run('-W','-l'); aligns=[int(line.split()[-1],16) for line in ph.splitlines() if line.lstrip().startswith('LOAD ')]
if not aligns or min(aligns)<16384: raise SystemExit('ELF PT_LOAD alignment below 16 KiB or unavailable')
dyn=run('-d'); soname=re.search(r'SONAME.*\[(.*?)\]',dyn)
if not soname or soname.group(1)!='libyara_x_capi.so': raise SystemExit('Unexpected SONAME')
allowed={'libc.so','libdl.so','libm.so','liblog.so'}
needed=set(re.findall(r'NEEDED.*\[(.*?)\]',dyn))
if needed-allowed: raise SystemExit('Unexpected DT_NEEDED: '+', '.join(sorted(needed-allowed)))
sym=run('-Ws'); required={'yrx_compile','yrx_scanner_scan','yrx_compiler_create'}
for name in required:
 if not re.search(r'\b'+re.escape(name)+r'\b',sym): raise SystemExit('Missing exported symbol '+name)
if meta['upstream']['commit']!=p['upstream']['commit'] or meta['upstream']['version']!=p['upstream']['version'] or meta['ndk']!=p['ndk']['version'] or meta['target']!=p['target'] or meta['abi']!=p['abi'] or meta['android_api']!=p['android_api']: raise SystemExit('Metadata does not match pins')
manifest=D/'SHA256SUMS'; seen=set()
for line in manifest.read_text().splitlines():
 m=re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)',line)
 if not m or m.group(2) in seen: raise SystemExit('Malformed or duplicate SHA256SUMS entry')
 seen.add(m.group(2)); f=D/m.group(2)
 if not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest()!=m.group(1): raise SystemExit('Artifact checksum mismatch: '+m.group(2))
if seen!={f.name for f in D.iterdir() if f.is_file() and f.name!='SHA256SUMS'}: raise SystemExit('SHA256SUMS inventory mismatch')
print('Artifact verification passed')
