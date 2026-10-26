"""Prepare checksum-pinned Windows host-test tools; never launch a VM.

Network access requires --download. Prepared image checks can import only the
explicitly pinned files from an existing owned checkout via --asset-cache.
Downloaded tools and copied build assets remain outside Git.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import urllib.parse
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def digest(file):
    with Path(file).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def safe_child(root, relative):
    relative=relative.replace('\\','/')
    parts=relative.split('/')
    if not relative or relative.startswith('/') or any(not part or part in {'.','..'} or ':' in part
            or re.search(r'[<>"|?*\x00-\x1f]',part) or part.endswith((' ','.'))
            or re.fullmatch(r'(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?',part) for part in parts):
        raise ValueError('Unsafe preparation path')
    root=Path(root).absolute()
    target=root.joinpath(*parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError('Preparation path escapes its owned root')
    for item in (target,*target.parents):
        if item.is_symlink() or getattr(item,'is_junction',lambda:False)():
            raise ValueError('Preparation paths cannot redirect through links')
        if item==root:break
    return target


def fetch(record, cache, download):
    destination=safe_child(cache,record['filename'])
    if destination.exists():
        if destination.stat().st_size!=record['bytes'] or digest(destination)!=record['sha256']:
            raise ValueError('Cached dependency changed: '+record['filename'])
        return destination.read_bytes()
    if not download:raise ValueError('Missing dependency cache; rerun explicitly with --download')
    parsed=urllib.parse.urlsplit(record['url'])
    if parsed.scheme!='https' or parsed.hostname not in {'files.pythonhosted.org','www.python.org'} or parsed.username or parsed.password:
        raise ValueError('Unexpected dependency download origin')
    if not 0<record['bytes']<=40*1024**2 or not re.fullmatch('[a-f0-9]{64}',record['sha256']):
        raise ValueError('Invalid pinned dependency bounds')
    request=urllib.request.Request(record['url'],headers={'User-Agent':'AgenticVM-test-preparation'})
    with urllib.request.urlopen(request,timeout=90) as response:
        final=urllib.parse.urlsplit(response.url)
        if final.scheme!='https' or final.hostname not in {'files.pythonhosted.org','www.python.org'}:
            raise ValueError('Unexpected dependency redirect')
        data=response.read(record['bytes']+1)
    if len(data)!=record['bytes'] or hashlib.sha256(data).hexdigest()!=record['sha256']:
        raise ValueError('Dependency download integrity failed')
    destination.parent.mkdir(parents=True,exist_ok=True)
    with destination.open('xb') as output:output.write(data)
    return data


def unpack(data, destination, overrides=None):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        items=archive.infolist()
        if len(items)>10000 or sum(item.file_size for item in items)>256*1024**2:
            raise ValueError('Dependency archive exceeds extraction bounds')
        seen=set()
        for item in items:
            name=item.filename.rstrip('/')
            folded=name.casefold()
            if folded in seen:raise ValueError('Duplicate dependency archive path')
            seen.add(folded)
            if stat.S_ISLNK(item.external_attr>>16):raise ValueError('Archive links are refused')
            parts=PurePosixPath(name).parts
            if len(parts)>2 and parts[0].endswith('.data') and parts[1] in {'purelib','platlib'}:
                name='/'.join(parts[2:])
            target=safe_child(destination,name)
            if item.is_dir():target.mkdir(parents=True,exist_ok=True);continue
            if item.file_size>64*1024**2:raise ValueError('Dependency archive member too large')
            value=archive.read(item)
            if overrides and name in overrides:value=overrides[name]
            if target.exists():
                existing=target.read_bytes()
                if overrides and name in overrides and existing.replace(b'\r\n',b'\n')==value:
                    continue
                if existing!=value:raise ValueError('Prepared dependency file changed: '+name)
                continue
            target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as output:output.write(value)


def import_assets(cache):
    lock=json.loads((ROOT/'tools/test-assets-lock.json').read_text())
    copied=0
    for item in lock['files']:
        destination=safe_child(ROOT,item['path'])
        if destination.exists():
            if destination.stat().st_size!=item['bytes'] or digest(destination)!=item['sha256']:
                raise ValueError('Existing test asset changed: '+item['path'])
            continue
        if item['kind']=='source':raise ValueError('Pinned source input is missing: '+item['path'])
        if not item['path'].startswith(('runtime/linux-pxe-base-v3/','tools/realism/','tools/uki-stub/')):
            raise ValueError('Asset import is outside supported test fixtures')
        source=safe_child(Path(cache),item['path'])
        if source.stat().st_size!=item['bytes'] or digest(source)!=item['sha256']:
            raise ValueError('Prepared asset cache integrity failed: '+item['path'])
        destination.parent.mkdir(parents=True,exist_ok=True)
        with source.open('rb') as incoming,destination.open('xb') as outgoing:
            shutil.copyfileobj(incoming,outgoing,1024*1024)
        if digest(destination)!=item['sha256']:raise ValueError('Copied asset integrity failed')
        copied+=1
    return copied


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download',action='store_true')
    parser.add_argument('--asset-cache',type=Path)
    args=parser.parse_args()
    if os.name!='nt':raise ValueError('This pinned portable test environment currently targets Windows x86-64; use requirements-test.txt in a local virtual environment elsewhere')
    lock=json.loads((ROOT/'tools/test-dependencies-lock.json').read_text())
    runtime=json.loads((ROOT/'tools/python-runtime-lock.json').read_text())
    folder=ROOT/'tools/test-environment'
    python_record={'filename':Path(runtime['archive']).name,**{key:runtime[key] for key in ('url','bytes','sha256')}}
    pth=(runtime['stdlib_zip']+'\n.\nsite-packages\n../../src\n').encode('utf-8')
    unpack(fetch(python_record,ROOT/'downloads/tests',args.download),folder,{runtime['pth_file']:pth})
    for wheel in lock['wheels']:
        unpack(fetch(wheel,ROOT/'downloads/tests',args.download),folder/'site-packages')
    # This is a separate test interpreter. The production embedded runtime and
    # all global interpreter/site settings are left alone. -I child tests use
    # the same pinned interpreter and dependency directory.
    assets=import_assets(args.asset_cache) if args.asset_cache else 0
    receipt={'python':runtime['version'],'python_sha256':digest(folder/'python.exe'),
             'dependencies':{item['name']:item['version'] for item in lock['wheels']},
             'copied_assets':assets,'native_vm_launched':False,'global_settings_changed':False}
    (folder/'test-environment.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(receipt))


if __name__=='__main__':main()
