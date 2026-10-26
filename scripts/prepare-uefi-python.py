"""Fetch pinned wheels into a workspace-only tool directory; never installs globally."""
import hashlib,json,sys,urllib.request,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import digest,save

def main():
    lock=ROOT/'tools/realism/firmware-python-lock.json';record=json.loads(lock.read_text())
    output=ROOT/'tools/python/firmware-v1';manifest=output/'verified-files.json'
    if manifest.exists():
        prior=json.loads(manifest.read_text())
        if prior['lock_sha256']!=digest(lock): raise ValueError('Firmware Python tool lock changed')
        for name,sha in prior['files'].items():
            if digest(output/name)!=sha: raise ValueError('Firmware Python tool changed: '+name)
        print(manifest);return
    output.mkdir(parents=True,exist_ok=True);files={}
    for item in record['packages']:
        url=item['url']
        if not url.startswith('https://files.pythonhosted.org/') or not url.endswith('.whl'): raise ValueError('Unapproved wheel source')
        path=ROOT/'downloads/uefi-python'/Path(url).name;path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists():
            with urllib.request.urlopen(url,timeout=30) as response: data=response.read(24*1024**2+1)
            if len(data)>24*1024**2 or hashlib.sha256(data).hexdigest()!=item['sha256']: raise ValueError('Wheel integrity mismatch')
            with path.open('xb') as out: out.write(data)
        if digest(path)!=item['sha256']: raise ValueError('Cached wheel changed')
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                name=PurePosixPath(member.filename)
                if name.is_absolute() or '..' in name.parts or '\\' in member.filename or member.file_size>24*1024**2: raise ValueError('Unsafe wheel member')
                if member.is_dir(): continue
                if '.data' in str(name): raise ValueError('Wheel needs unsupported installation mapping')
                target=output/str(name);target.parent.mkdir(parents=True,exist_ok=True);data=archive.read(member)
                if target.exists():
                    if target.read_bytes()!=data: raise ValueError('Conflicting tool member')
                else:
                    with target.open('xb') as out: out.write(data)
                files[str(name)]=hashlib.sha256(data).hexdigest()
    save(manifest,{'lock_sha256':digest(lock),'files':files});print(manifest)

if __name__=='__main__': main()
