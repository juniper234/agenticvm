"""Workspace-only tools for the owned enrollment realism lab; no host installation."""
import hashlib,io,json,subprocess,sys,tarfile,urllib.request,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import digest,save

def fetch(url,path,sha,limit=32*1024**2):
    if not path.exists():
        with urllib.request.urlopen(url,timeout=45) as response: data=response.read(limit+1)
        if len(data)>limit or hashlib.sha256(data).hexdigest()!=sha: raise ValueError('Tool download integrity failure')
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as out: out.write(data)
    if digest(path)!=sha: raise ValueError('Cached tool changed')

def main():
    root=ROOT/'tools/realism';root.mkdir(exist_ok=True);manifest=root/'manifest.json'
    if manifest.exists():
        record=json.loads(manifest.read_text())
        for name,sha in record['files'].items():
            if digest(root/name)!=sha: raise ValueError('Realism tool changed: '+name)
        print(manifest);return
    url='https://github.com/ipxe/ipxe/releases/download/v2.0.0/ipxeboot.tar.gz'
    sha='01a526d4cc791fc30362259c609d6c506cc64a7bdff51b9a5eb788354e17eee1'
    archive=ROOT/'downloads/ipxe/v2.0.0/ipxeboot.tar.gz';fetch(url,archive,sha)
    files={}
    with tarfile.open(archive) as source:
        for name in ('ipxeboot/x86_64-sb/ipxe.efi','ipxeboot/x86_64-sb/shimx64.efi'):
            item=source.getmember(name)
            if not item.isfile() or item.size>2*1024**2: raise ValueError('Unexpected iPXE member')
            destination=root/Path(name).name
            data=source.extractfile(item).read()
            if destination.exists():
                if destination.read_bytes()!=data: raise ValueError('Partially prepared iPXE file changed')
            else:
                with destination.open('xb') as out: out.write(data)
            files[destination.name]=digest(destination)
    lock=json.loads((ROOT/'tools/build-tools-lock.json').read_text())['sources']['qemu']
    original=ROOT/lock['archive']
    with original.open('rb') as stream:
        if hashlib.file_digest(stream,'sha512').hexdigest()!=lock['digest']: raise ValueError('QEMU installer changed')
    subprocess.run([str(ROOT/'tools/7zip/26.04/7z.exe'),'e',str(original),'-o'+str(root),'-y','-bb0',
                    'share/edk2-x86_64-secure-code.fd'],check=True,stdout=subprocess.DEVNULL,timeout=45)
    files['edk2-x86_64-secure-code.fd']=digest(root/'edk2-x86_64-secure-code.fd')
    save(manifest,{'schema':'agenticvm.realism-tools.v1','ipxe_source':url,'ipxe_archive_sha256':sha,
        'qemu_installer_sha512':lock['digest'],'files':files})
    print(manifest)

if __name__=='__main__': main()
