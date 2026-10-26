"""Extract Debian OVMF from the same authenticated archive used for the guest."""
import importlib.util,io,json,sys,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import save,digest

def main():
    output=ROOT/'tools/ovmf-debian';output.mkdir(exist_ok=True);manifest=output/'manifest.json'
    if manifest.exists():
        record=json.loads(manifest.read_text())
        for name,sha in record['files'].items():
            if digest(output/name)!=sha: raise ValueError('Debian firmware changed')
        print(manifest);return
    spec=importlib.util.spec_from_file_location('uefi_debian_packages',ROOT/'scripts/desktop-image-debian.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    packages,lock=module.prepare_packages(ROOT/'downloads/debian/trixie',['ovmf'],output/'package-lock.json')
    package=next(p for p in packages if p['name']=='ovmf');files={}
    with tarfile.open(fileobj=io.BytesIO(module.package_payload(package['path']))) as archive:
        for item in archive:
            if item.isfile() and Path(item.name).name in ('OVMF_CODE_4M.fd','OVMF_VARS_4M.fd','OVMF_CODE_4M.secboot.fd'):
                if item.size>8*1024**2: raise ValueError('Unexpected firmware size')
                destination=output/Path(item.name).name
                with destination.open('xb') as out: out.write(archive.extractfile(item).read())
                files[destination.name]=digest(destination)
    if not {'OVMF_CODE_4M.fd','OVMF_VARS_4M.fd'}<=files.keys(): raise ValueError('Required Debian firmware missing')
    save(manifest,{'schema':'agenticvm.debian-ovmf.v1','package':{k:v for k,v in package.items() if k!='path'},
        'archive_trust':lock['trust'],'package_lock_sha256':digest(output/'package-lock.json'),'files':files})
    print(manifest)

if __name__=='__main__': main()
