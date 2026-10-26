"""Extract systemd's standard UKI boot stub from authenticated Debian packages."""
import importlib.util,io,json,sys,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import save,digest
def main():
    output=ROOT/'tools/uki-stub';output.mkdir(exist_ok=True);manifest=output/'manifest.json'
    if manifest.exists():
        record=json.loads(manifest.read_text())
        if digest(output/'linuxx64.efi.stub')!=record['stub_sha256']: raise ValueError('UKI stub changed')
        print(manifest);return
    spec=importlib.util.spec_from_file_location('uki_debian_packages',ROOT/'scripts/desktop-image-debian.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    packages,lock=module.prepare_packages(ROOT/'downloads/debian/trixie',['systemd-boot-efi'],output/'package-lock.json')
    package=next(p for p in packages if p['name']=='systemd-boot-efi')
    with tarfile.open(fileobj=io.BytesIO(module.package_payload(package['path']))) as archive:
        item=next(i for i in archive if i.isfile() and i.name.endswith('/linuxx64.efi.stub'))
        if item.size>2*1024**2: raise ValueError('Unexpected UKI stub size')
        with (output/'linuxx64.efi.stub').open('xb') as out: out.write(archive.extractfile(item).read())
    save(manifest,{'schema':'agenticvm.uki-stub.v1','package':{k:v for k,v in package.items() if k!='path'},
        'archive_trust':lock['trust'],'package_lock_sha256':digest(output/'package-lock.json'),
        'stub_sha256':digest(output/'linuxx64.efi.stub')});print(manifest)
if __name__=='__main__': main()
