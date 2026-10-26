"""Extract unchanged stock PC firmware from the already verified QEMU installer."""
import hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import save,digest

def prepare():
    lock=json.loads((ROOT/'tools/build-tools-lock.json').read_text())['sources']['qemu']
    archive=ROOT/lock['archive'];output=ROOT/'tools/qemu-stock-firmware/20260811'
    manifest=output/'stock-firmware.json'
    if manifest.exists():
        prior=json.loads(manifest.read_text())
        for name,item in prior['files'].items():
            if digest(output/name)!=item['sha256']: raise ValueError('Stock firmware changed: '+name)
        print(manifest);return
    with archive.open('rb') as source: actual=hashlib.file_digest(source,'sha512').hexdigest()
    if actual!=lock['digest'] or archive.stat().st_size!=lock['bytes']: raise ValueError('Original QEMU installer integrity mismatch')
    output.mkdir(parents=True,exist_ok=True)
    names=['bios-256k.bin','bios.bin','vgabios.bin','vgabios-stdvga.bin','vgabios-cirrus.bin',
           'kvmvapic.bin','pxe-e1000.rom','efi-e1000.rom','efi-e1000e.rom','pxe-rtl8139.rom',
           'pxe-virtio.rom','efi-virtio.rom','edk2-x86_64-code.fd','edk2-i386-vars.fd','edk2-licenses.txt']
    command=[str(ROOT/'tools/7zip/26.04/7z.exe'),'e',str(archive),'-o'+str(output),'-y','-bb0']
    subprocess.run(command+['share/'+name for name in names],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=60)
    files={name:{'bytes':(output/name).stat().st_size,'sha256':digest(output/name)} for name in names if (output/name).exists()}
    if not {'bios-256k.bin','pxe-e1000.rom','vgabios-stdvga.bin'}<=files.keys(): raise ValueError('Required shipped PC firmware missing')
    save(manifest,{'schema':'agenticvm.stock-qemu-firmware.v1','source':lock['url'],
        'installer_sha512':actual,'unmodified_shipped_firmware':True,'files':files})
    print(manifest)

if __name__=='__main__': prepare()
