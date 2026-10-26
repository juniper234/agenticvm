"""Read the signed EFI variable filesystem module from the original verified ISO."""
import importlib.util,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import save,digest
def main():
    output=ROOT/'tools/secure-kernel';manifest=output/'manifest.json'
    if manifest.exists():
        data=json.loads(manifest.read_text())
        for name,sha in data['files'].items():
            if digest(output/name)!=sha: raise ValueError('EFI kernel module changed')
        print(manifest);return
    prior=json.loads((ROOT/'tools/kernel-network/manifest.json').read_text())
    archive=ROOT/'downloads/alpine/3.24.2/modloop-virt-network-source'
    if digest(archive)!=prior['modloop_sha256']: raise ValueError('Verified kernel module archive changed')
    name='modules/6.18.52-0-virt/kernel/fs/efivarfs/efivarfs.ko';output.mkdir(exist_ok=True)
    subprocess.run([str(ROOT/'tools/7zip/26.04/7z.exe'),'x',str(archive),'-o'+str(output),'-y','-bb0',name],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=45)
    save(manifest,{'iso_sha256':prior['iso_sha256'],'modloop_sha256':prior['modloop_sha256'],'files':{name:digest(output/name)}})
    print(manifest)
if __name__=='__main__': main()
