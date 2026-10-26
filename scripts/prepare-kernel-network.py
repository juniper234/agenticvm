"""Extract missing network modules directly from the checksum-verified Alpine ISO."""
import hashlib,importlib.util,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import save,digest
def main():
    output=ROOT/'tools/kernel-network';manifest=output/'manifest.json'
    if manifest.exists():
        record=json.loads(manifest.read_text())
        for name,sha in record['files'].items():
            if digest(output/name)!=sha: raise ValueError('Network module changed')
        print(manifest);return
    spec=importlib.util.spec_from_file_location('network_kernel_iso',ROOT/'scripts/build-linux-probe.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    base=json.loads((ROOT/'runtime/linux-pxe-base-v3/build-manifest.json').read_text());provenance=base['kernel']
    iso=ROOT/'downloads/alpine'/provenance['version']/Path(provenance['url']).name
    if digest(iso)!=provenance['sha256']: raise ValueError('Original Alpine ISO changed')
    source=module.pycdlib.PyCdlib();source.open(str(iso))
    try: data=module.extract(source,'/boot/modloop-virt')
    finally: source.close()
    archive=iso.parent/'modloop-virt-network-source'
    if archive.exists():
        if archive.read_bytes()!=data: raise ValueError('Module source changed')
    else:
        with archive.open('xb') as out: out.write(data)
    prefix='modules/6.18.52-0-virt/'
    names=[prefix+path for path in ('kernel/net/packet/af_packet.ko','kernel/drivers/net/ethernet/intel/e1000e/e1000e.ko')]
    output.mkdir(parents=True,exist_ok=True)
    subprocess.run([str(ROOT/'tools/7zip/26.04/7z.exe'),'x',str(archive),'-o'+str(output),'-y','-bb0',*names],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=60)
    files={name:digest(output/name) for name in names}
    save(manifest,{'schema':'agenticvm.extra-network-modules.v1','iso_sha256':provenance['sha256'],
        'source_url':provenance['url'],'modloop_sha256':digest(archive),'files':files})
    print(manifest)
if __name__=='__main__': main()
