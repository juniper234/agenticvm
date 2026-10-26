"""Add unmodified shipped keymaps for the read-only stock-OS framebuffer control."""
import hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import digest,save

def main():
    output=ROOT/'tools/qemu-stock-firmware/20260811';manifest=output/'stock-keymaps.json'
    if manifest.exists():
        record=json.loads(manifest.read_text())
        for name,sha in record['files'].items():
            if digest(output/'keymaps'/name)!=sha: raise ValueError('Shipped keymap changed')
        return
    lock=json.loads((ROOT/'tools/build-tools-lock.json').read_text())['sources']['qemu'];archive=ROOT/lock['archive']
    with archive.open('rb') as source:
        if hashlib.file_digest(source,'sha512').hexdigest()!=lock['digest']: raise ValueError('QEMU installer changed')
    stage=output/'keymap-extraction';stage.mkdir(exist_ok=True)
    subprocess.run([str(ROOT/'tools/7zip/26.04/7z.exe'),'x',str(archive),'share/keymaps/*','-o'+str(stage),'-y','-bb0'],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=60)
    target=output/'keymaps';target.mkdir(exist_ok=True);files={}
    for path in (stage/'share/keymaps').iterdir():
        if not path.is_file(): raise ValueError('Unexpected keymap directory')
        destination=target/path.name
        with destination.open('xb') as stream: stream.write(path.read_bytes())
        files[path.name]=digest(destination)
    if 'en-us' not in files: raise ValueError('Stock English keymap missing')
    save(manifest,{'installer_sha512':lock['digest'],'files':files})

if __name__=='__main__': main()
