"""Prepare pinned CPU inference artifacts and a disposable offline test VM.

No global installation, host mounts, model execution or production image edits.
"""
from pathlib import Path, PurePosixPath
import concurrent.futures
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import urllib.request
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.ext2 import Node, build_ext2

MODEL_REV = '657e078c94084481950a2d555a941481f715536b'
MODEL = 'LFM2.5-350M-Q4_K_M.gguf'
SPECS = {
    MODEL: (f'https://huggingface.co/LiquidAI/LFM2.5-350M-GGUF/resolve/{MODEL_REV}/{MODEL}', 229312224,
            '7e6f72643caafc9a68256686638c4d7916f2cec76d1df478d4c3ddcd95a6aed4'),
    'llama-b11711-bin-ubuntu-x64.tar.gz': ('https://github.com/ggml-org/llama.cpp/releases/download/b11711/llama-b11711-bin-ubuntu-x64.tar.gz',
                                        17917870, '05e4fb108c568a8717ef146e86edaee753dabe1f2713c33ea7cb380c74d63cc7'),
}

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare_openmp(folder):
    spec = importlib.util.spec_from_file_location('inference_debian', ROOT/'scripts/desktop-image-debian.py')
    deb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deb)
    records, indexes, keys = deb.signed_indexes(ROOT/'downloads/debian/trixie',
                                               json.loads((ROOT/'tools/desktop-image-lock.json').read_text()))
    item = next(row for row in records if row['Package'] == 'libgomp1')
    url = deb.REPOSITORIES[item['repository']]+item['Filename']
    directory = folder/'dependencies'
    directory.mkdir(exist_ok=True)
    package = directory/Path(item['Filename']).name
    deb.fetch(url, package, item['SHA256'], int(item['Size']))
    with tarfile.open(fileobj=io.BytesIO(deb.package_payload(package))) as archive:
        for member in archive:
            if member.isfile() and '/libgomp.so.' in member.name:
                (directory/'libgomp.so.1').write_bytes(archive.extractfile(member).read())
    if not (directory/'libgomp.so.1').is_file():
        raise ValueError('Verified Debian package did not contain OpenMP runtime')
    (directory/'provenance.json').write_text(json.dumps({'url':url, 'sha256':item['SHA256'],
        'version':item['Version'], 'library_sha256':digest(directory/'libgomp.so.1'),
        'indexes':indexes, 'keys':keys}, indent=2)+'\n')

def main():
    folder = ROOT / 'runtime/local-model-test'
    folder.mkdir(parents=True, exist_ok=True)
    downloads = folder / 'downloads'
    downloads.mkdir(exist_ok=True)
    def download(item):
        name, (url, size, sha) = item
        target = downloads / name
        if not target.exists():
            partial = target.with_suffix(target.suffix + '.partial')
            request = urllib.request.Request(url, headers={'User-Agent': 'AgenticVM-local-test'})
            with urllib.request.urlopen(request, timeout=60) as source, partial.open('xb') as output:
                total = 0
                while block := source.read(1024 * 1024):
                    total += len(block)
                    if total > size:
                        raise ValueError('Artifact exceeds published size')
                    output.write(block)
            if partial.stat().st_size != size or digest(partial) != sha:
                raise ValueError('Artifact size or SHA-256 mismatch: ' + name)
            partial.replace(target)
        if target.stat().st_size != size or digest(target) != sha:
            raise ValueError('Cached artifact mismatch: ' + name)
        print(json.dumps({'verified': name, 'bytes': size, 'sha256': sha}), flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(download, SPECS.items()))
    prepare_openmp(folder)
    source = (ROOT / 'guest/agent.c').read_text(encoding='utf-8')
    # Test-only controller: keep normal source/images and their limits intact.
    # 2 GiB is virtual address space, not a physical RAM allocation.
    assert source.count('128u * 1024u * 1024u') == 1
    source = source.replace('128u * 1024u * 1024u', '2048u * 1024u * 1024u').replace('134217728', '2147483648')
    test_source = folder / 'agent-inference-test.c'
    test_source.write_text(source, encoding='utf-8')
    binary = folder / 'agentd-inference-test'
    if not binary.exists():
        compiler = ROOT / 'tools/zig/zig-x86_64-windows-0.15.2/zig.exe'
        lock = json.loads((ROOT / 'tools/build-tools-lock.json').read_text())
        assert digest(compiler) == lock['sources']['zig']['exe_sha256']
        subprocess.run([sys.executable, '-I', str(ROOT/'scripts/run-bounded.py'), '--output', str(ROOT/'runtime'/('build-inference-compile-'+uuid4().hex[:8])),
                        '--', str(compiler), 'cc', '-target', 'x86_64-linux-musl', '-Os', '-static', '-s', '-std=c11',
                        str(test_source), '-o', str(binary)], check=True, cwd=ROOT)
    boot = folder/'boot'
    if not (boot/'agenticvm-linux-peer.iso').exists():
        subprocess.run([sys.executable, '-I', str(ROOT/'scripts/run-bounded.py'), '--output', str(ROOT/'runtime'/('build-inference-boot-'+uuid4().hex[:8])),
                        '--', sys.executable, '-I', str(ROOT/'scripts/build-linux-peer.py'), '--agent', str(binary), '--output', str(boot)], check=True, cwd=ROOT)
    workspace = folder/'vm'
    disk = workspace/'data/default.ext2'
    disk.parent.mkdir(parents=True, exist_ok=True)
    if not disk.exists():
        nodes = {'': Node(stat.S_IFDIR|0o700, uid=1000, gid=1000),
                 'model.gguf': Node(stat.S_IFREG|0o444, downloads/MODEL, 1000, 1000)}
        with tarfile.open(downloads/'llama-b11711-bin-ubuntu-x64.tar.gz') as archive:
            for member in archive:
                name = PurePosixPath(member.name)
                if name.is_absolute() or '..' in name.parts or member.size > 256*1024**2:
                    raise ValueError('Unsafe release member')
                if member.isdir():
                    continue
                relative = 'llama/' + str(name)
                if member.isfile():
                    nodes[relative] = Node(stat.S_IFREG | (member.mode & 0o755), archive.extractfile(member).read(), 1000, 1000)
                elif member.issym():
                    if '/' in member.linkname or member.linkname in ('.','..'):
                        raise ValueError('Unexpected release symlink')
                    nodes[relative] = Node(stat.S_IFLNK|0o777, member.linkname.encode(), 1000, 1000)
                else:
                    raise ValueError('Unexpected release file type')
        build_ext2(disk, nodes, size_mib=512, label='AGENTICVM_DATA')
    manifest = {'model': MODEL, 'model_revision': MODEL_REV, 'sources': {name: {'url': v[0], 'bytes':v[1], 'sha256':v[2]} for name,v in SPECS.items()},
                'runtime': 'llama.cpp b11711 Linux x86_64 CPU', 'controller_address_space_bytes': 2*1024**3,
                'normal_product_limits_unchanged': True, 'normal_root_image_unchanged': True,
                'workspace_disk_sha256_before_boot': digest(disk), 'test_agent_sha256': digest(binary),
                'model_execution_location': 'Linux guest only'}
    (folder/'preparation.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'prepared': True, 'folder':str(folder), 'disk':str(disk)}))

if __name__ == '__main__':
    main()
