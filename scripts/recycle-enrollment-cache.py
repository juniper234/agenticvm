"""Recycle only verified, reproducible task cache files after owned VM cleanup."""
import json
import argparse
from pathlib import Path
import sys
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.chain import exclusive
from agenticvm.lan_lab import digest, save
from agenticvm.lan_recovery import plain
from agenticvm.qemu import WindowsProcess
from agenticvm.errors import AgenticVMError


def main(ubuntu_installer=False):
    parent = plain(ROOT / 'runtime/native-enrollment-runs')
    removed = []
    retained = []
    with exclusive(parent):
        lock = json.loads((ROOT / 'tools/enrollment-assets-lock.json').read_text())
        coreos = next(row for row in lock['assets'] if row['name'].startswith('Fedora CoreOS'))
        expanded = plain(ROOT / coreos['uncompressed_path'])
        compressed = plain(ROOT / coreos['path'])
        if not expanded.resolve().is_relative_to(ROOT / 'runtime/enrollment-images') or not compressed.resolve().is_relative_to(ROOT / 'downloads/enrollment'):
            raise ValueError('Public image cache path escaped its task directories')
        if compressed.exists():
            if not expanded.exists() or digest(expanded) != coreos['uncompressed_sha256']:
                raise ValueError('Uncompressed CoreOS image changed; compressed recovery copy retained')
            if compressed.name != 'fedora-coreos-amd64.qcow2.xz' or digest(compressed) != coreos['sha256']:
                raise ValueError('Public compressed image changed; retained')
            removed.append({'path': compressed.relative_to(ROOT).as_posix(), 'sha256': coreos['sha256'], 'bytes': compressed.stat().st_size})
            compressed.unlink()
        for folder in parent.iterdir():
            if not folder.is_dir() or str(UUID(folder.name)) != folder.name:
                continue
            report = folder / 'report.json'
            if not report.exists() and (folder / 'recovery.json').exists():
                report = folder / 'recovery.json'
            if not report.exists():
                raise ValueError('An unfinished native run must be recovered before recycling cache')
            value = json.loads(report.read_text())
            if report.name == 'recovery.json' and not value.get('passed'):
                raise ValueError('Unfinished native recovery must be resolved before recycling cache')
            if value.get('cleanup_failures') or not value.get('all_owned_vms_stopped_and_disks_removed', True):
                raise ValueError('Owned resources were not confirmed stopped')
            can_recycle = True
            for binding in list(folder.glob('*/ownership.json')) + list(folder.glob('target/ownership-*.json')):
                owner = json.loads(binding.read_text())
                try:
                    with WindowsProcess(owner['pid']) as process:
                        if process.alive() and process.created == owner['created']:
                            raise ValueError('An owned VM is still running; its cache is retained')
                except AgenticVMError:
                    # A recycled Windows PID may now belong to a protected
                    # unrelated process. Keep this cache when inspection fails.
                    can_recycle = False
                    retained.append({'run_id': folder.name, 'reason': 'Recorded PID cannot be inspected; cache retained'})
                    break
            if not can_recycle:
                continue
            path = plain(folder / 'dhcp/infrastructure-initrd.gz')
            proof = plain(folder / 'dhcp/prepared-image.json')
            if path.exists():
                expected = json.loads(proof.read_text())['sha256']
                if digest(path) != expected:
                    raise ValueError('Owned DHCP cache changed; retained for review')
                removed.append({'path': path.relative_to(ROOT).as_posix(), 'sha256': expected, 'bytes': path.stat().st_size})
                path.unlink()
        if ubuntu_installer:
            media = json.loads((ROOT / 'tools/ubuntu-installer-lock.json').read_text())
            path = plain(ROOT / media['path'])
            if not path.resolve().is_relative_to(ROOT / 'downloads/enrollment-installers') or path.suffix != '.iso':
                raise ValueError('Unexpected Ubuntu public installer cache path')
            if path.exists():
                if digest(path) != media['sha256']:
                    raise ValueError('Ubuntu public media changed; retained')
                removed.append({'path': media['path'], 'sha256': media['sha256'], 'bytes': path.stat().st_size})
                path.unlink()
    output = ROOT / 'runtime/enrollment-cache-recycling' / (str(uuid4()) + '.json')
    output.parent.mkdir(exist_ok=True)
    save(output, {'passed': True, 'removed_only_verified_task_cache': removed, 'retained_uninspectable': retained,
        'retained': ['All publisher pins/URLs and all native reports/logs/checkpoints',
                     'DHCP prepared-image hashes and pinned base artifacts needed to rebuild the deterministic initrd']})
    print(json.dumps({'passed': True, 'reclaimed_bytes': sum(row['bytes'] for row in removed), 'files': len(removed), 'report': str(output)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ubuntu-installer', action='store_true', help='Recycle the verified public Ubuntu ISO; its URL and pin remain')
    main(parser.parse_args().ubuntu_installer)
