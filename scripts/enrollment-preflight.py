"""Read-only resource/prerequisite snapshot; never launch VMs or contact tenants."""
import json
from pathlib import Path
import shutil
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.enrollment_catalog import catalog
from agenticvm.resources import memory_status, whpx_status
from agenticvm.platform_contracts import REQUIREMENTS
from agenticvm.lan_lab import save


def snapshot():
    free, memory, hypervisor = shutil.disk_usage(ROOT).free, memory_status(), whpx_status()
    rows = []
    for item in catalog():
        route = item['id']
        gates = []
        if route in REQUIREMENTS:
            gates += ['Offline preparation only: native payload/client and external resources are still required', *REQUIREMENTS[route]]
        else:
            if not hypervisor['available']:
                gates.append('WHPX is unavailable; host settings were not changed')
            installer = route in ('debian-preseed', 'ubuntu-autoinstall', 'anaconda-kickstart', 'autoyast')
            minimum = 12 if installer else 4
            if free < minimum * 1024**3:
                gates.append(f'Keep {minimum} GiB free for this campaign profile; host currently has {free / 1024**3:.2f} GiB')
            allocation = 3328 if installer else 2816
            if route == 'ubuntu-autoinstall':
                allocation = 4864
            if memory['available_physical_mib'] < allocation + 512 or memory['available_commit_mib'] < allocation + 384:
                gates.append(f'Need {allocation + 512} MiB physical and {allocation + 384} MiB commit headroom for a positive case')
            if installer:
                kind = {'debian-preseed': 'debian', 'ubuntu-autoinstall': 'ubuntu', 'anaconda-kickstart': 'fedora', 'autoyast': 'opensuse'}[route]
                manifest = ROOT / 'runtime/enrollment-images' / (kind + '-installer') / 'manifest.json'
                if not manifest.exists() or not (ROOT / json.loads(manifest.read_text())['iso']['path']).is_file():
                    gates.append('Publisher-pinned local installer media must be reacquired/prepared')
            if route.startswith('ignition'):
                lock = json.loads((ROOT / 'tools/enrollment-assets-lock.json').read_text())
                asset = next(row for row in lock['assets'] if row['name'].startswith('Fedora CoreOS'))
                if not (ROOT / asset['uncompressed_path']).exists():
                    gates.append('Recreate the recycled verified CoreOS cache with scripts/prepare-enrollment-images.py')
            if route == 'uefi-http':
                gates.append('Prior native firmware HTTP probe failed; adapter needs a successful repair and retest')
        rows.append({'route': route, 'native_rerun_ready': not gates, 'gates': gates})
    return {'schema': 'agenticvm.enrollment-preflight.v1', 'read_only': True, 'host_free_bytes': free,
        'memory': memory, 'hypervisor': hypervisor, 'settings_changed': False, 'routes': rows,
        'note': 'A preflight is a resource snapshot, not native test evidence; existing acceptance remains in the coverage matrix'}


if __name__ == '__main__':
    value = snapshot()
    folder = ROOT / 'runtime/enrollment-preflight' / str(uuid4())
    folder.mkdir(parents=True)
    save(folder / 'report.json', value)
    print(json.dumps(value | {'report': str(folder / 'report.json')}, indent=2))
