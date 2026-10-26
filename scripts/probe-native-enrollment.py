"""Observe real cloud-init/Ignition execution and a second cold boot."""
import argparse
import base64
import json
from pathlib import Path
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.native_vm import NativeVM, seed_iso
from agenticvm.lan_lab import digest, save
from agenticvm.resources import check_memory_budget


def run(kind):
    route = 'cloud-init-local' if kind == 'ubuntu' else 'ignition-local'
    check_memory_budget(1024)
    folder = ROOT / 'runtime/native-provision-probes' / str(uuid4())
    folder.mkdir(parents=True)
    script = '''#!/bin/sh
set -eu
. /etc/os-release
printf 'NATIVE_PROBE {"route":"%s","os":"%s","boot_id":"%s"}\\n' ROUTE "$ID" "$(cat /proc/sys/kernel/random/boot_id)" > /dev/ttyS0
'''.replace('ROUTE', route)
    unit = '''[Unit]
Description=Owned native provisioner acceptance marker
After=local-fs.target systemd-logind.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/garden-native-probe
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''
    seed = ignition = None
    if kind == 'ubuntu':
        cfg = {'write_files': [
            {'path': '/usr/local/bin/garden-native-probe', 'permissions': '0755', 'content': script},
            {'path': '/etc/systemd/system/garden-native-probe.service', 'permissions': '0644', 'content': unit}],
            'runcmd': [['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', 'garden-native-probe.service']]}
        seed = folder / 'seed.iso'
        seed_iso(seed, {'user-data': ('#cloud-config\n' + json.dumps(cfg)).encode(),
                       'meta-data': json.dumps({'instance-id': folder.name, 'local-hostname': 'garden-native'}).encode()})
    else:
        cfg = {'ignition': {'version': '3.4.0'}, 'storage': {'files': [
            {'path': '/usr/local/bin/garden-native-probe', 'mode': 493,
             'contents': {'source': 'data:text/plain;base64,' + base64.b64encode(script.encode()).decode()}}]},
            'systemd': {'units': [{'name': 'garden-native-probe.service', 'enabled': True, 'contents': unit}]}}
        ignition = folder / 'config.ign'
        ignition.write_text(json.dumps(cfg))
    vm = None
    result = {'route': route, 'level': 'native-bootstrap-tested', 'passed': False,
              'source_sha256': {'scripts/probe-native-enrollment.py': digest(Path(__file__)),
                                'src/agenticvm/native_vm.py': digest(ROOT / 'src/agenticvm/native_vm.py')},
              'evidence': [], 'limitations': ['Provisioner/OS reboot probe only; no garden/model acceptance yet'],
              'native_os_observed': False}
    try:
        vm = NativeVM(folder / 'target', kind)
        for boot in (1, 2):
            log = vm.start(seed=seed if boot == 1 else None, ignition=ignition if boot == 1 else None)
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                if vm.process.poll() is not None:
                    raise RuntimeError('Native guest exited before marker: ' + str(vm.folder / f'stderr-{boot}.log'))
                text = log.read_text(errors='replace') if log.exists() else ''
                found = [line for line in text.splitlines() if line.startswith('NATIVE_PROBE ')]
                if found:
                    entry = json.loads(found[-1].removeprefix('NATIVE_PROBE '))
                    if entry['route'] != route or entry['os'] != ('ubuntu' if kind == 'ubuntu' else 'fedora'):
                        raise ValueError('Wrong native OS/provisioning marker')
                    result['evidence'].append({'boot': boot, **entry, 'console_sha256': digest(log)})
                    break
                time.sleep(.5)
            else:
                raise TimeoutError('Native provisioner did not emit marker within four minutes')
            vm.poweroff()
        if result['evidence'][0]['boot_id'] == result['evidence'][1]['boot_id']:
            raise ValueError('Second cold boot was not independently observed')
        result.update(passed=True, native_os_observed=True, native_cold_boots=2, base_sha256=vm.base_sha256)
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        if vm:
            vm.clean()
        result['disposable_vm_stopped_and_disk_removed'] = vm is None or not vm.disk.exists()
        save(folder / 'report.json', result)
    print(json.dumps({'passed': result['passed'], 'report': str(folder / 'report.json'), 'error': result.get('error')}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=('ubuntu', 'coreos'), default='ubuntu')
    raise SystemExit(run(parser.parse_args().kind))
