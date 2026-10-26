"""Install one real Ubuntu Server via Subiquity, then capture a security-on CP1 report.

Local owner lab only: cached publisher ISO, QEMU user networking, one disposable
qcow2 disk. It does not disable host/guest security features or scan externally.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
QEMU = ROOT / 'tools/qemu/11.1.0/qemu-system-x86_64.exe'
ISO = ROOT / 'downloads/enrollment-installers/ubuntu-24.04.5-live-server-amd64.iso'
VMLINUX = ROOT / 'runtime/enrollment-images/ubuntu-installer/vmlinuz'
INITRD = ROOT / 'runtime/enrollment-images/ubuntu-installer/initrd.gz'
WORK = ROOT / 'runtime/redteam-cp1-ubuntu'
ISO_SHA256 = '97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8'


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()

PROBE = r'''#!/usr/bin/python3
import json, os, pathlib, subprocess, sys

def run(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        return (p.stdout + p.stderr).strip()
    except Exception as e:
        return type(e).__name__ + ': ' + str(e)

try:
    subprocess.run(['/usr/sbin/ufw', 'allow', '22/tcp'], capture_output=True, timeout=15)
    subprocess.run(['/usr/sbin/ufw', '--force', 'enable'], capture_output=True, timeout=15)
except Exception:
    pass
try:
    subprocess.run(['/usr/bin/systemctl', 'enable', '--now', 'ssh'], capture_output=True, timeout=15)
    import time as _time
    _time.sleep(2)
except Exception:
    pass

osr = {}
try:
    for line in pathlib.Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k, v = line.split('=', 1); osr[k] = v.strip().strip('"')
except Exception:
    pass
report = {
    'os_id': osr.get('ID'), 'os_name': osr.get('PRETTY_NAME'),
    'init': run(['ps', '-p', '1', '-o', 'comm=']),
    'apparmor': pathlib.Path('/sys/module/apparmor/parameters/enabled').read_text().strip() if pathlib.Path('/sys/module/apparmor/parameters/enabled').exists() else 'absent',
    'selinux': run(['getenforce']) if pathlib.Path('/usr/sbin/getenforce').exists() else 'absent',
    'firewall': 'active' if 'Status: active' in run(['ufw', 'status', 'verbose']) else 'inactive',
    'firewall_detail': run(['ufw', 'status', 'verbose'])[:800],
    'sshd': 'installed' if pathlib.Path('/usr/sbin/sshd').exists() else 'not-installed',
    'ssh_active': run(['systemctl', 'is-active', 'ssh']) == 'active',
    'sshd_effective': run(['sshd', '-T'])[:1200],
    'sudo': run(['sudo', '-u', 'cp1', 'sudo', '-n', 'true']) == '',
    'ufw_active': run(['systemctl', 'is-active', 'ufw']),
    'apparmor_active': run(['systemctl', 'is-active', 'apparmor']),
    'pid1': run(['ps', '-p', '1', '-o', 'comm=']),
    'virt': run(['systemd-detect-virt']),
    'mounts': run(['findmnt', '-rn', '-o', 'TARGET,SOURCE,FSTYPE'])[:1500],
    'addresses': run(['ip', '-brief', 'address'])[:800],
    'security_disabled': [],
    'host_mounts': False,
    'real_disk': '/dev/vda' in run(['findmnt', '-n', '-o', 'SOURCE', '/']),
    'uid': os.getuid(),
}
text = 'CP1_REPORT ' + json.dumps(report, sort_keys=True)
try:
    with open('/dev/ttyS0', 'w', encoding='utf-8') as console:
        print(text, file=console, flush=True)
except Exception as e:
    print('CP1_CONSOLE_ERROR ' + str(e), file=sys.stderr)
pathlib.Path('/var/log/cp1-security-report.json').write_text(json.dumps(report, indent=2) + '\n')
subprocess.run(['systemctl', 'poweroff'], timeout=15)
'''

SERVICE = '''[Unit]
Description=AgenticVM CP1 security report
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/sbin/cp1-probe.py
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target
'''


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass


def serve_seed(folder):
    class Handler(Quiet):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(folder), **kwargs)
    server = socketserver.TCPServer(('0.0.0.0', 0), Handler)
    server.allow_reuse_address = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def run(argv, log, timeout):
    with log.open('wb') as out:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(10)
            return None


def main():
    if not all(path.is_file() for path in (QEMU, ISO, VMLINUX, INITRD)):
        raise SystemExit('missing installer input')
    if digest(ISO) != ISO_SHA256:
        raise SystemExit('cached Ubuntu installer changed from its pinned SHA-256')
    WORK.mkdir(parents=True, exist_ok=True)
    disk = WORK / 'cp1.raw'
    serial = WORK / 'installer-serial.log'
    boot_serial = WORK / 'boot-serial.log'
    if disk.exists():
        disk.unlink()
    disk.touch()
    subprocess.run(['fsutil', 'sparse', 'setflag', str(disk)], check=True, capture_output=True)
    subprocess.run(['fsutil', 'file', 'seteof', str(disk), str(16 * 1024**3)], check=True, capture_output=True)
    seed = WORK / 'seed'
    seed.mkdir(exist_ok=True)
    probe_b64 = base64.b64encode(PROBE.encode()).decode()
    service_b64 = base64.b64encode(SERVICE.encode()).decode()
    late = (
        "set -eu; "
        f"printf '%s' {probe_b64} | base64 -d > /target/usr/local/sbin/cp1-probe.py; "
        "chmod 755 /target/usr/local/sbin/cp1-probe.py; "
        f"printf '%s' {service_b64} | base64 -d > /target/etc/systemd/system/cp1-probe.service; "
        "chmod 644 /target/etc/systemd/system/cp1-probe.service; "
        "printf 'cp1 ALL=(ALL) NOPASSWD:ALL\\n' > /target/etc/sudoers.d/90-cp1; "
        "chmod 440 /target/etc/sudoers.d/90-cp1; "
        "systemctl --root=/target enable cp1-probe.service; "
        "systemctl --root=/target enable ssh"
    )
    install = {
        'version': 1,
        'refresh-installer': {'update': False},
        'locale': 'en_US.UTF-8', 'keyboard': {'layout': 'us'},
        'timezone': 'Etc/UTC',
        'identity': {'hostname': 'cp1-ubuntu', 'username': 'cp1', 'password': '!'},
        'ssh': {'install-server': True, 'allow-pw': False},
        'storage': {'layout': {'name': 'direct', 'match': {'path': '/dev/vda'}}},
        'packages': ['openssh-server', 'ufw', 'apparmor', 'auditd', 'python3', 'sudo'],
        'late-commands': [['/bin/sh', '-c', late]],
        'shutdown': 'poweroff',
    }
    (seed / 'user-data').write_text('#cloud-config\n' + json.dumps({'autoinstall': install}, indent=2) + '\n')
    (seed / 'meta-data').write_text(json.dumps({'instance-id': 'cp1-ubuntu', 'local-hostname': 'cp1-ubuntu'}) + '\n')
    (seed / 'vendor-data').write_text('')
    server, port = serve_seed(seed)
    boot = ('boot=casper autoinstall console=ttyS0,115200n8 '
            f'ds=nocloud-net;s=http://10.0.2.2:{port}/ ---')
    qemu_common = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-machine', 'q35', '-accel', 'whpx',
                   '-m', '3072', '-smp', '2', '-display', 'none', '-monitor', 'none', '-no-reboot',
                   '-netdev', 'user,id=net0', '-device', 'e1000,netdev=net0,romfile=']
    install_argv = qemu_common + ['-drive', f'file={disk},format=raw,if=virtio',
        '-cdrom', str(ISO), '-kernel', str(VMLINUX), '-initrd', str(INITRD), '-append', boot,
        '-serial', 'file:' + str(serial)]
    manifest = {'schema': 'agenticvm.cp1-ubuntu-install.v1', 'iso_sha256': digest(ISO),
                'kernel_sha256': digest(VMLINUX),
                'initrd_sha256': digest(INITRD),
                'autoinstall': install, 'qemu_install_argv': install_argv,
                'networking': 'QEMU user NAT; no host adapter or external guest route'}
    (WORK / 'install-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    started = time.time()
    code = run(install_argv, WORK / 'installer-console.log', 1500)
    install_seconds = round(time.time() - started, 1)
    server.shutdown()
    if code is None:
        (WORK / 'result.json').write_text(json.dumps({'passed': False, 'error': 'installer timeout'}, indent=2) + '\n')
        return 1
    boot_argv = qemu_common + ['-drive', f'file={disk},format=raw,if=virtio',
                               '-serial', 'file:' + str(boot_serial)]
    boot_code = run(boot_argv, WORK / 'firstboot-console.log', 420)
    report = None
    if boot_serial.exists():
        for line in boot_serial.read_text(errors='replace').splitlines():
            if line.startswith('CP1_REPORT '):
                report = json.loads(line.removeprefix('CP1_REPORT '))
    result = {'passed': bool(report and report.get('init') == 'systemd' and report.get('sshd') == 'installed'
                             and report.get('ssh_active') is True
                             and report.get('firewall') == 'active' and report.get('apparmor') == 'Y'
                             and report.get('sudo') is True),
              'installer_exit': code, 'install_seconds': install_seconds,
              'firstboot_exit': boot_code, 'report': report,
              'disk': str(disk), 'disk_bytes': disk.stat().st_size,
              'install_serial': str(serial), 'boot_serial': str(boot_serial),
              'limitations': ['QEMU user networking; no external target',
                              'CP1 only; no join/force/model yet']}
    (WORK / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
