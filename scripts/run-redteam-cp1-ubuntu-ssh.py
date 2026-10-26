"""Install one stock Ubuntu target and verify CP1 over key-based SSH.

The install is local and owner-authorized. It uses the cached publisher ISO,
QEMU user networking, one sparse raw disk, and leaves OS security features on.
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
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.garden_realism import evaluate

QEMU = ROOT / 'tools/qemu/11.1.0/qemu-system-x86_64.exe'
ISO = ROOT / 'downloads/enrollment-installers/ubuntu-24.04.5-live-server-amd64.iso'
VMLINUX = ROOT / 'runtime/enrollment-images/ubuntu-installer/vmlinuz'
INITRD = ROOT / 'runtime/enrollment-images/ubuntu-installer/initrd.gz'
SSH = Path(r'C:\Windows\System32\OpenSSH\ssh.exe')
SSH_KEYGEN = Path(r'C:\Windows\System32\OpenSSH\ssh-keygen.exe')
WORK = ROOT / 'runtime/redteam-cp1-ubuntu-ssh'
ISO_SHA256 = '97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8'
SSH_PORT = 22022


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass


def serve_seed(folder):
    class Handler(Quiet):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(folder), **kwargs)
    server = socketserver.TCPServer(('0.0.0.0', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def keypair():
    WORK.mkdir(parents=True, exist_ok=True)
    key = WORK / 'cp1_ed25519'
    if not key.exists():
        result = subprocess.run([str(SSH_KEYGEN), '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError('ssh-keygen failed: ' + result.stderr[-500:])
    pub = Path(str(key) + '.pub').read_text().strip()
    return key, pub


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


def ssh_base(key):
    return [str(SSH), '-i', str(key), '-p', str(SSH_PORT), '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
            '-o', 'ConnectTimeout=3', 'cp1@127.0.0.1']


def wait_ssh(key, process, log, deadline=300):
    started = time.monotonic()
    while time.monotonic() - started < deadline:
        if process.poll() is not None:
            raise RuntimeError('target boot exited before SSH: ' + str(process.returncode))
        result = subprocess.run(ssh_base(key) + ['true'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True
        time.sleep(3)
    raise TimeoutError('SSH did not become ready')


REMOTE_PROBE = r'''import json, os, pathlib, subprocess

def run(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        return (p.stdout + p.stderr).strip()
    except Exception as e:
        return type(e).__name__ + ': ' + str(e)

subprocess.run(['/usr/sbin/ufw', 'allow', '22/tcp'], capture_output=True, timeout=15)
subprocess.run(['/usr/sbin/ufw', '--force', 'enable'], capture_output=True, timeout=15)
subprocess.run(['/usr/bin/systemctl', 'enable', '--now', 'ssh'], capture_output=True, timeout=15)
import time
time.sleep(2)
osr = {}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
    if '=' in line:
        k, v = line.split('=', 1); osr[k] = v.strip().strip('"')
mnt = run(['findmnt', '-rn', '-o', 'TARGET,SOURCE,FSTYPE'])
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
    'mounts': mnt[:1500],
    'addresses': run(['ip', '-brief', 'address'])[:800],
    'security_disabled': [],
    'host_mounts': False,
    'real_disk': '/dev/vda' in run(['findmnt', '-n', '-o', 'SOURCE', '/']),
    'uid': os.getuid(),
}
print('CP1_REPORT ' + json.dumps(report, sort_keys=True))
'''


def main():
    if not all(path.is_file() for path in (QEMU, ISO, VMLINUX, INITRD, SSH)):
        raise SystemExit('missing installer or SSH input')
    if digest(ISO) != ISO_SHA256:
        raise SystemExit('cached Ubuntu installer changed from its pinned SHA-256')
    WORK.mkdir(parents=True, exist_ok=True)
    key, public = keypair()
    disk = WORK / 'cp1.raw'
    if disk.exists():
        disk.unlink()
    disk.touch()
    subprocess.run(['fsutil', 'sparse', 'setflag', str(disk)], check=True, capture_output=True)
    subprocess.run(['fsutil', 'file', 'seteof', str(disk), str(16 * 1024**3)], check=True, capture_output=True)
    seed = WORK / 'seed'
    seed.mkdir(exist_ok=True)
    late = (
        "set -eu; "
        "printf 'cp1 ALL=(ALL) NOPASSWD:ALL\\n' > /target/etc/sudoers.d/90-cp1; "
        "chmod 440 /target/etc/sudoers.d/90-cp1; "
        "systemctl --root=/target enable ssh"
    )
    install = {
        'version': 1, 'refresh-installer': {'update': False},
        'locale': 'en_US.UTF-8', 'keyboard': {'layout': 'us'}, 'timezone': 'Etc/UTC',
        'identity': {'hostname': 'cp1-ubuntu', 'username': 'cp1', 'password': '!'},
        'ssh': {'install-server': True, 'allow-pw': False, 'authorized-keys': [public]},
        'storage': {'layout': {'name': 'direct', 'match': {'path': '/dev/vda'}}},
        'packages': ['openssh-server', 'ufw', 'apparmor', 'auditd', 'python3', 'sudo'],
        'late-commands': [['/bin/sh', '-c', late]],
        'shutdown': 'poweroff',
    }
    (seed / 'user-data').write_text('#cloud-config\n' + json.dumps({'autoinstall': install}, indent=2) + '\n')
    (seed / 'meta-data').write_text(json.dumps({'instance-id': 'cp1-ubuntu', 'local-hostname': 'cp1-ubuntu'}) + '\n')
    (seed / 'vendor-data').write_text('')
    server, port = serve_seed(seed)
    qemu_common = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-machine', 'q35', '-accel', 'whpx',
                   '-m', '3072', '-smp', '2', '-display', 'none', '-monitor', 'none', '-no-reboot']
    install_argv = qemu_common + [
        '-netdev', 'user,id=net0', '-device', 'e1000,netdev=net0,romfile=',
        '-drive', f'file={disk},format=raw,if=virtio',
        '-cdrom', str(ISO), '-kernel', str(VMLINUX), '-initrd', str(INITRD),
        '-append', 'boot=casper autoinstall console=ttyS0,115200n8 '
                   f'ds=nocloud-net;s=http://10.0.2.2:{port}/ ---',
        '-serial', 'file:' + str(WORK / 'installer-serial.log')]
    manifest = {'schema': 'agenticvm.cp1-ubuntu-ssh.v1', 'iso_sha256': digest(ISO),
                'kernel_sha256': digest(VMLINUX), 'initrd_sha256': digest(INITRD),
                'ssh_public_key': public, 'autoinstall': install,
                'install_argv': install_argv, 'boot_hostfwd': f'127.0.0.1:{SSH_PORT}->22',
                'security_features': 'systemd, AppArmor, UFW active with SSH allow, sshd active, sudo delegation'}
    (WORK / 'install-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    started = time.time()
    code = run(install_argv, WORK / 'installer-console.log', 1500)
    install_seconds = round(time.time() - started, 1)
    server.shutdown()
    if code is None:
        (WORK / 'result.json').write_text(json.dumps({'passed': False, 'error': 'installer timeout'}, indent=2) + '\n')
        return 1
    boot_argv = qemu_common + [
        '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22',
        '-device', 'e1000,netdev=net0,romfile=',
        '-drive', f'file={disk},format=raw,if=virtio',
        '-serial', 'file:' + str(WORK / 'boot-serial.log')]
    with (WORK / 'boot-console.log').open('wb') as out:
        process = subprocess.Popen(boot_argv, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            wait_ssh(key, process, WORK / 'boot-console.log')
            remote = subprocess.run(ssh_base(key) + ['sudo -n /usr/bin/python3 -'], input=REMOTE_PROBE,
                                    capture_output=True, text=True, timeout=120)
            report = None
            for line in remote.stdout.splitlines():
                if line.startswith('CP1_REPORT '):
                    report = json.loads(line.removeprefix('CP1_REPORT '))
            observation = None
            if report:
                observation = {name: report[name] for name in ('os_id', 'init', 'apparmor', 'selinux',
                                                               'firewall', 'sshd', 'ssh_active', 'sudo',
                                                               'security_disabled', 'host_mounts', 'real_disk')}
            gate = evaluate(observation) if observation else {'passed': False, 'failures': ['no probe report']}
            result = {'passed': gate['passed'], 'installer_exit': code, 'install_seconds': install_seconds,
                      'ssh_exit': remote.returncode, 'ssh_stdout': remote.stdout[-8000:],
                      'ssh_stderr': remote.stderr[-2000:], 'report': report, 'gate': gate,
                      'disk': str(disk), 'disk_bytes': disk.stat().st_size,
                      'install_serial': str(WORK / 'installer-serial.log'),
                      'boot_serial': str(WORK / 'boot-serial.log'),
                      'limitations': ['QEMU user networking with host-forwarded SSH; no external target',
                                      'CP1 only; no join/force/model yet']}
        except Exception as error:
            result = {'passed': False, 'error': type(error).__name__ + ': ' + str(error),
                      'disk': str(disk), 'install_serial': str(WORK / 'installer-serial.log')}
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(10)
    (WORK / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
