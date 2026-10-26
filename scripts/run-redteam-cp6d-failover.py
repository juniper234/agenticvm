"""CP6d: private peer failover, target self-install and rollback denial."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm import bounded_torrent
from agenticvm.garden_identity import allowed_signers, canonical, generate, sign

QEMU = ROOT / 'tools/qemu/11.1.0/qemu-system-x86_64.exe'
DISK = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1.raw'
SSH_KEY = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1_ed25519'
SSH = Path(r'C:\Windows\System32\OpenSSH\ssh.exe')
WORK = ROOT / 'runtime/redteam-cp6d'
SSH_PORT, BAD_PORT, GOOD_PORT = 22022, 7448, 7449
MOTHER, NS = 'm-d00000000000000d', 'agenticvm-garden-v1'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ssh(command, *, input=None, timeout=60):
    return subprocess.run([str(SSH), '-i', str(SSH_KEY), '-p', str(SSH_PORT), '-o', 'BatchMode=yes',
                           '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
                           '-o', 'ConnectTimeout=5', 'cp1@127.0.0.1', command],
                          input=input, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)


def wait(process):
    started = 0
    while started < 240:
        if process.poll() is not None:
            raise RuntimeError('target exited before SSH')
        if ssh('true', timeout=10).returncode == 0:
            return
        time.sleep(3); started += 3
    raise TimeoutError('SSH not ready')


REMOTE = r'''import base64, json, pathlib, shutil, sys
sys.path.insert(0, "/tmp/cp6")
from agenticvm import garden_identity, garden_package
import bounded_torrent
garden_identity.SSH_KEYGEN = pathlib.Path("/usr/bin/ssh-keygen")
manifest_v2 = json.loads(pathlib.Path("/tmp/cp6/manifest-v2.json").read_bytes())
manifest_v1 = json.loads(pathlib.Path("/tmp/cp6/manifest-v1.json").read_bytes())
sig_v2 = base64.b64decode(pathlib.Path("/tmp/cp6/sig-v2.b64").read_text())
sig_v1 = base64.b64decode(pathlib.Path("/tmp/cp6/sig-v1.b64").read_text())
allowed = "/tmp/cp6/allowed"
p = manifest_v2["payload"]
first_error = None
receipt = None
for source in (("10.0.2.2", __BAD__), ("10.0.2.2", __GOOD__)):
    try:
        receipt = bounded_torrent.download(p["torrent"], "/tmp/cp6/agent.tar.gz", name=p["name"],
            size=p["bytes"], sha256=p["sha256"], source=source, attempts=1, timeout=10)
        break
    except Exception as e:
        first_error = type(e).__name__ + ": " + str(e)[:120]
if receipt is None:
    print("CP6D_ERROR both peers failed"); raise SystemExit(2)
garden_package.validate(manifest_v2, sig_v2, allowed, "__MOTHER__", expected_sha=p["sha256"])
staging = pathlib.Path("/tmp/cp6/staging"); staging.mkdir(exist_ok=True)
files = garden_package.extract("/tmp/cp6/agent.tar.gz", staging, expected_sha=p["sha256"])
target = pathlib.Path("/opt/agenticvm"); target.mkdir(parents=True, exist_ok=True)
for path in (staging / "agent").iterdir():
    if path.is_file(): shutil.copy2(path, target / path.name)
state = pathlib.Path("/var/lib/agenticvm"); state.mkdir(parents=True, exist_ok=True)
(state / "installed.json").write_text(json.dumps({"version": manifest_v2["version"], "package_sha256": p["sha256"]}))
rollback_denied = False
try:
    garden_package.validate(manifest_v1, sig_v1, allowed, "__MOTHER__", expected_sha=p["sha256"],
                            current_version=manifest_v2["version"])
except Exception as e:
    rollback_denied = "rollback" in str(e)
print("CP6D_REPORT " + json.dumps({"first_peer_error": first_error, "second_peer": receipt,
    "installed_version": manifest_v2["version"], "files": files, "rollback_denied": rollback_denied,
    "installed_state": json.loads((state / "installed.json").read_text())}, sort_keys=True))
'''


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    tmp = WORK / 'tmp'; tmp.mkdir()
    key = generate(MOTHER, WORK / 'key')
    allowed = allowed_signers(MOTHER, key['public'])
    archive = WORK / 'agent.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        for relative in ('src/agenticvm/garden_identity.py', 'guest/agent_join.py'):
            path = ROOT / relative
            tar.add(path, arcname='agent/' + path.name)
    entry = {'bytes': archive.stat().st_size, 'sha256': sha(archive),
             'torrent': bounded_torrent.metadata(archive)}
    payload = {'name': 'agent.tar.gz', 'bytes': entry['bytes'], 'sha256': entry['sha256'], 'torrent': entry['torrent']}
    v2 = {'schema': 'agenticvm.cp6-package.v1', 'version': 'cp6a-2', 'payload': payload}
    v1 = {'schema': 'agenticvm.cp6-package.v1', 'version': 'cp6a-1', 'payload': payload}
    raw2, raw1 = canonical(v2), canonical(v1)
    sig2, sig1 = sign(key['private'], raw2), sign(key['private'], raw1)
    (WORK / 'manifest-v2.json').write_bytes(raw2); (WORK / 'manifest-v1.json').write_bytes(raw1)
    (WORK / 'sig-v2.b64').write_text(base64.b64encode(sig2).decode())
    (WORK / 'sig-v1.b64').write_text(base64.b64encode(sig1).decode())
    (WORK / 'allowed').write_text(allowed)
    seed = bounded_torrent.Seeder({'agent.tar.gz': (archive, entry)}, ('0.0.0.0', GOOD_PORT), '127.0.0.1')
    qemu = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-name', 'cp6d-target', '-machine', 'q35',
            '-accel', 'whpx', '-m', '1536', '-smp', '2', '-display', 'none', '-monitor', 'none', '-no-reboot',
            '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22',
            '-device', 'e1000,netdev=net0,romfile=', '-snapshot',
            '-drive', f'file={DISK},format=raw,if=virtio', '-serial', 'file:' + str(WORK / 'boot.log')]
    with (WORK / 'console.log').open('wb') as out:
        process = subprocess.Popen(qemu, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   env=dict(os.environ, TEMP=str(tmp), TMP=str(tmp)),
                                   creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            wait(process)
            ssh('sudo -n mkdir -p /tmp/cp6/agenticvm')
            for name in ('bounded_torrent.py',):
                ssh(f'sudo -n tee /tmp/cp6/{name} >/dev/null', input=(ROOT / 'src/agenticvm' / name).read_text())
            for name in ('__init__.py', 'garden_identity.py', 'garden_package.py'):
                ssh(f'sudo -n tee /tmp/cp6/agenticvm/{name} >/dev/null', input=(ROOT / 'src/agenticvm' / name).read_text())
            for name, data in (('manifest-v2.json', raw2), ('manifest-v1.json', raw1),
                               ('sig-v2.b64', base64.b64encode(sig2)), ('sig-v1.b64', base64.b64encode(sig1)),
                               ('allowed', allowed.encode())):
                ssh(f'sudo -n tee /tmp/cp6/{name} >/dev/null', input=data.decode(), timeout=30)
            remote = REMOTE.replace('__MOTHER__', MOTHER).replace('__BAD__', str(BAD_PORT)).replace('__GOOD__', str(GOOD_PORT))
            result = ssh('sudo -n python3 -', input=remote, timeout=180)
            report = None
            for line in result.stdout.splitlines():
                if line.startswith('CP6D_REPORT '):
                    report = json.loads(line.removeprefix('CP6D_REPORT '))
            passed = bool(report and report['first_peer_error'] and report['second_peer']['sha256_verified']
                          and report['installed_version'] == 'cp6a-2' and report['rollback_denied']
                          and report['installed_state']['version'] == 'cp6a-2' and result.returncode == 0)
            output = {'schema': 'agenticvm.cp6d.failover-rollback.v1', 'passed': passed,
                      'package': entry, 'report': report, 'ssh_stdout': result.stdout[-4000:],
                      'ssh_stderr': result.stderr[-2000:],
                      'limitations': ['Two private seed addresses; first intentionally unavailable',
                                      'Target self-installs files but no systemd service/join in this gate',
                                      'Single owned target; no full swarm or zero-touch trigger']}
            (WORK / 'result.json').write_text(json.dumps(output, indent=2, sort_keys=True) + '\n')
            return 0 if passed else 1
        finally:
            seed.close()
            if process.poll() is None:
                process.terminate()
                try: process.wait(15)
                except subprocess.TimeoutExpired: process.kill(); process.wait(10)


if __name__ == '__main__':
    raise SystemExit(main())
