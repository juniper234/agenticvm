"""CP6a: private-torrent agent package delivery to a stock Ubuntu target.

Signed manifest + bounded BitTorrent + SHA-256 + safe staging unpack. No tracker,
DHT, PEX, execution or service installation. One owned target only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm import bounded_torrent
from agenticvm.garden_identity import allowed_signers, canonical, generate, sign

QEMU = ROOT / 'tools/qemu/11.1.0/qemu-system-x86_64.exe'
DISK = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1.raw'
SSH_KEY = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1_ed25519'
SSH = Path(r'C:\Windows\System32\OpenSSH\ssh.exe')
WORK = ROOT / 'runtime/redteam-cp6a'
SSH_PORT = 22022
SEED_PORT = 7445
MOTHER = 'm-9000000000000009'
NS = 'agenticvm-garden-v1'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ssh(command, *, input=None, timeout=60):
    return subprocess.run([str(SSH), '-i', str(SSH_KEY), '-p', str(SSH_PORT), '-o', 'BatchMode=yes',
                           '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
                           '-o', 'ConnectTimeout=5', 'cp1@127.0.0.1', command],
                          input=input, capture_output=True, text=True, timeout=timeout)


def wait(process, deadline=240):
    started = time.monotonic()
    while time.monotonic() - started < deadline:
        if process.poll() is not None:
            raise RuntimeError('target exited before SSH')
        if ssh('true', timeout=10).returncode == 0:
            return
        time.sleep(3)
    raise TimeoutError('SSH did not become ready')


def package():
    archive = WORK / 'agent.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        for relative in ('src/agenticvm/__init__.py', 'src/agenticvm/garden_identity.py',
                         'src/agenticvm/garden_ping.py', 'src/agenticvm/garden_policy.py'):
            path = ROOT / relative
            tar.add(path, arcname='agent/' + path.name)
    return archive


REMOTE = r'''import base64, hashlib, json, pathlib, subprocess, sys, tarfile
sys.path.insert(0, "/tmp/cp6")
import bounded_torrent
manifest_raw = base64.b64decode("__MANIFEST__")
signature = base64.b64decode("__SIG__")
pathlib.Path("/tmp/cp6/cp6-signature.sig").write_bytes(signature)
verify = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "verify", "-f", "/tmp/cp6/mother-allowed",
                         "-I", "__MOTHER__", "-n", "__NS__", "-s", "/tmp/cp6/cp6-signature.sig"],
                        input=manifest_raw, capture_output=True, timeout=20)
if verify.returncode:
    print("CP6A_ERROR manifest signature")
    raise SystemExit(2)
manifest = json.loads(manifest_raw)
if manifest.get("schema") != "agenticvm.cp6-package.v1":
    print("CP6A_ERROR schema")
    raise SystemExit(3)
payload = manifest["payload"]
receipt = bounded_torrent.download(payload["torrent"], "/tmp/cp6/agent.tar.gz",
    name=payload["name"], size=payload["bytes"], sha256=payload["sha256"],
    source=("10.0.2.2", __PORT__))
if hashlib.sha256(pathlib.Path("/tmp/cp6/agent.tar.gz").read_bytes()).hexdigest() != payload["sha256"]:
    print("CP6A_ERROR post-download hash")
    raise SystemExit(4)
staging = pathlib.Path("/tmp/cp6/staging")
staging.mkdir(exist_ok=True)
with tarfile.open("/tmp/cp6/agent.tar.gz") as tar:
    names = tar.getnames()
    if any(name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts for name in names):
        print("CP6A_ERROR unsafe archive path")
        raise SystemExit(5)
    tar.extractall(staging, filter="data")
print("CP6A_REPORT " + json.dumps({"manifest_verified": True, "payload": payload,
    "torrent": receipt, "files": sorted(p.name for p in staging.rglob("*") if p.is_file()),
    "extracted": str(staging)}, sort_keys=True))
'''


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    tmp = WORK / 'tmp'
    tmp.mkdir(exist_ok=True)
    archive = package()
    entry = {'bytes': archive.stat().st_size, 'sha256': sha(archive),
             'torrent': bounded_torrent.metadata(archive)}
    key_folder = WORK / 'mother-key'
    if key_folder.exists():
        import shutil
        shutil.rmtree(key_folder)
    mother_identity = generate(MOTHER, key_folder)
    manifest = {'schema': 'agenticvm.cp6-package.v1', 'version': 'cp6a-1',
                'payload': {'name': 'agent.tar.gz', 'bytes': entry['bytes'],
                            'sha256': entry['sha256'], 'torrent': entry['torrent']}}
    manifest_raw = canonical(manifest)
    signature = sign(mother_identity['private'], manifest_raw)
    allowed = allowed_signers(MOTHER, mother_identity['public']).encode()
    (WORK / 'manifest.json').write_bytes(manifest_raw)
    (WORK / 'manifest.sig').write_bytes(signature)
    seed = bounded_torrent.Seeder({'agent.tar.gz': (archive, entry)}, ('0.0.0.0', SEED_PORT),
                                  '127.0.0.1')
    boot_log = WORK / 'boot.log'
    qemu = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-name', 'cp6a-target', '-machine', 'q35',
            '-accel', 'whpx', '-m', '1536', '-smp', '2', '-display', 'none', '-monitor', 'none',
            '-no-reboot', '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22',
            '-device', 'e1000,netdev=net0,romfile=', '-snapshot',
            '-drive', f'file={DISK},format=raw,if=virtio', '-serial', 'file:' + str(boot_log)]
    with (WORK / 'console.log').open('wb') as out:
        process = subprocess.Popen(qemu, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   env=dict(os.environ, TEMP=str(tmp), TMP=str(tmp)),
                                   creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            wait(process)
            ssh('sudo -n mkdir -p /tmp/cp6')
            local_torrent = (ROOT / 'src/agenticvm/bounded_torrent.py').read_bytes()
            ssh('sudo -n tee /tmp/cp6/bounded_torrent.py >/dev/null',
                input=local_torrent.decode(), timeout=30)
            ssh('sudo -n tee /tmp/cp6/mother-allowed >/dev/null', input=allowed.decode(), timeout=30)
            remote = (REMOTE.replace('__MANIFEST__', base64.b64encode(manifest_raw).decode())
                      .replace('__SIG__', base64.b64encode(signature).decode())
                      .replace('__MOTHER__', MOTHER).replace('__NS__', NS)
                      .replace('__PORT__', str(SEED_PORT)))
            result = ssh('sudo -n python3 -', input=remote, timeout=180)
            report = None
            for line in result.stdout.splitlines():
                if line.startswith('CP6A_REPORT '):
                    report = json.loads(line.removeprefix('CP6A_REPORT '))
            passed = bool(report and result.returncode == 0
                          and report['payload']['sha256'] == entry['sha256']
                          and report['torrent']['sha256_verified'])
            output = {'schema': 'agenticvm.cp6a.private-torrent.v1', 'passed': passed,
                      'mother': MOTHER, 'target': 'stock Ubuntu 24.04 CP1',
                      'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
                      'manifest_signature': 'Ed25519 SSHSIG verified by target',
                      'package': entry, 'seed_port': SEED_PORT,
                      'seed_stats': seed.stats, 'result': report,
                      'ssh_stdout': result.stdout[-4000:], 'ssh_stderr': result.stderr[-2000:],
                      'security': 'CP1 Ubuntu security state retained; no host endpoint',
                      'limitations': ['Staging delivery only; no service installation or join',
                                      'Private torrent seeder and target are local/owned',
                                      'Keys are generated in the runtime work tree']}
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
