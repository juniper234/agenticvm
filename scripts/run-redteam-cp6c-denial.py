"""CP6c: native target-side denial suite for package trust."""
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
WORK = ROOT / 'runtime/redteam-cp6c'
SSH_PORT, SEED_PORT = 22022, 7447
MOTHER, NS = 'm-c00000000000000c', 'agenticvm-garden-v1'


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
        time.sleep(3)
        started += 3
    raise TimeoutError('SSH not ready')


REMOTE = r'''import base64, json, pathlib, sys
sys.path.insert(0, "/tmp/cp6")
from agenticvm import garden_identity, garden_package
import bounded_torrent
garden_identity.SSH_KEYGEN = pathlib.Path("/usr/bin/ssh-keygen")
manifest = json.loads(pathlib.Path("/tmp/cp6/manifest.json").read_bytes())
sig = base64.b64decode(pathlib.Path("/tmp/cp6/manifest.sig.b64").read_text())
allowed = "/tmp/cp6/allowed"
results = {}
def deny(name, fn, needle):
    try:
        fn()
    except Exception as e:
        results[name] = {"denied": True, "reason": type(e).__name__ + ": " + str(e)[:200]}
    else:
        results[name] = {"denied": False, "reason": "unexpectedly accepted"}
try:
    garden_package.validate(manifest, sig, allowed, "__MOTHER__", expected_sha=manifest["payload"]["sha256"],
                            current_version="cp6b-0")
    results["valid"] = {"accepted": True}
except Exception as e:
    results["valid"] = {"accepted": False, "reason": str(e)}
bad = bytearray(sig); bad[40] ^= 1
deny("bad_signature", lambda: garden_package.validate(manifest, bytes(bad), allowed, "__MOTHER__",
     expected_sha=manifest["payload"]["sha256"]), "signature")
deny("bad_hash", lambda: garden_package.validate(manifest, sig, allowed, "__MOTHER__",
     expected_sha="0"*64), "hash")
deny("rollback", lambda: garden_package.validate(manifest, sig, allowed, "__MOTHER__",
     expected_sha=manifest["payload"]["sha256"], current_version="cp6b-2"), "rollback")
dest = pathlib.Path("/tmp/cp6/wrong.tar.gz")
deny("wrong_download", lambda: bounded_torrent.download(manifest["payload"]["torrent"], dest,
     name=manifest["payload"]["name"], size=manifest["payload"]["bytes"],
     sha256="0"*64, source=("10.0.2.2", __PORT__)), "integrity")
results["wrong_download"]["file_absent"] = not dest.exists()
dest = pathlib.Path("/tmp/cp6/valid.tar.gz")
bounded_torrent.download(manifest["payload"]["torrent"], dest, name=manifest["payload"]["name"],
    size=manifest["payload"]["bytes"], sha256=manifest["payload"]["sha256"],
    source=("10.0.2.2", __PORT__))
truncated = pathlib.Path("/tmp/cp6/truncated.tar.gz")
truncated.write_bytes(dest.read_bytes()[:32])
deny("truncated", lambda: garden_package.extract(truncated, "/tmp/cp6/out",
     expected_sha=manifest["payload"]["sha256"]), "SHA")
print("CP6C_REPORT " + json.dumps(results, sort_keys=True))
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
        for name in ('agent/a.py', 'agent/b.py'):
            data = b'print("x")\n'
            info = tarfile.TarInfo(name); info.size = len(data)
            tar.addfile(info, __import__('io').BytesIO(data))
    entry = {'bytes': archive.stat().st_size, 'sha256': sha(archive), 'torrent': bounded_torrent.metadata(archive)}
    manifest = {'schema': 'agenticvm.cp6-package.v1', 'version': 'cp6b-1',
                'payload': {'name': 'agent.tar.gz', 'bytes': entry['bytes'],
                            'sha256': entry['sha256'], 'torrent': entry['torrent']}}
    manifest_raw = canonical(manifest); signature = sign(key['private'], manifest_raw)
    (WORK / 'manifest.json').write_bytes(manifest_raw); (WORK / 'manifest.sig').write_bytes(signature)
    (WORK / 'allowed').write_text(allowed)
    seed = bounded_torrent.Seeder({'agent.tar.gz': (archive, entry)}, ('0.0.0.0', SEED_PORT), '127.0.0.1')
    qemu = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-name', 'cp6c-target', '-machine', 'q35',
            '-accel', 'whpx', '-m', '1536', '-smp', '2', '-display', 'none', '-monitor', 'none',
            '-no-reboot', '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22',
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
                ssh(f'sudo -n tee /tmp/cp6/{name} >/dev/null',
                    input=(ROOT / 'src/agenticvm' / name).read_text(), timeout=30)
            for name in ('__init__.py', 'garden_identity.py', 'garden_package.py'):
                ssh(f'sudo -n tee /tmp/cp6/agenticvm/{name} >/dev/null',
                    input=(ROOT / 'src/agenticvm' / name).read_text(), timeout=30)
            ssh('sudo -n tee /tmp/cp6/manifest.json >/dev/null', input=manifest_raw.decode(), timeout=30)
            ssh('sudo -n tee /tmp/cp6/manifest.sig.b64 >/dev/null',
                input=base64.b64encode(signature).decode(), timeout=30)
            ssh('sudo -n tee /tmp/cp6/allowed >/dev/null', input=allowed, timeout=30)
            remote = REMOTE.replace('__MOTHER__', MOTHER).replace('__PORT__', str(SEED_PORT))
            result = ssh('sudo -n python3 -', input=remote, timeout=120)
            report = None
            for line in result.stdout.splitlines():
                if line.startswith('CP6C_REPORT '):
                    report = json.loads(line.removeprefix('CP6C_REPORT '))
            expected = {'bad_signature', 'bad_hash', 'rollback', 'wrong_download', 'truncated'}
            passed = bool(report and report.get('valid', {}).get('accepted') is True
                          and all(report.get(n, {}).get('denied') for n in expected)
                          and report['wrong_download'].get('file_absent'))
            output = {'schema': 'agenticvm.cp6c.denial.v1', 'passed': passed,
                      'report': report, 'ssh_exit': result.returncode,
                      'ssh_stdout': result.stdout[-4000:], 'ssh_stderr': result.stderr[-2000:],
                      'package': entry, 'limitations': ['Tampered/wrong-hash/rollback/truncated only',
                                                        'No multi-peer swarm or service rollback yet']}
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
