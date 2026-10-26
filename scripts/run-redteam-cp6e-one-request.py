"""CP6e: one mother request installs the package and starts target join."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm import bounded_torrent
from agenticvm.garden_identity import allowed_signers, canonical, generate, sign
from agenticvm.garden_policy import GardenPolicy
from agenticvm.garden_store import GardenStore

spec = importlib.util.spec_from_file_location('cp6b_support', ROOT / 'scripts/run-redteam-cp6b-join.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)

QEMU = ROOT / 'tools/qemu/11.1.0/qemu-system-x86_64.exe'
DISK = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1.raw'
SSH_KEY = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1_ed25519'
WORK = ROOT / 'runtime/redteam-cp6e'
SSH_PORT, SEED_PORT, JOIN_PORT = 22022, 7450, 7460
MOTHER_MEMBER, TARGET_MEMBER = 'm-e00000000000000e', 'm-f00000000000000f'


BOOTSTRAP = r'''import base64, json, pathlib, shutil, subprocess, sys
sys.path.insert(0, "/tmp/cp6")
payload = json.loads(base64.b64decode("__PAYLOAD__"))
root = pathlib.Path("/tmp/cp6"); root.mkdir(parents=True, exist_ok=True)
(root / "agenticvm").mkdir(exist_ok=True)
for name, value in (("bounded_torrent.py", payload["bounded_torrent"]),
                    ("agenticvm/__init__.py", payload["init"]),
                    ("agenticvm/garden_identity.py", payload["garden_identity"]),
                    ("agenticvm/garden_package.py", payload["garden_package"])):
    (root / name).write_bytes(base64.b64decode(value))
from agenticvm import garden_identity, garden_package
import bounded_torrent
garden_identity.SSH_KEYGEN = pathlib.Path("/usr/bin/ssh-keygen")
manifest = base64.b64decode(payload["manifest"])
(root / "manifest.json").write_bytes(manifest)
(root / "sig.b64").write_text(payload["sig"])
(root / "allowed").write_bytes(base64.b64decode(payload["allowed"]))
sig = base64.b64decode(payload["sig"])
body = json.loads(manifest)
p = body["payload"]
garden_package.validate(body, sig, str(root / "allowed"), "__MOTHER__", expected_sha=p["sha256"])
receipt = bounded_torrent.download(p["torrent"], "/tmp/cp6/agent.tar.gz", name=p["name"],
    size=p["bytes"], sha256=p["sha256"], source=("10.0.2.2", __SEED__), attempts=2, timeout=30)
staging = root / "staging"; staging.mkdir(exist_ok=True)
garden_package.extract("/tmp/cp6/agent.tar.gz", staging, expected_sha=p["sha256"])
target = pathlib.Path("/opt/agenticvm"); target.mkdir(parents=True, exist_ok=True)
for path in (staging / "agent").iterdir():
    if path.is_file(): shutil.copy2(path, target / path.name)
etc = pathlib.Path("/etc/agenticvm"); etc.mkdir(parents=True, exist_ok=True)
(etc / "mother-allowed").write_bytes(base64.b64decode(payload["allowed"]))
(etc / "invite.json").write_bytes(base64.b64decode(payload["invite"]))
(etc / "invite.sig").write_bytes(base64.b64decode(payload["invite_sig"]))
(etc / "mother.pem").write_bytes(base64.b64decode(payload["cert"]))
(etc / "join.json").write_bytes(base64.b64decode(payload["config"]))
unit = """[Unit]
Description=AgenticVM target-initiated join
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/agenticvm/agent_join.py /etc/agenticvm/join.json
[Install]
WantedBy=multi-user.target
"""
pathlib.Path("/etc/systemd/system/agenticvm-join.service").write_text(unit)
subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True, timeout=30)
subprocess.run(["/usr/bin/systemctl", "enable", "--now", "agenticvm-join.service"], check=True, timeout=60)
print("CP6E_BOOTSTRAP " + json.dumps({"installed": sorted(x.name for x in target.iterdir()),
    "torrent": receipt, "service_started": True}))
'''


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    tmp = WORK / 'tmp'; tmp.mkdir()
    remote = '/tmp/agenticvm-' + secrets.token_hex(8)
    support.WORK = WORK
    support.JOIN_PORT = JOIN_PORT
    support.SEED_PORT = SEED_PORT
    support.SSH_PORT = SSH_PORT
    support.MOTHER_MEMBER = MOTHER_MEMBER
    support.TARGET_MEMBER = TARGET_MEMBER
    crt, key = support.cert()
    policy = GardenPolicy.create('cp6e', ['10.0.2.0/24'], methods=('ssh', 'tcp'),
                                 max_total=4, max_depth=2, max_active=2)
    store = GardenStore(WORK / 'garden'); store.init(policy)
    mother = generate(MOTHER_MEMBER, WORK / 'mother-key')
    archive = WORK / 'agent.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        for relative in ('src/agenticvm/__init__.py', 'src/agenticvm/garden_identity.py',
                         'src/agenticvm/garden_ping.py', 'src/agenticvm/garden_policy.py',
                         'guest/agent_join.py'):
            path = ROOT / relative
            tar.add(path, arcname='agent/' + path.name)
    entry = {'bytes': archive.stat().st_size, 'sha256': sha(archive),
             'torrent': bounded_torrent.metadata(archive)}
    manifest = {'schema': 'agenticvm.cp6-package.v1', 'version': 'cp6e-1',
                'payload': {'name': 'agent.tar.gz', 'bytes': entry['bytes'],
                            'sha256': entry['sha256'], 'torrent': entry['torrent']}}
    manifest_raw = canonical(manifest)
    manifest_sig = sign(mother['private'], manifest_raw)
    invite = {'schema': 'agenticvm.garden-invite.v1', 'member': TARGET_MEMBER,
              'garden': policy.digest(), 'package_sha256': entry['sha256'],
              'nonce': secrets.token_hex(16), 'expires': int(time.time()) + 300}
    invite_raw = canonical(invite)
    invite_sig = sign(mother['private'], invite_raw)
    allowed = allowed_signers(MOTHER_MEMBER, mother['public'])
    config = {'mother_host': '10.0.2.2', 'mother_port': JOIN_PORT, 'member': TARGET_MEMBER,
              'garden': policy.digest(), 'package_sha256': entry['sha256'],
              'mother_member': MOTHER_MEMBER, 'mother_cert': '/etc/agenticvm/mother.pem',
              'mother_allowed': '/etc/agenticvm/mother-allowed',
              'invite': '/etc/agenticvm/invite.json', 'invite_sig': '/etc/agenticvm/invite.sig'}
    payload = {
        'manifest': base64.b64encode(manifest_raw).decode(),
        'sig': base64.b64encode(manifest_sig).decode(),
        'allowed': base64.b64encode(allowed.encode()).decode(),
        'invite': base64.b64encode(invite_raw).decode(),
        'invite_sig': base64.b64encode(json.dumps({'sig': base64.b64encode(invite_sig).decode()}).encode()).decode(),
        'cert': base64.b64encode(crt.read_bytes()).decode(),
        'config': base64.b64encode(json.dumps(config).encode()).decode(),
        'bounded_torrent': base64.b64encode((ROOT / 'src/agenticvm/bounded_torrent.py').read_bytes()).decode(),
        'garden_identity': base64.b64encode((ROOT / 'src/agenticvm/garden_identity.py').read_bytes()).decode(),
        'garden_package': base64.b64encode((ROOT / 'src/agenticvm/garden_package.py').read_bytes()).decode(),
        'init': base64.b64encode((ROOT / 'src/agenticvm/__init__.py').read_bytes()).decode(),
    }
    bootstrap = (BOOTSTRAP.replace('__PAYLOAD__', base64.b64encode(json.dumps(payload).encode()).decode())
                 .replace('__MOTHER__', MOTHER_MEMBER).replace('__SEED__', str(SEED_PORT))
                 .replace('/tmp/cp6', remote))
    seed = bounded_torrent.Seeder({'agent.tar.gz': (archive, entry)}, ('0.0.0.0', SEED_PORT), '127.0.0.1')
    join = support.JoinServer(crt, key, mother, invite, invite_raw, store, policy)
    qemu = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-name', 'cp6e-target', '-machine', 'q35',
            '-accel', 'whpx', '-m', '1536', '-smp', '2', '-display', 'none', '-monitor', 'none', '-no-reboot',
            '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22',
            '-device', 'e1000,netdev=net0,romfile=', '-snapshot',
            '-drive', f'file={DISK},format=raw,if=virtio', '-serial', 'file:' + str(WORK / 'boot.log')]
    with (WORK / 'console.log').open('wb') as out:
        process = subprocess.Popen(qemu, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   env=dict(os.environ, TEMP=str(tmp), TMP=str(tmp)),
                                   creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            support.wait(process)
            support.ssh(f'sudo -n install -d -m 700 {remote}')
            result = support.ssh('sudo -n python3 -', input=bootstrap, timeout=240)
            joined = None
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                read = support.ssh('sudo -n cat /var/lib/agenticvm/joined.json 2>/dev/null', timeout=20)
                if read.returncode == 0 and read.stdout.strip():
                    joined = json.loads(read.stdout); break
                if join.result and join.result.get('error'): break
                time.sleep(3)
            state = store.load()
            passed = bool(result.returncode == 0 and joined and joined.get('joined')
                          and join.result and join.result.get('receipt')
                          and state.membership.get(TARGET_MEMBER).state == 'active')
            output = {'schema': 'agenticvm.cp6e.one-request.v1', 'passed': passed,
                      'bootstrap': result.stdout[-3000:], 'bootstrap_stderr': result.stderr[-2000:],
                      'join': join.result, 'target_joined': joined, 'garden': state.status(),
                      'package': entry, 'transport': 'single SSH request -> torrent -> self-install -> TLS join',
                      'limitations': ['Single owned target', 'Self-signed lab cert', 'No multi-peer swarm/Windows',
                                      'Host SSH triggers the one bootstrap request']}
            (WORK / 'result.json').write_text(json.dumps(output, indent=2, sort_keys=True) + '\n')
            return 0 if passed else 1
        finally:
            join.close(); seed.close()
            if process.poll() is None:
                process.terminate()
                try: process.wait(15)
                except subprocess.TimeoutExpired: process.kill(); process.wait(10)


if __name__ == '__main__':
    raise SystemExit(main())
