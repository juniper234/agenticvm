"""CP6b: install the torrent-delivered package and let the target initiate join.

Stock Ubuntu target, systemd service, target-generated Ed25519 key, mother-signed
single-use invite, TLS 1.3 pinned mother certificate, mother-signed receipt.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm import bounded_torrent
from agenticvm.garden_identity import allowed_signers, canonical, generate, sign, verify
from agenticvm.garden_membership import Member, utc
from agenticvm.garden_policy import GardenPolicy
from agenticvm.garden_store import GardenStore

QEMU = ROOT / 'tools/qemu/11.1.0/qemu-system-x86_64.exe'
OPENSSL = Path(r'C:\Program Files\Git\usr\bin\openssl.exe')
DISK = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1.raw'
SSH_KEY = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1_ed25519'
SSH = Path(r'C:\Windows\System32\OpenSSH\ssh.exe')
WORK = ROOT / 'runtime/redteam-cp6b'
SSH_PORT, SEED_PORT, JOIN_PORT = 22022, 7446, 7460
MOTHER_MEMBER, TARGET_MEMBER = 'm-a00000000000000a', 'm-b00000000000000b'
TARGET_IP = '10.0.2.15'
NS = 'agenticvm-garden-v1'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ssh(command, *, input=None, timeout=60):
    return subprocess.run([str(SSH), '-i', str(SSH_KEY), '-p', str(SSH_PORT), '-o', 'BatchMode=yes',
                           '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
                           '-o', 'ConnectTimeout=5', 'cp1@127.0.0.1', command],
                          input=input, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)


def wait(process, deadline=240):
    started = time.monotonic()
    while time.monotonic() - started < deadline:
        if process.poll() is not None:
            raise RuntimeError('target exited before SSH')
        if ssh('true', timeout=10).returncode == 0:
            return
        time.sleep(3)
    raise TimeoutError('SSH did not become ready')


def cert():
    crt, key = WORK / 'mother.crt', WORK / 'mother.key'
    subprocess.run([str(OPENSSL), 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '1',
                    '-keyout', str(key), '-out', str(crt), '-subj', '/CN=10.0.2.2',
                    '-addext', 'subjectAltName=IP:10.0.2.2'], check=True, capture_output=True)
    return crt, key


class JoinServer:
    def __init__(self, crt, key, mother, invite, invite_raw, store, policy):
        self.mother, self.invite, self.invite_raw = mother, invite, invite_raw
        self.store, self.policy = store, policy
        self.result = None
        self.errors = []
        self.used = False
        self.idempotent = False
        self.stopped = threading.Event()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(crt, key)
        self.context = context
        self.listener = socket.socket()
        self.listener.bind(('0.0.0.0', JOIN_PORT))
        self.listener.listen(8)
        self.listener.settimeout(1)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopped.is_set():
            try:
                raw, peer = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                raw.settimeout(30)
                with self.context.wrap_socket(raw, server_side=True) as tls:
                    data = b''
                    while b'\n' not in data and len(data) < 65536:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    request = json.loads(data.split(b'\n', 1)[0])
                    receipt = self.admit(request)
                    tls.sendall((json.dumps(receipt) + '\n').encode())
                    self.result = {'peer': peer[0], 'request': request, 'receipt': receipt}
            except Exception as error:
                self.errors.append(type(error).__name__ + ': ' + str(error)[:500])

    def admit(self, request):
        if self.used:
            raise ValueError('invite already used')
        fields = {'schema', 'member', 'garden', 'package_sha256', 'nonce', 'issued',
                  'expires', 'public_key', 'sig'}
        if set(request) != fields or request['schema'] != 'agenticvm.garden-join-request.v1':
            raise ValueError('join request schema')
        if (request['member'] != TARGET_MEMBER or request['garden'] != self.policy.digest()
                or request['nonce'] != self.invite['nonce']
                or request['package_sha256'] != self.invite['package_sha256']
                or int(request['expires']) <= int(time.time())):
            raise ValueError('join request binding')
        public = request['public_key']
        if not isinstance(public, str) or not public.startswith('ssh-ed25519 '):
            raise ValueError('join public key')
        signature = base64.b64decode(request['sig'])
        body = {key: request[key] for key in fields if key != 'sig'}
        allowed = WORK / 'target-allowed'
        allowed.write_text(allowed_signers(TARGET_MEMBER, public))
        if not verify(allowed, TARGET_MEMBER, canonical(body), signature):
            raise ValueError('join request signature')
        state = self.store.load()
        existing = state.membership.members.get(TARGET_MEMBER)
        if existing:
            if not self.idempotent:
                raise ValueError('member already admitted')
            if existing.public_key_sha256 != hashlib.sha256(public.encode()).hexdigest():
                raise ValueError('member key conflict')
            receipt = {'schema': 'agenticvm.garden-join-receipt.v1', 'member': TARGET_MEMBER,
                       'garden': self.policy.digest(), 'nonce': request['nonce'],
                       'package_sha256': request['package_sha256'], 'admitted': True,
                       'duplicate': True, 'issued': int(time.time()),
                       'expires': int(time.time()) + 60}
            receipt['sig'] = base64.b64encode(sign(self.mother['private'], canonical(receipt))).decode()
            self.used = True
            return receipt
        mother_id = state.membership.status()['mother']
        member = Member(TARGET_MEMBER, 2, 'offshoot', 1, 'active', 'cp6b-target', TARGET_IP,
                        mother_id, hashlib.sha256(public.encode()).hexdigest(), utc(), utc())
        state.membership.members[TARGET_MEMBER] = member
        state.membership.validate()
        state.revision += 1
        self.store.save(state)
        self.store.receipt('member_joined', member=TARGET_MEMBER, address=TARGET_IP,
                           public_key_sha256=member.public_key_sha256,
                           package_sha256=request['package_sha256'])
        receipt = {'schema': 'agenticvm.garden-join-receipt.v1', 'member': TARGET_MEMBER,
                   'garden': self.policy.digest(), 'nonce': request['nonce'],
                   'package_sha256': request['package_sha256'], 'admitted': True,
                   'issued': int(time.time()), 'expires': int(time.time()) + 60}
        receipt['sig'] = base64.b64encode(sign(self.mother['private'], canonical(receipt))).decode()
        self.used = True
        return receipt

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(3)


DOWNLOAD = r'''import base64, hashlib, json, pathlib, subprocess, sys, tarfile
sys.path.insert(0, "/tmp/cp6")
import bounded_torrent
raw = base64.b64decode("__MANIFEST__")
pathlib.Path("/tmp/cp6/manifest.json").write_bytes(raw)
pathlib.Path("/tmp/cp6/manifest.sig").write_bytes(base64.b64decode("__SIG__"))
v = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "verify", "-f", "/tmp/cp6/mother-allowed",
                    "-I", "__MOTHER__", "-n", "__NS__", "-s", "/tmp/cp6/manifest.sig"],
                   input=raw, capture_output=True, timeout=20)
if v.returncode: print("CP6B_ERROR manifest signature"); raise SystemExit(2)
manifest = json.loads(raw); p = manifest["payload"]
r = bounded_torrent.download(p["torrent"], "/tmp/cp6/agent.tar.gz", name=p["name"],
    size=p["bytes"], sha256=p["sha256"], source=("10.0.2.2", __SEED__))
if not r["sha256_verified"]: raise SystemExit(3)
staging = pathlib.Path("/tmp/cp6/staging"); staging.mkdir(exist_ok=True)
with tarfile.open("/tmp/cp6/agent.tar.gz") as tar: tar.extractall(staging, filter="data")
print("CP6B_DOWNLOAD " + json.dumps({"verified": True, "bytes": p["bytes"], "files": sorted(x.name for x in staging.iterdir())}))
'''


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    tmp = WORK / 'tmp'
    tmp.mkdir()
    remote = '/tmp/agenticvm-' + secrets.token_hex(8)
    crt, key = cert()
    policy = GardenPolicy.create('cp6b', ['10.0.2.0/24'], methods=('ssh', 'tcp'),
                                 max_total=4, max_depth=2, max_active=2)
    store = GardenStore(WORK / 'garden')
    store.init(policy)
    mother = generate(MOTHER_MEMBER, WORK / 'mother-key')
    target_pkg = WORK / 'agent.tar.gz'
    with tarfile.open(target_pkg, 'w:gz') as tar:
        for relative in ('src/agenticvm/__init__.py', 'src/agenticvm/garden_identity.py',
                         'src/agenticvm/garden_ping.py', 'src/agenticvm/garden_policy.py',
                         'guest/agent_join.py'):
            path = ROOT / relative
            tar.add(path, arcname='agent/' + path.name)
    entry = {'bytes': target_pkg.stat().st_size, 'sha256': sha(target_pkg),
             'torrent': bounded_torrent.metadata(target_pkg)}
    manifest = {'schema': 'agenticvm.cp6-package.v1', 'version': 'cp6b-1', 'payload': {
        'name': 'agent.tar.gz', 'bytes': entry['bytes'], 'sha256': entry['sha256'],
        'torrent': entry['torrent']}}
    manifest_raw = canonical(manifest)
    manifest_sig = sign(mother['private'], manifest_raw)
    invite = {'schema': 'agenticvm.garden-invite.v1', 'member': TARGET_MEMBER,
              'garden': policy.digest(), 'package_sha256': entry['sha256'],
              'nonce': secrets.token_hex(16), 'expires': int(time.time()) + 300}
    invite_raw = canonical(invite)
    invite_sig = sign(mother['private'], invite_raw)
    (WORK / 'invite.json').write_bytes(invite_raw)
    (WORK / 'invite.sig').write_text(json.dumps({'sig': base64.b64encode(invite_sig).decode()}))
    mother_allowed = allowed_signers(MOTHER_MEMBER, mother['public'])
    (WORK / 'mother-allowed').write_text(mother_allowed)
    seed = bounded_torrent.Seeder({'agent.tar.gz': (target_pkg, entry)}, ('0.0.0.0', SEED_PORT),
                                  '127.0.0.1')
    join = JoinServer(crt, key, mother, invite, invite_raw, store, policy)
    qemu = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-name', 'cp6b-target', '-machine', 'q35',
            '-accel', 'whpx', '-m', '1536', '-smp', '2', '-display', 'none', '-monitor', 'none',
            '-no-reboot', '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22',
            '-device', 'e1000,netdev=net0,romfile=', '-snapshot',
            '-drive', f'file={DISK},format=raw,if=virtio',
            '-serial', 'file:' + str(WORK / 'boot.log')]
    with (WORK / 'console.log').open('wb') as out:
        process = subprocess.Popen(qemu, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   env=dict(os.environ, TEMP=str(tmp), TMP=str(tmp)),
                                   creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            wait(process)
            ssh(f'sudo -n install -d -m 700 {remote}')
            ssh(f'sudo -n tee {remote}/bounded_torrent.py >/dev/null',
                input=(ROOT / 'src/agenticvm/bounded_torrent.py').read_text(), timeout=30)
            ssh(f'sudo -n tee {remote}/mother-allowed >/dev/null', input=mother_allowed, timeout=30)
            download = (DOWNLOAD.replace('__MANIFEST__', base64.b64encode(manifest_raw).decode())
                        .replace('__SIG__', base64.b64encode(manifest_sig).decode())
                        .replace('__MOTHER__', MOTHER_MEMBER).replace('__NS__', NS)
                        .replace('__SEED__', str(SEED_PORT)).replace('/tmp/cp6', remote))
            got = ssh('sudo -n python3 -', input=download, timeout=180)
            if got.returncode:
                raise RuntimeError('download failed: ' + got.stderr[-1000:])
            # Install the delivered package and the join service.
            ssh('sudo -n install -d -m 700 /opt/agenticvm /etc/agenticvm /var/lib/agenticvm')
            ssh(f'sudo -n sh -c "install -m 644 {remote}/staging/agent/__init__.py {remote}/staging/agent/garden_identity.py {remote}/staging/agent/garden_ping.py {remote}/staging/agent/garden_policy.py /opt/agenticvm/; install -m 755 {remote}/staging/agent/agent_join.py /opt/agenticvm/agent_join.py"', timeout=30)
            ssh('sudo -n tee /etc/agenticvm/mother-allowed >/dev/null', input=mother_allowed, timeout=30)
            ssh('sudo -n tee /etc/agenticvm/invite.json >/dev/null', input=invite_raw.decode(), timeout=30)
            ssh('sudo -n tee /etc/agenticvm/invite.sig >/dev/null',
                input=(WORK / 'invite.sig').read_text(), timeout=30)
            ssh('sudo -n tee /etc/agenticvm/mother.pub >/dev/null', input=mother['public'] + '\n', timeout=30)
            ssh('sudo -n tee /etc/agenticvm/mother.pem >/dev/null', input=crt.read_text(), timeout=30)
            config = {'mother_host': '10.0.2.2', 'mother_port': JOIN_PORT, 'member': TARGET_MEMBER,
                      'garden': policy.digest(), 'package_sha256': entry['sha256'],
                      'mother_member': MOTHER_MEMBER, 'mother_cert': '/etc/agenticvm/mother.pem',
                      'mother_allowed': '/etc/agenticvm/mother-allowed',
                      'invite': '/etc/agenticvm/invite.json', 'invite_sig': '/etc/agenticvm/invite.sig',
                      'package': remote + '/agent.tar.gz'}
            ssh('sudo -n tee /etc/agenticvm/join.json >/dev/null', input=json.dumps(config), timeout=30)
            unit = '''[Unit]
Description=AgenticVM target-initiated join
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/agenticvm/agent_join.py /etc/agenticvm/join.json
[Install]
WantedBy=multi-user.target
'''
            ssh('sudo -n tee /etc/systemd/system/agenticvm-join.service >/dev/null', input=unit, timeout=30)
            ssh('sudo -n systemctl daemon-reload; sudo -n systemctl enable --now agenticvm-join.service', timeout=60)
            deadline, joined = time.monotonic() + 180, None
            diag = ''
            while time.monotonic() < deadline:
                result = ssh('sudo -n cat /var/lib/agenticvm/joined.json 2>/dev/null', timeout=20)
                if result.returncode == 0 and result.stdout.strip():
                    joined = json.loads(result.stdout)
                    break
                if join.result and join.result.get('error'):
                    break
                time.sleep(3)
            if joined is None:
                diag = ssh('systemctl status agenticvm-join.service --no-pager -l; journalctl -u agenticvm-join.service --no-pager -n 40; ls -l /etc/agenticvm /var/lib/agenticvm', timeout=30).stdout[-4000:]
            state = store.load()
            passed = bool(joined and joined.get('joined') and join.result and join.result.get('receipt')
                          and state.membership.get(TARGET_MEMBER).state == 'active')
            output = {'schema': 'agenticvm.cp6b.join.v1', 'passed': passed,
                      'package': entry, 'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
                      'manifest_signature': 'Ed25519 SSHSIG', 'download': got.stdout[-3000:],
                      'join_server': join.result, 'target_joined': joined,
                      'service_diagnostics': diag, 'garden': state.status(), 'service': 'agenticvm-join.service',
                      'transport': 'TLS 1.3 with pinned self-signed mother certificate',
                      'security': 'CP1 Ubuntu security state retained; target initiated join',
                      'limitations': ['Single owned target', 'Target key generated in guest; invite single-use',
                                      'Self-signed lab certificate', 'No multi-peer/rollback/tamper suite yet']}
            (WORK / 'result.json').write_text(json.dumps(output, indent=2, sort_keys=True) + '\n')
            return 0 if passed else 1
        finally:
            join.close()
            seed.close()
            if process.poll() is None:
                process.terminate()
                try: process.wait(15)
                except subprocess.TimeoutExpired: process.kill(); process.wait(10)


if __name__ == '__main__':
    raise SystemExit(main())
