"""R1b-5: four stock Ubuntu members with mutual Ed25519 SSHSIG authentication.

Mother signs each challenge; targets verify it before responding and sign their
response with their own key. No shared HMAC. Read-only lab; no join/install.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import socketserver
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.garden_identity import allowed_signers, canonical, generate

QEMU = ROOT / 'tools/qemu/11.1.0/qemu-system-x86_64.exe'
DISK = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1.raw'
SSH_KEY = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1_ed25519'
SSH = Path(r'C:\Windows\System32\OpenSSH\ssh.exe')
WORK = ROOT / 'runtime/redteam-r1b5'
LAB_PORT = 23458
NS = 'agenticvm-garden-v1'
MOTHER = {'name': 'mother', 'ssh': 22222, 'ip': '10.68.0.10', 'member': 'm-5000000000000005'}
NODES = [
    {'name': 'target1', 'ssh': 22223, 'ip': '10.68.0.11', 'member': 'm-6000000000000006'},
    {'name': 'target2', 'ssh': 22224, 'ip': '10.68.0.12', 'member': 'm-7000000000000007'},
    {'name': 'target3', 'ssh': 22225, 'ip': '10.68.0.13', 'member': 'm-8000000000000008'},
]
MAC = ['52:54:00:88:00:10', '52:54:00:88:00:11', '52:54:00:88:00:12', '52:54:00:88:00:13']


class FrameHub(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clients, self.lock, self.frames = set(), threading.Lock(), 0

    def broadcast(self, source, frame):
        with self.lock:
            self.frames += 1
            targets = [c for c in self.clients if c is not source]
        for target in targets:
            try:
                target.sendall(len(frame).to_bytes(4, 'big') + frame)
            except OSError:
                with self.lock:
                    self.clients.discard(target)


class HubHandler(socketserver.BaseRequestHandler):
    def handle(self):
        with self.server.lock:
            self.server.clients.add(self.request)
        self.request.settimeout(300)
        try:
            while True:
                header = self._read(4)
                if not header:
                    return
                length = int.from_bytes(header, 'big')
                if not 1 <= length <= 65536:
                    return
                frame = self._read(length)
                if len(frame) != length:
                    return
                self.server.broadcast(self.request, frame)
        except OSError:
            return
        finally:
            with self.server.lock:
                self.server.clients.discard(self.request)

    def _read(self, count):
        data = b''
        while len(data) < count:
            chunk = self.request.recv(count - len(data))
            if not chunk:
                return b''
            data += chunk
        return data


def ssh(port, command, *, input=None, timeout=60):
    return subprocess.run([str(SSH), '-i', str(SSH_KEY), '-p', str(port), '-o', 'BatchMode=yes',
                           '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
                           '-o', 'ConnectTimeout=5', 'cp1@127.0.0.1', command],
                          input=input, capture_output=True, text=True, timeout=timeout)


def wait(port, process, deadline=300):
    started = time.monotonic()
    while time.monotonic() - started < deadline:
        if process.poll() is not None:
            raise RuntimeError('guest exited before SSH')
        if ssh(port, 'true', timeout=10).returncode == 0:
            return
        time.sleep(3)
    raise TimeoutError('guest SSH did not become ready')


def qemu_args(index, node):
    tmp = WORK / ('tmp-' + node['name'])
    tmp.mkdir(exist_ok=True)
    args = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-name', 'r1b5-' + node['name'],
            '-machine', 'q35', '-accel', 'whpx', '-m', '1024', '-smp', '2',
            '-display', 'none', '-monitor', 'none', '-no-reboot',
            '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{node["ssh"]}-:22',
            '-device', 'e1000,netdev=net0,romfile=',
            '-netdev', f'socket,id=lab,connect=127.0.0.1:{LAB_PORT}',
            '-device', f'e1000,netdev=lab,romfile=,mac={MAC[index]}',
            '-snapshot', '-drive', f'file={DISK},format=raw,if=virtio',
            '-serial', 'file:' + str(WORK / (node['name'] + '.log'))]
    return args, dict(os.environ, TEMP=str(tmp), TMP=str(tmp))


def configure(node):
    command = (
        "set -eu; "
        "iface=$(ip -o link | awk -F': ' '$2 != \"lo\" {print $2}' | sed -n '2p'); test -n \"$iface\"; "
        f"sudo -n ip link set \"$iface\" up; sudo -n ip addr add {node['ip']}/24 dev \"$iface\" 2>/dev/null || true; "
        f"sudo -n hostnamectl set-hostname r1b5-{node['name']}; "
        "sudo -n sh -c 'truncate -s 0 /etc/machine-id; systemd-machine-id-setup'; "
        "sudo -n rm -f /etc/ssh/ssh_host_*; sudo -n ssh-keygen -A; "
        "sudo -n systemctl restart ssh; ip -brief address; hostname; cat /etc/machine-id"
    )
    result = ssh(node['ssh'], command, timeout=60)
    if result.returncode:
        raise RuntimeError('node config failed: ' + node['name'] + ': ' + result.stderr[-1000:])
    time.sleep(3)
    return result.stdout.strip()


TARGET = r'''import base64, json, os, subprocess, socket, time
MEMBER = "__MEMBER__"; NS = "agenticvm-garden-v1"
PRIVATE = "__PRIVATE__"; MOTHER_MEMBER = "__MOTHER_MEMBER__"; MOTHER_PUBLIC = "__MOTHER_PUBLIC__"
open("/tmp/r1b5-key", "wb").write(base64.b64decode(PRIVATE)); os.chmod("/tmp/r1b5-key", 0o600)
open("/tmp/r1b5-mother-allowed", "w").write(f'{MOTHER_MEMBER} namespaces="{NS}" {MOTHER_PUBLIC}\n')
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 7443)); s.listen(16)
with open("/tmp/r1b5-server.log", "a") as log:
    log.write("READY " + MEMBER + "\n"); log.flush()
    while True:
        c, peer = s.accept()
        with c:
            c.settimeout(4)
            try:
                raw = b""
                while b"\n" not in raw and len(raw) < 16384: raw += c.recv(2048)
                q = json.loads(raw.split(b"\n", 1)[0])
                if q.get("schema") != "agenticvm.garden-challenge.v1" or q.get("member") != MEMBER: raise ValueError("challenge")
                challenge_sig = base64.b64decode(q.pop("sig"))
                cpayload = json.dumps(q, sort_keys=True, separators=(",", ":")).encode()
                open("/tmp/r1b5-challenge-sig", "wb").write(challenge_sig)
                v = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "verify", "-f", "/tmp/r1b5-mother-allowed",
                                    "-I", MOTHER_MEMBER, "-n", NS, "-s", "/tmp/r1b5-challenge-sig"],
                                   input=cpayload, capture_output=True, timeout=15)
                if v.returncode: raise ValueError("mother signature")
                r = {"schema":"agenticvm.garden-response.v1","id":q["id"],"garden":q["garden"],
                     "member":MEMBER,"nonce":q["nonce"],"received":int(time.time())}
                open("/tmp/r1b5-response", "wb").write(json.dumps(r, sort_keys=True, separators=(",", ":")).encode())
                p = subprocess.run(["/usr/bin/ssh-keygen","-Y","sign","-f","/tmp/r1b5-key","-n",NS,"/tmp/r1b5-response"],
                                   capture_output=True, timeout=15)
                if p.returncode: raise ValueError("sign")
                r["sig"] = base64.b64encode(open("/tmp/r1b5-response.sig", "rb").read()).decode()
                c.sendall((json.dumps(r) + "\n").encode()); log.write("OK " + peer[0] + "\n"); log.flush()
            except Exception as e:
                log.write("ERR " + repr(e)[:500] + "\n"); log.flush()
'''

MOTHER_SCAN = r'''import base64, json, os, secrets, socket, subprocess, time
MOTHER_MEMBER = "__MOTHER_MEMBER__"; NS = "agenticvm-garden-v1"
PRIVATE = "__PRIVATE__"; ALLOWED = """__ALLOWED__"""
TARGETS = __TARGETS__
open("/tmp/r1b5-mother.key", "wb").write(base64.b64decode(PRIVATE)); os.chmod("/tmp/r1b5-mother.key", 0o600)
open("/tmp/r1b5-target-allowed", "w").write(ALLOWED)
def probe(ip, member):
    try:
        with socket.create_connection((ip, 7443), timeout=.5) as s:
            s.settimeout(3)
            q={"schema":"agenticvm.garden-challenge.v1","id":secrets.token_hex(8),"garden":"r1b5",
               "member":member,"nonce":secrets.token_hex(16),"issued":int(time.time()),"expires":int(time.time())+30}
            path = "/tmp/r1b5-challenge-" + q["id"]
            open(path, "wb").write(json.dumps(q, sort_keys=True, separators=(",", ":")).encode())
            sign = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", "/tmp/r1b5-mother.key", "-n", NS,
                                   path], capture_output=True, timeout=15)
            if sign.returncode: return {"address":ip,"member":member,"ok":False,"error":"mother-sign"}
            q["sig"] = base64.b64encode(open(path + ".sig", "rb").read()).decode()
            s.sendall((json.dumps(q) + "\n").encode())
            raw = b""
            while b"\n" not in raw and len(raw) < 32768: raw += s.recv(4096)
            r = json.loads(raw.split(b"\n", 1)[0])
            if r.get("id") != q["id"] or r.get("member") != member or "sig" not in r:
                return {"address":ip,"member":member,"ok":False,"error":"correlation"}
            body = {k:r[k] for k in ("schema","id","garden","member","nonce","received")}
            payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            open("/tmp/r1b5-response-sig", "wb").write(base64.b64decode(r["sig"]))
            p = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "verify", "-f", "/tmp/r1b5-target-allowed",
                                "-I", member, "-n", NS, "-s", "/tmp/r1b5-response-sig"], input=payload,
                               capture_output=True, timeout=15)
            return {"address":ip,"member":member,"ok":p.returncode == 0,"error":None if p.returncode == 0 else "signature"}
    except Exception as e:
        return {"address":ip,"member":member,"ok":False,"error":type(e).__name__}
hits = [probe(ip, member) for ip, member in TARGETS.items()]
print("R1B5_REPORT " + json.dumps({"hits":hits,"verified":len([h for h in hits if h.get("ok")])}, sort_keys=True))
'''


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    keys = WORK / 'keys'
    keys.mkdir()
    mother_identity = generate(MOTHER['member'], keys / MOTHER['member'])
    identities = {MOTHER['member']: mother_identity}
    allowed_targets = []
    for node in NODES:
        identity = generate(node['member'], keys / node['member'])
        identities[node['member']] = identity
        allowed_targets.append(allowed_signers(node['member'], identity['public']))
    target_allowed = ''.join(allowed_targets)
    hub = FrameHub(('127.0.0.1', LAB_PORT), HubHandler)
    threading.Thread(target=hub.serve_forever, daemon=True).start()
    processes = []
    for index, node in enumerate([MOTHER] + NODES):
        args, env = qemu_args(index, node)
        processes.append((node, subprocess.Popen(args, stdin=subprocess.DEVNULL,
                         stdout=(WORK / (node['name'] + '-console.log')).open('wb'),
                         stderr=subprocess.STDOUT, env=env,
                         creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)))
    try:
        for node, process in processes:
            wait(node['ssh'], process)
        identities_out = {node['name']: configure(node) for node, _ in processes}
        for node in NODES:
            ssh(node['ssh'], 'sudo -n ufw allow 7443/tcp', timeout=30)
            server = (TARGET.replace('__MEMBER__', node['member'])
                      .replace('__PRIVATE__', base64.b64encode(Path(identities[node['member']]['private']).read_bytes()).decode())
                      .replace('__MOTHER_MEMBER__', MOTHER['member'])
                      .replace('__MOTHER_PUBLIC__', mother_identity['public']))
            ssh(node['ssh'], 'sudo -n tee /tmp/r1b5-server.py >/dev/null', input=server, timeout=30)
            ssh(node['ssh'], 'sudo -n sh -c "nohup python3 /tmp/r1b5-server.py >/tmp/r1b5-server.log 2>&1 &"', timeout=30)
        time.sleep(3)
        targets = {node['ip']: node['member'] for node in NODES}
        scan = (MOTHER_SCAN.replace('__MOTHER_MEMBER__', MOTHER['member'])
                .replace('__PRIVATE__', base64.b64encode(Path(mother_identity['private']).read_bytes()).decode())
                .replace('__ALLOWED__', target_allowed)
                .replace('__TARGETS__', repr(targets)))
        scan_error = None
        try:
            result = ssh(MOTHER['ssh'], 'sudo -n python3 -', input=scan, timeout=60)
        except subprocess.TimeoutExpired:
            result, scan_error = None, 'scanner timeout'
        report = None
        if result is not None:
            for line in result.stdout.splitlines():
                if line.startswith('R1B5_REPORT '):
                    report = json.loads(line.removeprefix('R1B5_REPORT '))
        ids = [(node['name'], ssh(node['ssh'], 'cat /etc/machine-id', timeout=20).stdout.strip())
               for node in [MOTHER] + NODES]
        distinct = len({v for _, v in ids}) == len(ids)
        logs = {node['name']: ssh(node['ssh'], 'cat /tmp/r1b5-server.log 2>/dev/null', timeout=20).stdout[-1000:]
                for node in NODES}
        passed = bool(report and report['verified'] == len(NODES) and distinct
                      and result is not None and result.returncode == 0)
        output = {'schema': 'agenticvm.r1b5.mutual.v1', 'passed': passed,
                  'mother': MOTHER, 'targets': NODES, 'identities': identities_out,
                  'machine_ids': ids, 'distinct_machine_ids': distinct, 'report': report,
                  'target_logs': logs, 'hub_frames': hub.frames, 'scan_error': scan_error,
                  'identity': 'mutual Ed25519 SSHSIG; mother challenge signed; target response signed; no shared HMAC',
                  'limitations': ['Snapshot clones; no independent install provenance',
                                  'Keys in runtime work tree, not production custody',
                                  'No join/install/model/replication']}
        (WORK / 'result.json').write_text(json.dumps(output, indent=2, sort_keys=True) + '\n')
        return 0 if passed else 1
    finally:
        for _, process in processes:
            if process.poll() is None:
                process.terminate()
                try: process.wait(15)
                except subprocess.TimeoutExpired: process.kill(); process.wait(10)
        hub.shutdown(); hub.server_close()


if __name__ == '__main__':
    raise SystemExit(main())
