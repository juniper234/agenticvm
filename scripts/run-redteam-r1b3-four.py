"""R1b-3: four distinct stock Ubuntu snapshot members on a shared QEMU lab.

One mother scans three targets by static lab address and verifies each target's
HMAC responder. Management SSH uses the host user network; the lab segment has
no host endpoint. Shared-key HMAC only; asymmetric identity is not claimed.
"""
from __future__ import annotations

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
from agenticvm.garden_store import GardenStore

QEMU = ROOT / 'tools/qemu/11.1.0/qemu-system-x86_64.exe'
DISK = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1.raw'
KEY = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1_ed25519'
SSH = Path(r'C:\Windows\System32\OpenSSH\ssh.exe')
WORK = ROOT / 'runtime/redteam-r1b3'
NODES = [
    {'name': 'mother', 'ssh': 22022, 'ip': '10.66.0.10', 'member': 'm-aaaaaaaaaaaaaaa1'},
    {'name': 'target1', 'ssh': 22023, 'ip': '10.66.0.11', 'member': 'm-bbbbbbbbbbbbbb2'},
    {'name': 'target2', 'ssh': 22024, 'ip': '10.66.0.12', 'member': 'm-ccccccccccccccc3'},
    {'name': 'target3', 'ssh': 22025, 'ip': '10.66.0.13', 'member': 'm-ddddddddddddddd4'},
]
LAB_PORT = 23456
MAC = ['52:54:00:66:00:10', '52:54:00:66:00:11', '52:54:00:66:00:12', '52:54:00:66:00:13']


class FrameHub(socketserver.ThreadingTCPServer):
    """Bounded Ethernet frame relay for the four owned QEMU sockets."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clients = set()
        self.lock = threading.Lock()
        self.frames = 0

    def register(self, client):
        with self.lock:
            self.clients.add(client)

    def unregister(self, client):
        with self.lock:
            self.clients.discard(client)

    def broadcast(self, source, frame):
        with self.lock:
            self.frames += 1
            targets = [c for c in self.clients if c is not source]
        for target in targets:
            try:
                target.sendall(len(frame).to_bytes(4, 'big') + frame)
            except OSError:
                self.unregister(target)


class HubHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.register(self.request)
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
            self.server.unregister(self.request)

    def _read(self, count):
        data = b''
        while len(data) < count:
            chunk = self.request.recv(count - len(data))
            if not chunk:
                return b''
            data += chunk
        return data


def ssh(port, command, *, input=None, timeout=60):
    return subprocess.run([str(SSH), '-i', str(KEY), '-p', str(port), '-o', 'BatchMode=yes',
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
    args = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-name', 'r1b3-' + node['name'],
            '-machine', 'q35', '-accel', 'whpx', '-m', '1024', '-smp', '2',
            '-display', 'none', '-monitor', 'none', '-no-reboot',
            '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{node["ssh"]}-:22',
            '-device', 'e1000,netdev=net0,romfile=',
            '-netdev', f'socket,id=lab,connect=127.0.0.1:{LAB_PORT}',
            '-device', f'e1000,netdev=lab,romfile=,mac={MAC[index]}',
            '-snapshot', '-drive', f'file={DISK},format=raw,if=virtio',
            '-serial', 'file:' + str(WORK / (node['name'] + '.log'))]
    env = dict(os.environ, TEMP=str(tmp), TMP=str(tmp))
    return args, env


def configure(node):
    iface_cmd = "iface=$(ip -o link | awk -F': ' '$2 != \"lo\" {print $2}' | sed -n '2p'); test -n \"$iface\"; " \
                f"sudo -n ip link set \"$iface\" up; sudo -n ip addr add {node['ip']}/24 dev \"$iface\" 2>/dev/null || true; " \
                f"sudo -n hostnamectl set-hostname r1b3-{node['name']}; " \
                "sudo -n sh -c 'truncate -s 0 /etc/machine-id; systemd-machine-id-setup'; " \
                'sudo -n rm -f /etc/ssh/ssh_host_*; sudo -n ssh-keygen -A; ' \
                "sudo -n systemctl restart ssh; ip -brief address; hostname; cat /etc/machine-id"
    result = ssh(node['ssh'], iface_cmd, timeout=60)
    if result.returncode:
        raise RuntimeError('node config failed: ' + node['name'] + ': ' + result.stderr[-1000:])
    time.sleep(3)
    return result.stdout.strip()


SERVER = r'''import hashlib, hmac, json, socket, time
KEY = bytes.fromhex("__KEY__"); MEMBER = "__MEMBER__"; IP = "__IP__"
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 7443)); s.listen(16)
with open("/tmp/r1b3-server.log", "a") as log:
    log.write("READY " + IP + "\n"); log.flush()
    while True:
        c, peer = s.accept()
        with c:
            c.settimeout(3)
            try:
                raw = b""
                while b"\n" not in raw and len(raw) < 8192: raw += c.recv(1024)
                q = json.loads(raw.split(b"\n", 1)[0])
                if q.get("schema") != "agenticvm.garden-challenge.v1" or q.get("member") != MEMBER: raise ValueError("challenge")
                body = {k:q[k] for k in ("schema","id","garden","member","nonce","issued","expires")}
                if not hmac.compare_digest(q["mac"], hmac.new(KEY, json.dumps(body,sort_keys=True,separators=(",",":")).encode(), hashlib.sha256).hexdigest()): raise ValueError("mac")
                r = {"schema":"agenticvm.garden-response.v1","id":q["id"],"garden":q["garden"],"member":MEMBER,"nonce":q["nonce"],"received":int(time.time())}
                r["mac"] = hmac.new(KEY, json.dumps(r,sort_keys=True,separators=(",",":")).encode(), hashlib.sha256).hexdigest()
                c.sendall((json.dumps(r)+"\n").encode()); log.write("OK " + peer[0] + "\n"); log.flush()
            except Exception as e:
                log.write("ERR " + str(e) + "\n"); log.flush()
'''


SCAN = r'''import concurrent.futures, hashlib, hmac, json, secrets, socket, time
KEY = bytes.fromhex("__KEY__"); TARGETS = __TARGETS__
def challenge(member):
    p={"schema":"agenticvm.garden-challenge.v1","id":secrets.token_hex(8),"garden":"r1b3",
       "member":member,"nonce":secrets.token_hex(16),"issued":int(time.time()),"expires":int(time.time())+30}
    p["mac"]=hmac.new(KEY,json.dumps(p,sort_keys=True,separators=(",",":")).encode(),hashlib.sha256).hexdigest()
    return p
def probe(item):
    ip, member = item
    try:
        with socket.create_connection((ip,7443),timeout=.4) as s:
            s.settimeout(2); q=challenge(member); s.sendall((json.dumps(q)+"\n").encode())
            raw=b""
            while b"\n" not in raw and len(raw)<8192: raw+=s.recv(1024)
            r=json.loads(raw.split(b"\n",1)[0])
            if r.get("id")!=q["id"] or r.get("member")!=member: return {"address":ip,"member":member,"ok":False,"error":"correlation"}
            body={k:r[k] for k in ("schema","id","garden","member","nonce","received")}
            if not hmac.compare_digest(r["mac"],hmac.new(KEY,json.dumps(body,sort_keys=True,separators=(",",":")).encode(),hashlib.sha256).hexdigest()):
                return {"address":ip,"member":member,"ok":False,"error":"mac"}
            return {"address":ip,"member":member,"ok":True}
    except Exception:
        return {"address":ip,"member":member,"ok":False,"error":"unreachable"}
hits=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as p:
    for result in p.map(probe, TARGETS.items()): hits.append(result)
print("R1B3_REPORT "+json.dumps({"hits":hits,"members":len([h for h in hits if h.get("ok")])},sort_keys=True))
'''


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    hub = FrameHub(('127.0.0.1', LAB_PORT), HubHandler)
    threading.Thread(target=hub.serve_forever, daemon=True).start()
    key = GardenStore(ROOT / 'runtime/redteam-r0').ping_key()
    processes, envs = [], []
    for index, node in enumerate(NODES):
        args, env = qemu_args(index, node)
        envs.append(env)
        processes.append((node, subprocess.Popen(args, stdin=subprocess.DEVNULL,
                         stdout=(WORK / (node['name'] + '-console.log')).open('wb'),
                         stderr=subprocess.STDOUT, env=env,
                         creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)))
    try:
        for node, process in processes:
            wait(node['ssh'], process)
        identities = {node['name']: configure(node) for node, _ in processes}
        for node in NODES[1:]:
            ssh(node['ssh'], 'sudo -n ufw allow 7443/tcp', timeout=30)
            server = SERVER.replace('__KEY__', key.hex()).replace('__MEMBER__', node['member']).replace('__IP__', node['ip'])
            ssh(node['ssh'], 'sudo -n tee /tmp/r1b3-server.py >/dev/null', input=server, timeout=30)
            ssh(node['ssh'], 'sudo -n sh -c "nohup python3 /tmp/r1b3-server.py >/tmp/r1b3-server.log 2>&1 &"', timeout=30)
        time.sleep(3)
        targets = {node['ip']: node['member'] for node in NODES[1:]}
        scan = SCAN.replace('__KEY__', key.hex()).replace('__TARGETS__', repr(targets))
        result = ssh(NODES[0]['ssh'], 'sudo -n python3 -', input=scan, timeout=120)
        report = None
        for line in result.stdout.splitlines():
            if line.startswith('R1B3_REPORT '):
                report = json.loads(line.removeprefix('R1B3_REPORT '))
        machine_ids = []
        for node in NODES:
            machine_ids.append((node['name'], ssh(node['ssh'], 'cat /etc/machine-id', timeout=20).stdout.strip()))
        distinct = len({v for _, v in machine_ids}) == len(machine_ids)
        logs = {node['name']: ssh(node['ssh'], 'cat /tmp/r1b3-server.log 2>/dev/null', timeout=20).stdout[-1000:]
                for node in NODES[1:]}
        passed = bool(report and report['members'] == len(NODES) - 1 and result.returncode == 0 and distinct)
        output = {'schema': 'agenticvm.r1b3.four-member.v1', 'passed': passed,
                  'nodes': NODES, 'identities': identities, 'machine_ids': machine_ids,
                  'distinct_machine_ids': distinct, 'report': report,
                  'target_logs': logs, 'ssh_exit': result.returncode, 'hub_frames': hub.frames,
                  'transport': 'host Layer-2 frame relay; no host IP endpoint on lab',
                  'limitations': ['Shared HMAC key, not asymmetric identity', 'Snapshot clones share the CP1 SSH host-key recipe before regeneration',
                                  'No join/install/model/replication']}
        (WORK / 'result.json').write_text(json.dumps(output, indent=2, sort_keys=True) + '\n')
        return 0 if passed else 1
    finally:
        for _, process in processes:
            if process.poll() is None:
                process.terminate()
                try: process.wait(15)
                except subprocess.TimeoutExpired: process.kill(); process.wait(10)
        hub.shutdown()
        hub.server_close()


if __name__ == '__main__':
    raise SystemExit(main())
