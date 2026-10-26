"""R1b-2: two snapshot-booted stock Ubuntu VMs on a private QEMU lab link.

Read-only network test: the mother guest scans the lab subnet and pings the
target guest's HMAC responder. Host SSH is management only; no host endpoint
responds on the lab network.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.garden_ping import PingServer
from agenticvm.garden_store import GardenStore

QEMU = ROOT / 'tools/qemu/11.1.0/qemu-system-x86_64.exe'
DISK = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1.raw'
KEY = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1_ed25519'
SSH = Path(r'C:\Windows\System32\OpenSSH\ssh.exe')
WORK = ROOT / 'runtime/redteam-r1b2'
MOTHER_SSH, TARGET_SSH = 22022, 22023
LAB_PORT = 23456
MOTHER_IP, TARGET_IP = '10.66.0.10', '10.66.0.11'
MEMBER = 'm-1111111111111111'


def ssh(port, command, *, input=None, timeout=60):
    return subprocess.run([str(SSH), '-i', str(KEY), '-p', str(port), '-o', 'BatchMode=yes',
                           '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
                           '-o', 'ConnectTimeout=5', 'cp1@127.0.0.1', command],
                          input=input, capture_output=True, text=True, timeout=timeout)


def wait(port, process, deadline=240):
    started = time.monotonic()
    while time.monotonic() - started < deadline:
        if process.poll() is not None:
            raise RuntimeError('guest exited before SSH')
        if ssh(port, 'true', timeout=10).returncode == 0:
            return
        time.sleep(3)
    raise TimeoutError('SSH guest did not become ready')


def qemu_args(name, ssh_port, lab, snapshot=True):
    args = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-name', name, '-machine', 'q35',
            '-accel', 'whpx', '-m', '2048', '-smp', '2', '-display', 'none', '-monitor', 'none',
            '-no-reboot', '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22',
            '-device', 'e1000,netdev=net0,romfile=', '-netdev', lab,
            '-device', 'e1000,netdev=lab,romfile=', '-drive', f'file={DISK},format=raw,if=virtio']
    if snapshot:
        args.insert(args.index('-drive'), '-snapshot')
    args += ['-serial', 'file:' + str(WORK / f'{name}.log')]
    return args


def configure_lab(port, address):
    command = (
        "set -eu; "
        "iface=$(ip -o link | awk -F': ' '$2 != \"lo\" {print $2}' | sed -n '2p'); "
        "test -n \"$iface\"; "
        f"sudo -n ip link set \"$iface\" up; "
        f"sudo -n ip addr add {address}/24 dev \"$iface\" 2>/dev/null || true; "
        "ip -brief address"
    )
    result = ssh(port, command)
    if result.returncode:
        raise RuntimeError('lab address failed: ' + result.stderr[-1000:])
    return result.stdout.strip()


TARGET_SERVER = r'''import hashlib, hmac, json, socket, time
KEY = bytes.fromhex("__KEY__")
MEMBER = "__MEMBER__"
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 7443)); s.listen(16)
with open("/tmp/r1b2-server.log", "a") as log:
    log.write("READY\n"); log.flush()
    while True:
        c, peer = s.accept()
        with c:
            c.settimeout(3)
            try:
                raw = b""
                while b"\n" not in raw and len(raw) < 8192:
                    raw += c.recv(1024)
                q = json.loads(raw.split(b"\n", 1)[0])
                if q.get("schema") != "agenticvm.garden-challenge.v1" or q.get("member") != MEMBER:
                    raise ValueError("challenge mismatch")
                body = {k: q[k] for k in ("schema", "id", "garden", "member", "nonce", "issued", "expires")}
                if not hmac.compare_digest(q["mac"], hmac.new(KEY, json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()):
                    raise ValueError("challenge mac")
                r = {"schema": "agenticvm.garden-response.v1", "id": q["id"], "garden": q["garden"],
                     "member": MEMBER, "nonce": q["nonce"], "received": int(time.time())}
                r["mac"] = hmac.new(KEY, json.dumps(r, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
                c.sendall((json.dumps(r) + "\n").encode())
                log.write("OK " + peer[0] + "\n"); log.flush()
            except Exception as e:
                log.write("ERR " + str(e) + "\n"); log.flush()
'''


MOTHER_SCAN = r'''import concurrent.futures, hashlib, hmac, json, secrets, socket, time
KEY = bytes.fromhex("__KEY__")
MEMBER = "__MEMBER__"
def challenge():
    p = {"schema": "agenticvm.garden-challenge.v1", "id": secrets.token_hex(8), "garden": "r1b2",
         "member": MEMBER, "nonce": secrets.token_hex(16), "issued": int(time.time()), "expires": int(time.time()) + 30}
    p["mac"] = hmac.new(KEY, json.dumps(p, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    return p
def probe(ip):
    try:
        with socket.create_connection((ip, 7443), timeout=.3) as s:
            s.settimeout(2); q = challenge(); s.sendall((json.dumps(q) + "\n").encode())
            raw = b""
            while b"\n" not in raw and len(raw) < 8192: raw += s.recv(1024)
            r = json.loads(raw.split(b"\n", 1)[0])
            if r.get("id") != q["id"]: return {"address": ip, "ok": False, "error": "correlation"}
            body = {k: r[k] for k in ("schema", "id", "garden", "member", "nonce", "received")}
            if not hmac.compare_digest(r["mac"], hmac.new(KEY, json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()):
                return {"address": ip, "ok": False, "error": "mac"}
            return {"address": ip, "ok": True, "member": MEMBER}
    except Exception:
        return None
hits = []
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
    for result in pool.map(probe, [f"10.66.0.{n}" for n in range(1, 255)]):
        if result: hits.append(result)
print("R1B2_REPORT " + json.dumps({"hits": hits, "members": len([h for h in hits if h.get("ok")])}, sort_keys=True))
'''


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    state = GardenStore(ROOT / 'runtime/redteam-r0').load()
    key = GardenStore(ROOT / 'runtime/redteam-r0').ping_key()
    mother_args = qemu_args('r1b2-mother', MOTHER_SSH, f'socket,id=lab,listen=127.0.0.1:{LAB_PORT}')
    target_args = qemu_args('r1b2-target', TARGET_SSH, f'socket,id=lab,connect=127.0.0.1:{LAB_PORT}')
    mother_tmp, target_tmp = WORK / 'tmp-mother', WORK / 'tmp-target'
    mother_tmp.mkdir(exist_ok=True)
    target_tmp.mkdir(exist_ok=True)
    mother_env = dict(os.environ, TEMP=str(mother_tmp), TMP=str(mother_tmp))
    target_env = dict(os.environ, TEMP=str(target_tmp), TMP=str(target_tmp))
    (WORK / 'launch.json').write_text(json.dumps({'mother': mother_args, 'target': target_args}, indent=2))
    with (WORK / 'mother-console.log').open('wb') as mout, (WORK / 'target-console.log').open('wb') as tout:
        mother = subprocess.Popen(mother_args, stdin=subprocess.DEVNULL, stdout=mout, stderr=subprocess.STDOUT,
                                  env=mother_env,
                                  creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        target = subprocess.Popen(target_args, stdin=subprocess.DEVNULL, stdout=tout, stderr=subprocess.STDOUT,
                                  env=target_env,
                                  creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            wait(MOTHER_SSH, mother)
            wait(TARGET_SSH, target)
            mother_if = configure_lab(MOTHER_SSH, MOTHER_IP)
            target_if = configure_lab(TARGET_SSH, TARGET_IP)
            ssh(TARGET_SSH, 'sudo -n ufw allow 7443/tcp', timeout=30)
            script = TARGET_SERVER.replace('__KEY__', key.hex()).replace('__MEMBER__', MEMBER)
            ssh(TARGET_SSH, 'sudo -n tee /tmp/r1b2-server.py >/dev/null', input=script, timeout=30)
            ssh(TARGET_SSH, 'sudo -n sh -c "nohup python3 /tmp/r1b2-server.py >/tmp/r1b2-server.log 2>&1 &"', timeout=30)
            time.sleep(3)
            scan = MOTHER_SCAN.replace('__KEY__', key.hex()).replace('__MEMBER__', MEMBER)
            result = ssh(MOTHER_SSH, 'sudo -n python3 -', input=scan, timeout=120)
            report = None
            for line in result.stdout.splitlines():
                if line.startswith('R1B2_REPORT '):
                    report = json.loads(line.removeprefix('R1B2_REPORT '))
            log = ssh(TARGET_SSH, 'cat /tmp/r1b2-server.log', timeout=30).stdout
            passed = bool(report and report['members'] >= 1 and result.returncode == 0)
            output = {'schema': 'agenticvm.r1b2.two-vm.v1', 'passed': passed,
                      'mother_ssh': MOTHER_SSH, 'target_ssh': TARGET_SSH,
                      'lab': {'mother': MOTHER_IP, 'target': TARGET_IP, 'transport': 'QEMU socket point-to-point'},
                      'mother_interfaces': mother_if, 'target_interfaces': target_if,
                      'scan_exit': result.returncode, 'report': report, 'target_server_log': log[-2000:],
                      'source': 'stock Ubuntu 24.04 CP1 snapshot; security features remain enabled',
                      'limitations': ['Two VMs, not four', 'No join/install/model/replication',
                                      'SSH host keys not pinned for this probe', 'QEMU socket link is lab-only']}
            (WORK / 'result.json').write_text(json.dumps(output, indent=2, sort_keys=True) + '\n')
            return 0 if passed else 1
        finally:
            for process in (target, mother):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(15)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(10)


if __name__ == '__main__':
    raise SystemExit(main())
