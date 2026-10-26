"""R1b native scout: stock Ubuntu searches its user net and pings a host responder.

Read-only: no installation, no target modification. The host responder is an
authenticated garden member endpoint, not a real agent install.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.garden_ping import PingServer
from agenticvm.garden_policy import GardenPolicy
from agenticvm.garden_store import GardenStore

QEMU = ROOT / 'tools/qemu/11.1.0/qemu-system-x86_64.exe'
DISK = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1.raw'
KEY = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1_ed25519'
SSH = Path(r'C:\Windows\System32\OpenSSH\ssh.exe')
WORK = ROOT / 'runtime/redteam-r1b-native'
SSH_PORT = 22022
PING_PORT = 7443


def wait_ssh(process, deadline=240):
    started = time.monotonic()
    command = [str(SSH), '-i', str(KEY), '-p', str(SSH_PORT), '-o', 'BatchMode=yes',
               '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
               '-o', 'ConnectTimeout=3', 'cp1@127.0.0.1', 'true']
    while time.monotonic() - started < deadline:
        if process.poll() is not None:
            raise RuntimeError('target exited before SSH')
        if subprocess.run(command, capture_output=True, timeout=10).returncode == 0:
            return
        time.sleep(3)
    raise TimeoutError('SSH did not become ready')


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    store = GardenStore(ROOT / 'runtime/redteam-r0')
    state = store.load()
    key = store.ping_key()
    garden = state.policy.digest()
    member = state.membership.status()['mother']
    server = PingServer(key, garden, member, host='0.0.0.0', port=PING_PORT).start()
    boot_log = WORK / 'boot.log'
    qemu = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-machine', 'q35', '-accel', 'whpx',
            '-m', '2048', '-smp', '2', '-display', 'none', '-monitor', 'none', '-no-reboot',
            '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22',
            '-device', 'e1000,netdev=net0,romfile=',
            '-drive', f'file={DISK},format=raw,if=virtio',
            '-serial', 'file:' + str(boot_log)]
    with (WORK / 'console.log').open('wb') as out:
        process = subprocess.Popen(qemu, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            wait_ssh(process)
            scout = f'''import concurrent.futures, hashlib, hmac, json, secrets, socket, time
KEY = bytes.fromhex("{key.hex()}")
GARDEN = "{garden}"
MEMBER = "{member}"
PORT = {PING_PORT}
def challenge():
    p = {{"schema":"agenticvm.garden-challenge.v1","id":secrets.token_hex(8),"garden":GARDEN,
          "member":MEMBER,"nonce":secrets.token_hex(16),"issued":int(time.time()),"expires":int(time.time())+30}}
    p["mac"] = hmac.new(KEY, json.dumps(p,sort_keys=True,separators=(',',':')).encode(), hashlib.sha256).hexdigest()
    return p
def probe(ip):
    try:
        with socket.create_connection((ip, PORT), timeout=.25) as s:
            s.settimeout(2)
            c = challenge()
            s.sendall((json.dumps(c)+chr(10)).encode())
            raw = b''
            while b'\\n' not in raw and len(raw) < 8192:
                raw += s.recv(1024)
            r = json.loads(raw.split(b'\\n',1)[0])
            if r.get('schema') != 'agenticvm.garden-response.v1' or r.get('id') != c['id']:
                return {{'address':ip,'reachable':True,'garden_member':False,'error':'correlation'}}
            body = {{k:r[k] for k in ('schema','id','garden','member','nonce','received')}}
            if not hmac.compare_digest(r['mac'], hmac.new(KEY,json.dumps(body,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest()):
                return {{'address':ip,'reachable':True,'garden_member':False,'error':'mac'}}
            return {{'address':ip,'reachable':True,'garden_member':True,'member':MEMBER}}
    except Exception:
        return None
hits=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
    for result in pool.map(probe, [f'10.0.2.{{n}}' for n in range(1,255)]):
        if result: hits.append(result)
print('R1B_REPORT '+json.dumps({{'scope':'10.0.2.0/24','port':PORT,'hits':hits,
    'responsive':len([h for h in hits if h.get('reachable')]),
    'garden_members':len([h for h in hits if h.get('garden_member')])}},sort_keys=True))
'''
            remote = subprocess.run([str(SSH), '-i', str(KEY), '-p', str(SSH_PORT), '-o', 'BatchMode=yes',
                                     '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
                                     '-o', 'ConnectTimeout=5', 'cp1@127.0.0.1',
                                     'sudo -n /usr/bin/python3 -'], input=scout, capture_output=True, text=True, timeout=180)
            report = None
            for line in remote.stdout.splitlines():
                if line.startswith('R1B_REPORT '):
                    report = json.loads(line.removeprefix('R1B_REPORT '))
            passed = bool(report and report['garden_members'] >= 1 and report['responsive'] >= 1
                          and server.events and all(e['ok'] for e in server.events))
            store.receipt('r1b_native_search_ping', passed=passed, report=report,
                          server_events=server.events)
            result = {'schema': 'agenticvm.r1b-native.v1', 'passed': passed,
                      'ssh_exit': remote.returncode, 'report': report,
                      'server_events': server.events, 'serial': str(boot_log),
                      'limitations': ['One stock Ubuntu scout; host responder is not a VM',
                                      'No join/force/install; read-only search and ping',
                                      'QEMU user networking; no external/LAN scope']}
            (WORK / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
            return 0 if passed else 1
        finally:
            server.stop()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(15)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(10)


if __name__ == '__main__':
    raise SystemExit(main())
