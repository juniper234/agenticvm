"""CP6f: native concurrent two-peer private swarm transfer on CP1."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm import bounded_torrent

QEMU = ROOT / 'tools/qemu/11.1.0/qemu-system-x86_64.exe'
DISK = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1.raw'
SSH_KEY = ROOT / 'runtime/redteam-cp1-ubuntu-ssh/cp1_ed25519'
SSH = Path(r'C:\Windows\System32\OpenSSH\ssh.exe')
WORK = ROOT / 'runtime/redteam-cp6g'
SSH_PORT, PORT1, PORT2 = 22022, 7451, 7452


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ssh(command, *, input=None, timeout=60):
    return subprocess.run([str(SSH), '-i', str(SSH_KEY), '-p', str(SSH_PORT), '-o', 'BatchMode=yes',
                           '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
                           '-o', 'ConnectTimeout=5', 'cp1@127.0.0.1', command],
                          input=input, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)


def wait(process):
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('target exited before SSH')
        if ssh('true', timeout=10).returncode == 0:
            return
        time.sleep(3)
    raise TimeoutError('SSH not ready')


REMOTE = r'''import json, pathlib, sys
sys.path.insert(0, "/tmp/cp6")
import bounded_torrent
result = bounded_torrent.download_swarm(
    pathlib.Path("/tmp/cp6/torrent.txt").read_text().strip(),
    "/tmp/cp6/swarm.tar.gz", name="agent.tar.gz", size=__SIZE__, sha256="__SHA__",
    sources=[("10.0.2.2", __P1__), ("10.0.2.2", __P2__)], timeout=120)
print("CP6F_REPORT " + json.dumps(result, sort_keys=True))
'''


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    tmp = WORK / 'tmp'; tmp.mkdir()
    archive = WORK / 'agent.tar.gz'
    payload = os.urandom(700_000)
    info = tarfile.TarInfo('agent/swarm.bin'); info.size = len(payload)
    with tarfile.open(archive, 'w:gz') as tar:
        tar.addfile(info, io.BytesIO(payload))
    entry = {'bytes': archive.stat().st_size, 'sha256': sha(archive),
             'torrent': bounded_torrent.metadata(archive)}
    seed1 = bounded_torrent.Seeder({'agent.tar.gz': (archive, entry)}, ('0.0.0.0', PORT1), '127.0.0.1', interrupt_after_bytes=250_000)
    seed2 = bounded_torrent.Seeder({'agent.tar.gz': (archive, entry)}, ('0.0.0.0', PORT2), '127.0.0.1')
    qemu = [str(QEMU), '-L', str(QEMU.parent / 'share'), '-name', 'cp6g-target', '-machine', 'q35',
            '-accel', 'whpx', '-m', '1024', '-smp', '2', '-display', 'none', '-monitor', 'none', '-no-reboot',
            '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22',
            '-device', 'e1000,netdev=net0,romfile=', '-snapshot',
            '-drive', f'file={DISK},format=raw,if=virtio', '-serial', 'file:' + str(WORK / 'boot.log')]
    with (WORK / 'console.log').open('wb') as out:
        process = subprocess.Popen(qemu, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   env=dict(os.environ, TEMP=str(tmp), TMP=str(tmp)),
                                   creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        try:
            wait(process)
            ssh('sudo -n mkdir -p /tmp/cp6')
            ssh('sudo -n tee /tmp/cp6/bounded_torrent.py >/dev/null',
                input=(ROOT / 'src/agenticvm/bounded_torrent.py').read_text(), timeout=30)
            ssh('sudo -n tee /tmp/cp6/torrent.txt >/dev/null', input=entry['torrent'], timeout=30)
            remote = (REMOTE.replace('__SIZE__', str(entry['bytes'])).replace('__SHA__', entry['sha256'])
                      .replace('__P1__', str(PORT1)).replace('__P2__', str(PORT2)))
            result = ssh('sudo -n python3 -', input=remote, timeout=240)
            report = None
            for line in result.stdout.splitlines():
                if line.startswith('CP6F_REPORT '):
                    report = json.loads(line.removeprefix('CP6F_REPORT '))
            both = bool(report and report.get('swarm') and report.get('peer_count') == 2
                        and report.get('sha256_verified')
                        and report.get('failed_peers')
                        and report.get('retries', 0) >= 1
                        and all(seed.stats['payload_bytes_sent'] > 0 for seed in (seed1, seed2))
                        and result.returncode == 0)
            output = {'schema': 'agenticvm.cp6g.peer-loss.v1', 'passed': both,
                      'package': entry, 'client': report,
                      'seeder_stats': {'peer1': seed1.stats, 'peer2': seed2.stats},
                      'ssh_stdout': result.stdout[-3000:], 'ssh_stderr': result.stderr[-2000:],
                      'target': 'stock Ubuntu 24.04 CP1', 'target_memory_mib': 1024,
                      'transport': 'two concurrent private BEP 3 peers; odd/even pieces; no tracker/DHT/PEX',
                      'limitations': ['No peer loss mid-transfer in this native run',
                                      'No install/join; transfer only', 'Single owned target']}
            (WORK / 'result.json').write_text(json.dumps(output, indent=2, sort_keys=True) + '\n')
            return 0 if both else 1
        finally:
            seed1.close(); seed2.close()
            if process.poll() is None:
                process.terminate()
                try: process.wait(15)
                except subprocess.TimeoutExpired: process.kill(); process.wait(10)


if __name__ == '__main__':
    raise SystemExit(main())

