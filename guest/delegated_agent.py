"""Mother delegates one owned VM installation; sponsor returns verified proof.

The recruited member receives the original messaging-only agent. Installation
authority and its SSH identity remain with the explicitly prepared sponsor.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lan_agent as base
from bounded_torrent import Seeder

BASE = base.BASE
encoded, sha, save = base.encoded, base.sha, base.save
TASK_FIELDS = {'garden', 'request_id', 'target', 'target_uuid', 'sponsor',
               'manifest_sha256', 'bootstrap_sha256', 'grant', 'deadline_unix_ms'}


def bootstrap_source(config, installer, wire):
    """Send reviewed source over SSH stdin, with no downloaded code pre-execution."""
    original = installer.split("\nif __name__=='__main__':", 1)[0].replace('from __future__ import annotations\n', '')
    return (
        'import types,sys\n'
        'wire=types.ModuleType("bounded_torrent")\n'
        'exec(' + repr(wire) + ',wire.__dict__)\n'
        'CONFIG=' + repr(config) + '\n' + original + '\n'
        'def fetch(opener,url,destination,entry):\n'
        '    return wire.download(entry["torrent"],destination,name=entry["name"],size=entry["bytes"],'
        'sha256=entry["sha256"],source=("192.0.2.1",6881))\n'
        'try: print(json.dumps(install(CONFIG,fetch=fetch),sort_keys=True),flush=True)\n'
        'except Exception as error:\n'
        '    print(json.dumps({"ok":False,"error":type(error).__name__+": "+str(error)}),flush=True)\n'
        '    raise SystemExit(1)\n'
    )


def validate_task(config, identity, actor, task, now_ms):
    if identity != 'offshoot-1' or actor != 'mother' or not isinstance(task, dict) or set(task) != TASK_FIELDS:
        raise ValueError('Only mother may delegate to the prepared sponsor')
    expected = {'garden': config['garden'], 'request_id': config['request_id'],
                'target': 'sprout-4', 'target_uuid': config['target_uuid'], 'sponsor': 'offshoot-1',
                'manifest_sha256': config['manifest_sha256'], 'bootstrap_sha256': config['bootstrap_sha256']}
    if any(task[k] != v for k, v in expected.items()):
        raise ValueError('Delegation differs from approved target or package')
    if (type(task['deadline_unix_ms']) is not int or not now_ms < task['deadline_unix_ms'] <= now_ms + 360_000
            or not isinstance(task['grant'], str) or not 32 <= len(task['grant']) <= 128):
        raise ValueError('Delegation is expired or outside its bound')


class Handler(base.Handler):
    def handle_request(self, body):
        if not self.server.control and self.path == '/delegate' and body is not None:
            try:
                actor = self.server.node.authenticate(self.connection)
                return self.output(self.server.node.delegate(actor, body))
            except Exception as error:
                return self.output({'error': type(error).__name__ + ': ' + str(error)}, 403)
        return super().handle_request(body)


class Node(base.Node):
    def __init__(self, config):
        super().__init__(config)
        self.seed = None
        self.bundle_initialized = False
        self.db.execute('CREATE TABLE IF NOT EXISTS delegation(id TEXT PRIMARY KEY, task_sha256 TEXT, state TEXT, receipt TEXT)')
        self.db.commit()

    def update_bundle(self):
        # Mother verifies the seed before opening provisioning. A cold offshoot
        # may reach the LAN first; only connection failures receive a retry.
        deadline = time.monotonic() + 60
        while True:
            try:
                super().update_bundle()
                self.bundle_initialized = True
                return
            except OSError:
                if self.bundle_initialized or time.monotonic() >= deadline:
                    raise
                time.sleep(.25)

    def start_server(self, port, control=False):
        server = base.SecureServer((base.ADDRESSES[self.identity], port), Handler)
        server.node, server.control = self, control
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def snapshot(self):
        result = super().snapshot()
        with self.lock:
            result['delegations'] = [dict(row) for row in self.db.execute('SELECT id,task_sha256,state FROM delegation')]
        if self.seed:
            result['torrent_seed'] = {**self.seed.stats, 'errors': list(self.seed.errors)}
        return result

    def delegate(self, actor, task):
        validate_task(self.config, self.identity, actor, task, int(time.time() * 1000))
        signature = sha(encoded(task))
        with self.lock:
            prior = self.db.execute('SELECT * FROM delegation WHERE id=?', (task['request_id'],)).fetchone()
            if prior:
                if prior['task_sha256'] != signature:
                    raise ValueError('Changed duplicate delegation rejected')
                if prior['state'] == 'complete':
                    return {**json.loads(prior['receipt']), 'duplicate': True}
                raise ValueError('Uncertain delegation requires reconciliation; installation is not replayed')
            with self.db:
                self.db.execute('INSERT INTO delegation VALUES (?,?,?,NULL)', (task['request_id'], signature, 'installing'))
        try:
            receipt = self.provision(task)
            with self.lock, self.db:
                self.db.execute('UPDATE delegation SET state=?,receipt=? WHERE id=?',
                                ('complete', encoded(receipt).decode(), task['request_id']))
            return receipt
        except Exception:
            with self.lock, self.db:
                self.db.execute("UPDATE delegation SET state='failed' WHERE id=?", (task['request_id'],))
            raise

    def provision(self, task):
        installer = (BASE / 'lab/lan_install.py').read_text()
        wire = (BASE / 'peer/bounded_torrent.py').read_text()
        if sha(installer.encode() + b'\0' + wire.encode()) != task['bootstrap_sha256']:
            raise ValueError('Reviewed bootstrap source changed')
        cfg = {k: task[k] for k in ('garden', 'request_id', 'grant', 'manifest_sha256', 'target_uuid')}
        cfg.update(identity='sprout-4', mother='https://192.0.2.1:8443', mother_certificate=self.config['mother_certificate'])
        script = bootstrap_source(cfg, installer, wire)
        command = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', '2222', '-i', '/workspace/lab/enroll_key',
                   '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'UserKnownHostsFile=/workspace/lab/known_hosts', '-o', 'GlobalKnownHostsFile=/dev/null',
                   '-o', 'ConnectTimeout=3', '-o', 'PasswordAuthentication=no', '-o', 'ClearAllForwardings=yes',
                   'garden@192.0.2.4', '/usr/bin/python3 -I -']
        remaining = (task['deadline_unix_ms'] - int(time.time() * 1000)) / 1000
        if remaining <= 0:
            raise ValueError('Delegation expired before installation')
        completed = subprocess.run(command, input=script, text=True, capture_output=True, timeout=remaining)
        if completed.returncode:
            raise RuntimeError('Sponsor bootstrap failed: ' + completed.stdout[-1800:] + completed.stderr[-700:])
        installed = json.loads(completed.stdout)
        if installed.get('ok') is not True or installed.get('duplicate'):
            raise ValueError('Sponsor did not install a fresh target')
        self.update_bundle()
        self.wait_ready(('sprout-4',))
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            target, tls = self.rpc('sprout-4', '/status', timeout=10)
            delivered = [row for row in target['delivered'] if row['hello']['to'] == self.identity]
            if delivered:
                break
            time.sleep(.5)
        else:
            raise TimeoutError('New sprout did not introduce itself to its sponsor')
        if target['pid'] != installed['process']['pid']:
            raise ValueError('Sponsor verified a different target process')
        # A duplicate target bootstrap is independently checked as in v1.
        repeated = subprocess.run(command, input=script, text=True, capture_output=True, timeout=15)
        if repeated.returncode:
            raise ValueError('Duplicate bootstrap verification failed')
        duplicate = json.loads(repeated.stdout)
        if not duplicate.get('duplicate') or duplicate['process'] != installed['process']:
            raise ValueError('Duplicate bootstrap created another process')
        return {'ok': True, 'duplicate': False, 'request_id': task['request_id'], 'garden': task['garden'],
                'target_uuid': task['target_uuid'], 'target': 'sprout-4', 'sponsor': self.identity,
                'manifest_sha256': task['manifest_sha256'], 'installed': installed,
                'duplicate_bootstrap': duplicate, 'target_sha256': self.known['sprout-4']['sha256'],
                'target_model_ready': target['ready'] and target['model']['weights_verified_inside_vm'],
                'sponsor_exchange': delivered[0], 'confirmation_tls': tls, 'target_pid': target['pid']}

    def mother(self):
        self.wait_ready(('offshoot-1', 'offshoot-2'))
        baseline = [self.exchange(name) for name in ('offshoot-1', 'offshoot-2')]
        self.enrollment = time.monotonic() + 360
        task = {k: self.config[k] for k in ('garden', 'request_id', 'target_uuid', 'manifest_sha256', 'bootstrap_sha256', 'grant')}
        task.update(target='sprout-4', sponsor='offshoot-1', deadline_unix_ms=int(time.time() * 1000) + 300_000)
        if self.config['test_case'] == 'wrong-grant':
            task['grant'] = 'intentionally-invalid-lab-grant-0000'
        receipt, tls = self.rpc('offshoot-1', '/delegate', task, timeout=330)
        if (not receipt.get('ok') or receipt.get('duplicate') or receipt['request_id'] != task['request_id']
                or receipt['sponsor'] != 'offshoot-1' or receipt['target_uuid'] != task['target_uuid']
                or receipt['manifest_sha256'] != task['manifest_sha256'] or not receipt['target_model_ready']):
            raise ValueError('Sponsor confirmation failed scope verification')
        self.wait_ready(('sprout-4',))
        target, target_tls = self.rpc('sprout-4', '/status')
        if target['pid'] != receipt['target_pid'] or self.known['sprout-4']['sha256'] != receipt['target_sha256']:
            raise ValueError('Mother verification differs from sponsor confirmation')
        joined = self.exchange('sprout-4')
        duplicate, _ = self.rpc('offshoot-1', '/delegate', task, timeout=10)
        if duplicate != {**receipt, 'duplicate': True}:
            raise ValueError('Duplicate delegation changed the completed receipt')
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            target = self.rpc('sprout-4', '/status')[0]
            if len(target['delivered']) == 2:
                break
            time.sleep(.5)
        else:
            raise TimeoutError('New sprout did not reach both offshoots')
        begin = time.monotonic()
        before = {name: self.rpc(name, '/status')[0] for name in base.MEMBERS if name != 'mother'}
        while time.monotonic() - begin < self.config['contact_seconds']:
            time.sleep(.5)
        statuses = {name: self.rpc(name, '/status')[0] for name in base.MEMBERS if name != 'mother'}
        statuses['mother'] = self.snapshot()
        for name, old in before.items():
            for peer in base.MEMBERS:
                if peer != name and statuses[name]['heartbeat_received'].get(peer, 0) <= old['heartbeat_received'].get(peer, 0):
                    raise ValueError('Encrypted contact did not continue')
        sponsor_rows = statuses['offshoot-1']['delegations']
        if len(sponsor_rows) != 1 or sponsor_rows[0]['state'] != 'complete':
            raise ValueError('Sponsor ledger did not complete exactly one delegation')
        report = {'passed': True, 'schema': 'agenticvm.delegated-enrollment.guest.v2', 'garden': task['garden'],
                  'baseline': baseline, 'new_mother_exchange': joined, 'statuses': statuses,
                  'installed': receipt['installed'], 'duplicate': receipt['duplicate_bootstrap'],
                  'delegation': receipt, 'duplicate_delegation': duplicate, 'delegation_tls': tls,
                  'mother_confirmation_tls': target_tls, 'mother_independently_verified': True,
                  'idle_contact_seconds': round(time.monotonic() - begin, 3)}
        save(BASE / 'lan-report.json', report)
        os.sync()

    def run(self):
        if self.identity == 'mother':
            manifest = json.loads((BASE / 'lab/manifest.json').read_text())
            paths = {'model.gguf': BASE / 'model.gguf', 'libgomp.so.1': BASE / 'dependencies/libgomp.so.1',
                     'agent.tar.gz': BASE / 'lab/assets/agent.tar.gz', 'llama.tar.gz': BASE / 'lab/assets/llama.tar.gz'}
            self.seed = Seeder({name: (path, manifest['files'][name]) for name, path in paths.items()},
                               ('192.0.2.1', 6881), '192.0.2.4', interrupt=self.config['test_case'] == 'resume')
        return super().run()


def main():
    node = None
    try:
        node = Node(json.loads((BASE / 'lan-config.json').read_text()))
        node.run()
    except Exception as error:
        if node:
            node.error = type(error).__name__ + ': ' + str(error)
        save(BASE / 'lan-report.json', {'passed': False, 'identity': node.identity if node else None,
                                      'error': type(error).__name__ + ': ' + str(error)})
        os.sync()
        import traceback
        traceback.print_exc()
        while True:
            time.sleep(30)


if __name__ == '__main__':
    main()
