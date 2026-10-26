"""Linux sponsor for an actual Windows target; native accounts stay explicit."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import threading
import time
from uuid import UUID, uuid5

sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_mother import NativeNode, NativeHandler, BASE, ADDRESSES, SecureServer, save
from lan_agent import MEMBERS


class WindowsHandler(NativeHandler):
    def handle_request(self, body):
        if self.server.control and self.path == '/windows/installer' and body is None:
            node = self.server.node
            if not node.install_token or self.headers.get('Authorization') != 'Bearer ' + node.install_token:
                return self.output({'error': 'Wrong provisioning token'}, 403)
            if self.client_address[0] != '192.0.2.4' or node.enrollment is None or time.monotonic() > node.enrollment:
                return self.output({'error': 'Owned Windows enrollment is not open'}, 403)
            raw = (BASE / 'lab/windows_install.py').read_bytes()
            if node.config['test_case'] == 'bad-bootstrap':
                raw += b'\n# deliberately changed owned Windows installer\n'
            self.send_response(200)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        return super().handle_request(body)


class WindowsMother(NativeNode):
    def start_server(self, port, control=False):
        server = SecureServer((ADDRESSES[self.identity], port), WindowsHandler)
        server.node, server.control = self, control
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def mother(self):
        self.wait_ready(('offshoot-1', 'offshoot-2'))
        baseline = [self.exchange(peer) for peer in ('offshoot-1', 'offshoot-2')]
        self.enrollment = time.monotonic() + 7200
        print('WINDOWS_MOTHER_READY', flush=True)
        deadline = time.monotonic() + 7200
        while time.monotonic() < deadline:
            with self.lock:
                joined, receipt = 'sprout-4' in self.known, self.install_receipt
            if joined and receipt:
                try:
                    target = self.rpc('sprout-4', '/status', timeout=5)[0]
                    if target['error']:
                        raise ValueError('Windows target model failed: ' + target['error'])
                    if target['ready']:
                        break
                except OSError:
                    pass
            time.sleep(.5)
        else:
            raise TimeoutError('The real Windows target did not enroll and become model-ready')
        if (not receipt['ok'] or any(receipt['initial_absence'].values())
                or receipt['agent_account_sid'] != 'S-1-5-19' or receipt['activation'] != 'Windows Task Scheduler'
                or target['native_windows']['uuid'] != self.config['target_uuid']):
            raise ValueError('Windows native preparation, account or target receipt mismatch')
        joined_exchange = self.exchange('sprout-4')
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if len(self.rpc('sprout-4', '/status')[0]['delivered']) == 2:
                break
            time.sleep(.5)
        else:
            raise TimeoutError('Windows target did not exchange actual model messages with both offshoots')
        before = self.all_statuses()
        target = before['sprout-4']
        if target['native_windows']['sid'] != 'S-1-5-19':
            raise ValueError('Windows inference agent is not running as Local Service')
        print('WINDOWS_READY_FOR_COLD_REBOOT', flush=True)
        deadline, outages = time.monotonic() + 600, 0
        while time.monotonic() < deadline:
            try:
                after = self.rpc('sprout-4', '/status', timeout=3)[0]
                if after['native_boot_id'] != target['native_boot_id'] and after['ready']:
                    break
            except OSError:
                outages += 1
            time.sleep(.5)
        else:
            raise TimeoutError('Windows startup task did not reconnect after an actual cold boot')
        if (after['public_identity'] != target['public_identity'] or after['native_windows']['sid'] != 'S-1-5-19'
                or after['native_windows']['uuid'] != self.config['target_uuid'] or after['calls'] != target['calls']):
            raise ValueError('Windows cold reboot changed identity, account, target or model ledger')
        ident = str(uuid5(UUID(self.config['garden']), 'windows-post-reboot-challenge'))
        hello = self.message(ident, 'sprout-4', 'hello')
        reply, tls = self.rpc('sprout-4', '/hello', hello)
        self.validate_message(reply, 'sprout-4', 'reply')
        if reply['reply_to'] != ident:
            raise ValueError('Windows fresh challenge/reply correlation failed')
        with self.lock, self.db:
            self.db.execute('INSERT INTO delivered VALUES (?,?,?,?)', (ident, 'sprout-4', json.dumps(hello), json.dumps(reply)))
        save(BASE / 'lan-report.json', {'passed': True, 'garden': self.config['garden'], 'route': self.config['route'],
            'initial_statuses': before, 'final_statuses': self.all_statuses(), 'baseline': baseline,
            'joined_exchange': joined_exchange, 'installed': receipt,
            'post_reboot_challenge': {'hello': hello, 'reply': reply, 'tls': tls},
            'cold_reboot_same_identity': True, 'cold_reboot_no_model_task_replay': True,
            'network_outages_observed': outages})
        __import__('os').sync()


def main():
    try:
        config = json.loads((BASE / 'lan-config.json').read_text())
        node = WindowsMother(config) if config['identity'] == 'mother' else NativeNode(config)
        if config['identity'] == 'mother' and config['test_case'] not in ('happy', 'resume'):
            node.start_server(8443, True)
            node.enrollment = time.monotonic() + 2400
            print('WINDOWS_MOTHER_READY', flush=True)
            while not node.stop.wait(1):
                pass
        else:
            node.run()
    except Exception as error:
        save(BASE / 'lan-report.json', {'passed': False, 'error': type(error).__name__ + ': ' + str(error)})
        __import__('os').sync()
        import traceback
        traceback.print_exc()
        while True:
            time.sleep(30)


if __name__ == '__main__':
    main()
