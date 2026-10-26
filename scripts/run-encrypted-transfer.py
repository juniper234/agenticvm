"""Minimal encrypted message utility. Double-click runs a local courier demo."""
from pathlib import Path
import json
import subprocess
import sys
import threading
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))


def demo():
    from agenticvm import blind_transfer as carrier
    folder = ROOT/'runtime/transfer-demo'/str(uuid4())
    folder.mkdir(parents=True)
    script = Path(__file__).resolve()

    def endpoint(home, *args):
        result = subprocess.run([sys.executable, '-I', '-B', str(script), 'endpoint', '--home', str(home), *map(str,args)],
            capture_output=True, timeout=20, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        envelope = json.loads(result.stdout)
        if result.returncode or not envelope.get('ok'):
            raise RuntimeError('Endpoint command failed: '+str(envelope))
        return envelope['result']

    a, b = folder/'computer-a', folder/'computer-b'
    ca = endpoint(a, 'init', '--name', 'orchestrator')
    cb = endpoint(b, 'init', '--name', 'worker')
    endpoint(a, 'trust', b/'contact.json', '--fingerprint', cb['fingerprint'])
    endpoint(b, 'trust', a/'contact.json', '--fingerprint', ca['fingerprint'])
    text = folder/'task.txt'
    text.write_bytes('Hello from an offline agent. \u4f60\u597d'.encode('utf-8'))
    task = endpoint(a, 'send', '--peer', cb['fingerprint'], '--input', text)
    before = endpoint(b, 'status')['mail']
    out = folder/'message.sealed'
    endpoint(a, 'export', task['id'], '--output', out)
    service = carrier.server(carrier.Store(folder/'blind-relay'))
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        origin = 'http://127.0.0.1:'+str(service.server_port)
        ticket = carrier.push(origin, out.read_bytes())['sha256']
        incoming = folder/'received.sealed'
        incoming.write_bytes(carrier.pull(origin, ticket))
        received = endpoint(b, 'receive', incoming)
        duplicate = endpoint(b, 'receive', incoming)
        ack = folder/'receipt.sealed'
        endpoint(b, 'export', received['receipt'], '--output', ack)
        ack_ticket = carrier.push(origin, ack.read_bytes())['sha256']
        ack_in = folder/'received-receipt.sealed'
        ack_in.write_bytes(carrier.pull(origin, ack_ticket))
        endpoint(a, 'receive', ack_in)
        restored = folder/'restored.txt'
        endpoint(b, 'read', task['id'], '--output', restored)
        checks = {'no_delivery_before_carrier': before == [], 'exact_plaintext_restored': restored.read_bytes() == text.read_bytes(),
                  'replay_deduplicated': duplicate['duplicate'] and duplicate['receipt'] == received['receipt'],
                  'sender_has_authenticated_receipt': endpoint(a,'status')['mail'][0]['acked'] == 1,
                  'payload_absent_from_carrier': text.read_bytes() not in out.read_bytes()}
        report = {'passed': all(checks.values()), 'scope': 'two host process identities on one PC; not VM or physical-host validation',
                  'checks': checks, 'folder': str(folder), 'keys_retained_locally_for_demo_inspection': True,
                  'separate_physical_hosts_tested': False, 'report': str(folder/'report.json')}
        (folder/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        print(json.dumps(report))
        return 0 if report['passed'] else 1
    finally:
        service.shutdown()
        service.server_close()
        thread.join(3)


def main():
    args = sys.argv[1:]
    if not args or args == ['demo']:
        return demo()
    if args[0] == 'endpoint':
        from agenticvm.offline_transfer import main as endpoint
        return endpoint(args[1:])
    if args[0] == 'courier':
        from agenticvm.blind_transfer import main as courier
        return courier(args[1:])
    print('Encrypted-Transfer.exe [demo | endpoint --help | courier --help]\n'
          'Default: two separate host processes, ciphertext-only loopback relay, delivery receipt.\n'
          'Linux VM isolation evidence: docs/validation/disconnected-transfer-report.json.\n'
          'Remote transfer: encrypted envelopes over authenticated HTTPS, or explicit offline file transfer.\n'
          'No cross-physical-host validation or automatic remote mailbox discovery is claimed.')
    return 0 if args[0] in ('--help','-h','--describe') else 2


if __name__ == '__main__':
    raise SystemExit(main())
