"""A finite self-reproducing VM agent: every copy requests one identical child.

Reproduction is an explicit program policy, not an unrestricted model decision.
The local model contributes a greeting; the trusted broker enforces all limits.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent))
from peer_agent import FDTransport, Evidence
from peer_protocol import BIOStream, PeerSession, PeerTLSConfig
from pong_agent import Model, schema

BASE = Path('/workspace/peer')


def rpc(session, body):
    request = session.send('request', body, timeout=20)
    reply = session.receive(timeout=180)
    if reply['kind'] != 'response' or reply['reply_to'] != request['id']:
        raise ValueError('Broker response correlation failed')
    if reply['body'].get('ok') is not True:
        raise ValueError('Broker rejected a capability: '+str(reply['body'].get('error')))
    return reply['body']


def conversation(session, config, model, log):
    source_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if source_sha != config['agent_sha256']:
        raise ValueError('Replica source changed after installation')
    rpc(session, {'op': 'hello', 'node_id': config['identity'], 'parent': config['parent'],
                  'generation': config['generation'], 'package_sha256': config['package_sha256'],
                  'agent_sha256': source_sha, 'reproduction_capable': True})
    model.start()
    generated = model.ask('replica_greeting', 'Write a brief friendly greeting to another agent. Return the JSON field text. Use fewer than eight words.',
                          schema({'text': {'type': 'string', 'maxLength': 80}}), 32)
    greeting = generated.get('text')
    if not isinstance(greeting, str) or not 1 <= len(greeting) <= 80:
        raise ValueError('Model greeting did not meet its bounded schema')
    model.close()
    log({'event': 'local_model_greeting', 'text': greeting, 'replication_decision_origin': 'fixed_agent_policy'})
    parent = config['parent']
    def send(to, kind, text):
        result = rpc(session, {'op': 'send', 'message_id': str(uuid4()), 'recipient': to,
                               'kind': kind, 'text': text})
        log({'event': 'mail_stored', 'to': to, 'kind': kind, 'message_id': result['message_id']})
    if parent:
        send(parent, 'hello', greeting)
    # Each descendant carries this same reproduction request code. It never
    # chooses a host path, external address, executable or quota of its own.
    request = {'op': 'replicate', 'request_id': str(uuid4()), 'package_sha256': config['package_sha256']}
    reproduction = rpc(session, request)
    duplicate = rpc(session, request)
    if duplicate != reproduction:
        raise ValueError('Reproduction request was not idempotent')
    log({'event': 'reproduction_result', 'request_id': request['request_id'], 'result': reproduction,
         'duplicate_returned_same_result': True})
    child = reproduction.get('child')
    parent_confirmed = parent is None
    child_confirmed = child is None
    seen, acknowledgements = set(), []
    deadline = time.monotonic()+300
    polls = 0
    while time.monotonic() < deadline and polls < 140:
        polls += 1
        status = rpc(session, {'op': 'poll', 'ack': acknowledgements})
        acknowledgements = []
        for message in status['messages']:
            if message['recipient'] != config['identity']:
                raise ValueError('Mailbox recipient mismatch')
            acknowledgements.append(message['id'])
            if message['id'] in seen:
                continue
            seen.add(message['id'])
            sender, kind = message['sender'], message['kind']
            log({'event': 'lineage_message_received', 'message': message})
            if sender == child and kind == 'hello':
                send(child, 'ack', 'Parent received your greeting; your reproduction capability is inherited.')
            elif sender == parent and kind == 'ack':
                send(parent, 'confirm', 'Child received the acknowledgement and submitted its own reproduction request.')
                parent_confirmed = True
            elif sender == child and kind == 'confirm':
                child_confirmed = True
            else:
                raise ValueError('Unexpected parent/child message')
        child_status = status['child']
        child_requested = child is None or (child_status is not None and child_status['id'] == child and child_status['child_requested'] == 1)
        if parent_confirmed and child_confirmed and child_requested:
            rpc(session, {'op': 'finish', 'ack': acknowledgements})
            return {'passed': True, 'agent_sha256': source_sha, 'reproduction': reproduction,
                    'duplicate_request_verified': True, 'lineage_messages_received': len(seen),
                    'model_greeting': greeting, 'parent_handshake_confirmed': parent_confirmed,
                    'child_handshake_confirmed': child_confirmed, 'polls': polls,
                    'replication_decision_origin': 'fixed_agent_policy'}
        time.sleep(1)
    raise TimeoutError('Replica lifecycle deadline or poll budget exhausted')


def main():
    if os.getuid() != 1000:
        raise ValueError('Replica must run as guest UID 1000')
    config = json.loads((BASE/'replica.json').read_text())
    log = Evidence(str(BASE/'evidence.jsonl'), config['run_id'], config['identity'], 'broker')
    model = Model(log)
    stream = None
    report = {'passed': False, 'identity': config['identity'], 'parent': config['parent'],
              'generation': config['generation'], 'run_id': config['run_id'], 'uid': os.getuid(),
              'interfaces': sorted(path.name for path in Path('/sys/class/net').iterdir()),
              'model': 'LFM2.5-350M-Q4_K_M', 'reproduction_capable': True}
    started = time.monotonic()
    try:
        if report['interfaces'] != ['lo']:
            raise ValueError('A replica must have no network adapter')
        tls = PeerTLSConfig(str(BASE/'identity.pem'), str(BASE/'key.pem'), str(BASE/'ca.pem'),
                            config['broker_pin'], 'broker')
        stream = BIOStream(FDTransport('/dev/virtio-ports/org.agenticvm.peer'), tls, server_side=True, timeout=45)
        report['tls'] = stream.info
        session = PeerSession(stream, config['run_id'], config['identity'], 'broker', log)
        report.update(conversation(session, config, model, log))
    except Exception as error:
        report['error'] = {'class': type(error).__name__, 'message': str(error)[:1500]}
        log({'event': 'replica_failed', 'error': report['error']})
    finally:
        if stream:
            stream.close()
        # conversation may already close its server to release model RAM while
        # waiting for a queued descendant. Re-closing its output is harmless.
        model.close()
        report.update(model_calls=model.calls, model_peak_rss_kib=model.peak_rss_kib,
                      elapsed_seconds=round(time.monotonic()-started, 3))
        (BASE/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
        log({'event': 'replica_completed', 'passed': report['passed']})
        log.close()
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
