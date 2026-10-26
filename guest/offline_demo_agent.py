"""Deterministic ping/pong agents for the disconnected-transfer integration test.

Each process runs inside its own VM, with only its own persistent mailbox.
This transport test deliberately does not invoke a language model.
"""
import argparse
import json
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from transfer import Endpoint, encoded, parsed, sha


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=('orchestrator-send', 'worker-reply', 'orchestrator-check'))
    parser.add_argument('--peer')
    parser.add_argument('--message-id')
    args = parser.parse_args()
    endpoint = Endpoint('/workspace/mailbox')
    try:
        if args.role == 'orchestrator-send':
            payload = encoded({'op': 'ping', 'challenge': secrets.token_hex(32), 'text': 'offline agent hello \u4f60\u597d'})
            sent = endpoint.send(args.peer, payload, kind='task')
            Path('/workspace/challenge.json').write_bytes(encoded({'task': sent['id'], 'payload': parsed(payload)}))
            result = {**sent, 'payload_sha256': sha(payload)}
        elif args.role == 'worker-reply':
            task = parsed(endpoint.payload(args.message_id))
            if set(task) != {'op', 'challenge', 'text'} or task['op'] != 'ping' or len(task['challenge']) != 64:
                raise ValueError('Invalid bounded ping task')
            result = endpoint.send(args.peer, encoded({'op': 'pong', 'challenge': task['challenge'], 'text': task['text']}),
                                   kind='result', reply_to=args.message_id)
        else:
            saved = parsed(Path('/workspace/challenge.json').read_bytes())
            reply = parsed(endpoint.payload(args.message_id))
            row = next(row for row in endpoint.status()['mail'] if row['id'] == args.message_id)
            if row['reply_to'] != saved['task'] or row['peer'] != args.peer or reply != {**saved['payload'], 'op': 'pong'}:
                raise ValueError('Reply does not preserve the authenticated task and challenge')
            result = {'challenge_matched': True, 'unicode_preserved': True, 'payload_sha256': sha(endpoint.payload(args.message_id))}
        print(json.dumps(result))
    finally:
        endpoint.close()


if __name__ == '__main__':
    main()
