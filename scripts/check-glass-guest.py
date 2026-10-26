"""Exercise the real native viewer API; receipts contain no launch token."""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit, parse_qs, urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'runtime/glass-acceptance'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--start', choices=['desktop', 'android', 'windows'])
    parser.add_argument('--status', action='store_true')
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--stop', action='store_true')
    parser.add_argument('--test', choices=['desktop', 'android', 'windows'])
    args = parser.parse_args()
    ready = json.loads((ROOT / 'runtime/glass-app/viewer-ready.json').read_text(encoding='utf-8'))
    link = urlsplit(ready['url'])
    assert link.scheme == 'http' and link.hostname == '127.0.0.1' and link.port
    origin = 'http://127.0.0.1:' + str(link.port)
    token = parse_qs(link.fragment)['token'][0]
    OUT.mkdir(parents=True, exist_ok=True)

    def call(path, body=None, timeout=360):
        headers = {'X-AgenticVM-Token': token, 'Origin': origin}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        request = Request(origin + path, json.dumps(body).encode() if body is not None else None, headers)
        for attempt in range(40):
            try:
                with urlopen(request, timeout=timeout) as response:
                    data = response.read(3 * 1024 * 1024)
                    if 'application/json' in response.headers.get('Content-Type', ''):
                        result = json.loads(data)
                        if not result['ok']:
                            raise RuntimeError(str(result.get('error')))
                        return result['result']
                    return data
            except HTTPError as error:
                detail = error.read(65536)
                if error.code == 409 and b'busy' in detail and attempt < 39:
                    time.sleep(.5)
                    continue
                raise RuntimeError(detail.decode('utf-8', 'replace')) from error

    def action(name, **values):
        return call('/api/action', {'action': name, **values})

    def capture(label):
        data = call('/api/screen')
        assert data.startswith(b'\x89PNG\r\n\x1a\n')
        path = OUT / (label + '.png')
        path.write_bytes(data)
        return str(path)

    if args.start:
        memory = {'desktop': 768, 'android': 2560, 'windows': 2048}[args.start]
        print(json.dumps(action('start', profile=args.start, memory=memory, network=False, persistent=True)), flush=True)
    if args.status:
        print(json.dumps(call('/api/status')), flush=True)
    if args.capture:
        print(capture('current-' + str(int(time.time()))), flush=True)
    if args.test:
        profile = args.test
        report = {'profile': profile, 'checks': [], 'started_at': time.time()}
        receipt = OUT / (profile + '-report.json')

        def record(name, result):
            report['checks'].append({'check': name, 'result': result, 'at': time.time()})
            receipt.write_text(json.dumps(report, indent=2), encoding='utf-8')
            print(name + ': passed', flush=True)

        try:
            state = call('/api/status')
            assert state['profile'] == profile and state['guest_ready'] is True
            record('real-guest-ready', state)
            record('display-png', capture(profile + '-display'))
            command = "$env:OS; [Environment]::OSVersion.VersionString" if profile == 'windows' else 'uname -a; id'
            result = action('exec', command=command)
            assert result['exit_code'] == 0 and result['stdout'].strip()
            record('guest-command', result)
            content = ('AgenticVM ' + profile + ' file check\n').encode()
            path = ('C:/workspace/' if profile == 'windows' else '/workspace/') + 'glass-check.txt'
            action('upload', path=path, data_b64=base64.b64encode(content).decode())
            downloaded = call('/api/download?' + urlencode({'path': path}))
            assert downloaded == content
            record('file-roundtrip', {'bytes': len(content), 'sha256': hashlib.sha256(downloaded).hexdigest()})
            action('key', keys='home' if profile == 'android' else 'escape')
            action('click', x=400 if profile != 'android' else 360, y=350 if profile != 'android' else 640)
            record('mouse-and-key-dispatched', True)
            record('display-after-input', capture(profile + '-after-input'))
            report['ok'] = True
        except Exception as error:
            report.update(ok=False, error=str(error))
            raise
        finally:
            report['finished_at'] = time.time()
            receipt.write_text(json.dumps(report, indent=2), encoding='utf-8')
    if args.stop:
        print(json.dumps(action('stop')), flush=True)


if __name__ == '__main__':
    main()
