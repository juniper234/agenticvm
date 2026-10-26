"""Acquire official public Windows Server evaluation media after resource checks.

The initial download is trusted via publisher HTTPS, then locally SHA256 pinned.
No independent publisher whole-ISO checksum or Windows acceptance is claimed.
"""
import argparse
import json
from pathlib import Path
import shutil
import sys
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save

PAGE = 'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025'
SOURCE = 'https://go.microsoft.com/fwlink/?clcid=0x409&country=us&culture=en-us&linkid=2345730'


def main(metadata_only):
    lock = ROOT / 'tools/windows-evaluation-lock.json'
    if lock.exists():
        entry = json.loads(lock.read_text())
    else:
        with urllib.request.urlopen(urllib.request.Request(SOURCE, method='HEAD'), timeout=30) as response:
            resolved, size = response.url, int(response.headers['Content-Length'])
        parsed = urllib.parse.urlparse(resolved)
        name = Path(parsed.path).name
        if (parsed.scheme != 'https' or not parsed.hostname.endswith('.microsoft.com')
                or not name.lower().endswith('.iso') or '/' in name or '\\' in name or not 2 * 1024**3 < size < 10 * 1024**3):
            raise ValueError('Unexpected publisher evaluation download destination or size')
        entry = {'evaluation': 'Windows Server 2025', 'page': PAGE, 'source_url': SOURCE, 'url': resolved,
            'path': 'downloads/enrollment-installers/' + name, 'bytes': size,
            'trust': 'Official publisher HTTPS; first acquisition is locally SHA256 pinned. No independent publisher whole-ISO hash claimed',
            'native_acceptance': False, 'evaluation_limits': 'Disposable offline test only; no activation or license extension is performed'}
        save(lock, entry)
    if metadata_only:
        return print(json.dumps({'metadata_ready': True, **entry}, indent=2))
    path = ROOT / entry['path']
    if not path.resolve().is_relative_to(ROOT / 'downloads/enrollment-installers'):
        raise ValueError('Evaluation image path escaped task downloads')
    receipt = ROOT / 'runtime/enrollment-images/windows-evaluation-download.json'
    if path.exists():
        pin = json.loads(receipt.read_text())['sha256']
        if path.stat().st_size != entry['bytes'] or digest(path) != pin:
            raise ValueError('Previously pinned evaluation download changed')
    else:
        partial = path.with_suffix('.iso.partial')
        offset = partial.stat().st_size if partial.exists() else 0
        if shutil.disk_usage(ROOT).free + offset < 40 * 1024**3:
            raise RuntimeError('Windows acquisition waits for 40 GiB free, counting any verified in-progress download allocation')
        request = urllib.request.Request(entry['url'], headers={'Range': f'bytes={offset}-'} if offset else {})
        print('Downloading official public Windows evaluation media; no activation or host settings changes', flush=True)
        with urllib.request.urlopen(request, timeout=30) as source:
            append = bool(offset and source.status == 206)
            if append and not source.headers.get('Content-Range', '').startswith('bytes ' + str(offset) + '-'):
                raise ValueError('Windows evaluation download resume offset mismatch')
            count = offset if append else 0
            with partial.open('ab' if append else 'wb') as output:
                while data := source.read(1024 * 1024):
                    count += len(data)
                    if count > entry['bytes'] or shutil.disk_usage(ROOT).free < 32 * 10**9 + 2 * 1024**3:
                        raise ValueError('Windows evaluation acquisition stopped to preserve installed-OS headroom')
                    output.write(data)
        if count != entry['bytes']:
            raise ValueError('Windows evaluation download length mismatch')
        pin = digest(partial)
        if receipt.exists():
            if json.loads(receipt.read_text())['sha256'] != pin:
                raise ValueError('Reacquired evaluation bytes differ from the initial local pin')
        partial.replace(path)
        if not receipt.exists():
            save(receipt, {**entry, 'sha256': pin, 'initial_pin_source': 'Locally hashed publisher HTTPS response'})
    print(json.dumps({'ready': True, 'native_acceptance': False, 'path': str(path), 'sha256': pin,
        'trust': entry['trust']}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata-only', action='store_true')
    main(parser.parse_args().metadata_only)
