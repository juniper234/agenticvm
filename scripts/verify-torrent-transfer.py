"""Verify a real partial-piece torrent restart on loopback, with no public swarm."""
import hashlib
import json
from pathlib import Path
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from agenticvm.torrent import digest, download_local, load_libtorrent, make_torrent


def main():
    folder = ROOT/'runtime/torrent-transfer-tests'/str(uuid4())
    seed, partial = folder/'seed', folder/'partial'
    seed.mkdir(parents=True)
    partial.mkdir()
    # Distinct nonzero pieces; retain one correct 256 KiB piece and leave the
    # other three missing. The client must rehash and fetch only missing data.
    content = b''.join(hashlib.sha256(str(index).encode()).digest()*8192 for index in range(4))
    archive = seed/'fixture.zip'
    archive.write_bytes(content)
    (partial/archive.name).write_bytes(content[:262144]+b'\0'*(len(content)-262144))
    lt = load_libtorrent(ROOT)
    torrent = folder/'fixture.torrent'
    make_torrent(lt, archive, torrent)
    catalog = {'payload': {'name': archive.name, 'bytes': len(content), 'sha256': digest(archive)},
               'torrent_sha256': digest(torrent)}
    downloaded, evidence = download_local(ROOT, torrent, catalog, seed, partial)
    if not evidence['resumed_existing_file'] or not 0 < evidence['payload_downloaded_bytes'] < len(content):
        raise AssertionError('The client did not reuse the verified existing piece')
    if downloaded.read_bytes() != content:
        raise AssertionError('Resumed file differs from seed')
    report = {'passed': True, 'test': 'partial piece restart and independent full-file verification',
              'fixture_bytes': len(content), 'existing_valid_piece_bytes': 262144,
              'expected_missing_bytes': len(content)-262144, 'evidence': evidence,
              'public_swarm_joined': False, 'directory': str(folder)}
    (folder/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    destination = ROOT/'docs/validation/torrent-resume-report.json'
    destination.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'passed': True, 'report': str(destination), 'received_missing_bytes': evidence['payload_downloaded_bytes']}))


if __name__ == '__main__':
    main()
