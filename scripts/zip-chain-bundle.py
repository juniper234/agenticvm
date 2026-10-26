"""ZIP only verified release inventory; exclude generated workspaces and keys."""
import argparse
import json
from pathlib import Path
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from agenticvm.torrent import digest, member_name, plain, read_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=ROOT/'dist/Agent-Chain-v1')
    parser.add_argument('--output', type=Path, help='Fresh ZIP in dist; existing archives are never overwritten')
    args = parser.parse_args()
    bundle = plain(args.bundle)
    if bundle.parent != ROOT/'dist':
        raise ValueError('Use a local dist assembly')
    manifest = read_json(bundle/'package-manifest.json', maximum=1024*1024)
    if manifest['schema'] != 'agenticvm.torrent-chain-bundle.v1' or manifest['published']:
        raise ValueError('Select the unpublished local development assembly')
    sources = []
    for entry in manifest['files']:
        relative = member_name(entry['path'])
        if relative.startswith(('runtime/chain-runs/', 'runtime/pong-agent-runs/', 'runtime/replication-runs/', 'runtime/agent-cache/')) or relative.endswith(('.key', 'key.pem')):
            raise ValueError('Private runtime state cannot enter a release ZIP')
        path = plain(bundle/relative)
        if path.stat().st_size != entry['bytes'] or digest(path) != entry['sha256']:
            raise ValueError('Release file changed before ZIP assembly: '+relative)
        sources.append((path, relative))
    sources.append((bundle/'package-manifest.json', 'package-manifest.json'))
    archive = plain(args.output) if args.output else bundle.with_suffix('.zip')
    if archive.parent != ROOT/'dist' or archive.suffix.lower() != '.zip':
        raise ValueError('Select a fresh .zip file directly in dist')
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as package:
        for index, (source, relative) in enumerate(sources):
            package.write(source, bundle.name+'/'+relative)
            if index % 100 == 0:
                print(json.dumps({'event': 'packing_release', 'files': index, 'total_files': len(sources)}), flush=True)
    with zipfile.ZipFile(archive) as package:
        if package.testzip() is not None:
            raise ValueError('Release ZIP CRC verification failed')
    receipt = {'ready': True, 'zip': str(archive), 'bytes': archive.stat().st_size, 'sha256': digest(archive),
               'files': len(sources), 'user_runtime_data_included': False, 'published': False,
               'run': 'Extract the entire folder, then double-click '+('Agent-Replicator.exe' if manifest.get('kind') == 'replication' else 'Agent-Chain.exe')}
    archive.with_suffix('.archive.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt), flush=True)


if __name__ == '__main__':
    main()
