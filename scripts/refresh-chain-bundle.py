"""Refresh source/docs in a stopped, local development chain assembly only."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from agenticvm.state import StateStore
from agenticvm.chain import exclusive
from agenticvm.torrent import digest, plain, read_json


def refresh(bundle):
    if bundle.parent != ROOT/'dist':
        raise ValueError('Development assembly must be a direct dist subfolder')
    lock_path = bundle/'chain/launcher-lock.json'
    lock = read_json(lock_path, maximum=256*1024)
    if lock['schema'] != 'agenticvm.chain-launcher.v1':
        raise ValueError('Unrecognized development assembly')
    manifest = read_json(bundle/'package-manifest.json', maximum=1024*1024)
    if manifest['schema'] != 'agenticvm.torrent-chain-bundle.v1' or manifest['published']:
        raise ValueError('Only unpublished development assemblies may be refreshed')
    for family in ('pong-agent-runs', 'replication-runs'):
        for state_file in (bundle/'runtime').glob(family+'/*/*/sessions/default.json'):
            if StateStore(state_file.parent.parent).load()['registered']:
                raise ValueError('An agent VM is still registered; finish or recover it before refreshing')
    if lock.get('kind') == 'replication':
        catalog = read_json(bundle/'chain/agent-catalog.json')
        packaged = next(entry['sha256'] for entry in catalog['files'] if entry['path'] == 'guest/replica_agent.py')
        if digest(ROOT/'guest/replica_agent.py') != packaged:
            raise ValueError('Replica guest code changed; build a new pinned agent package before refreshing')
    # The manifest names only release material; generated workspaces, keys and
    # downloads are never added by scanning the runtime directory.
    spec = importlib.util.spec_from_file_location('portable_refresh', ROOT/'scripts/package-portable.py')
    portable = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(portable)
    sources = portable.source_files()
    names = {entry['path'] for entry in manifest['files']}
    runtime_names = {entry['path'] for entry in lock['runtime_files']}
    for source, relative in sources:
        if relative == 'mcp.example.json':
            continue  # Preserve the bundle-relative configuration.
        destination = plain(bundle/relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        names.add(relative)
        if relative.startswith(('src/', 'scripts/', 'guest/', 'tools/')):
            runtime_names.add(relative)
    # The plan describes the fixed workflow; it is not an executable graph.
    spec = importlib.util.spec_from_file_location('chain_refresh', ROOT/'scripts/package-agent-chain.py')
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    package.json_file(bundle/'chain/pong-chain.json', package.plan())
    if lock.get('kind') == 'replication':
        from agenticvm.replicator import plan
        package.json_file(bundle/'chain/replication-plan.json', plan())
        (bundle/'Start-Agent-Chain.cmd').write_bytes(b'@echo off\r\n"%~dp0Agent-Replicator.exe" %*\r\n')
        (bundle/'CHAIN-QUICKSTART.txt').write_text('This assembly starts Agent-Replicator.exe. See REPLICATION-QUICKSTART.txt.\n', encoding='utf-8')
    def entries(paths):
        return [{'path': relative, 'bytes': plain(bundle/relative).stat().st_size, 'sha256': digest(bundle/relative)}
                for relative in sorted(paths)]
    lock['runtime_files'] = entries(runtime_names)
    lock_path.write_text(json.dumps(lock, indent=2)+'\n')
    manifest['files'] = entries(names)
    manifest.update(file_count=len(manifest['files']), bytes=sum(entry['bytes'] for entry in manifest['files']))
    (bundle/'package-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'refreshed': str(bundle), 'runtime_files': len(runtime_names), 'user_runtime_data_included': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    bundle = plain(args.bundle)
    if bundle.parent != ROOT/'dist' or not (bundle/'chain/launcher-lock.json').is_file():
        raise ValueError('Select an existing local chain assembly')
    lock = read_json(bundle/'chain/launcher-lock.json', maximum=256*1024)
    runs = plain(bundle/('runtime/replication-runs' if lock.get('kind') == 'replication' else 'runtime/chain-runs'))
    runs.mkdir(parents=True, exist_ok=True)
    with exclusive(runs):
        refresh(bundle)


if __name__ == '__main__':
    main()
