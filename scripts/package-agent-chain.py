"""Assemble a fresh runnable Windows torrent + two-VM agent chain bundle.

The included seed is local release material, never announced to a tracker/DHT.
The receiving client must obtain its own copy over loopback BitTorrent.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
from uuid import uuid4
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from agenticvm.torrent import digest, load_libtorrent, make_torrent, plain


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def json_file(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')


def agent_package(release, *, replication=False):
    model = ROOT/'runtime/local-model-test'
    prepared = json.loads((model/'preparation.json').read_text())
    entries = {}
    for name in ('LFM2.5-350M-Q4_K_M.gguf', 'llama-b11711-bin-ubuntu-x64.tar.gz'):
        source = model/'downloads'/name
        if digest(source) != prepared['sources'][name]['sha256']:
            raise ValueError('Pinned model/runtime changed')
        entries['downloads/'+name] = source
    qjs = model/'downloads/qjs-linux-x86_64'
    if digest(qjs) != '0bfc02511a9f549c28b53880d988fc7cd5d361e90c5e8afdfcd7dc6774ceace5':
        raise ValueError('QuickJS changed')
    entries['downloads/qjs-linux-x86_64'] = qjs
    provenance = json.loads((model/'dependencies/provenance.json').read_text())
    deb = model/'dependencies/libgomp1_14.2.0-19_amd64.deb'
    if digest(deb) != provenance['sha256']:
        raise ValueError('Pinned Debian OpenMP package changed')
    debian = module('chain_debian', 'desktop-image-debian.py')
    with tarfile.open(fileobj=io.BytesIO(debian.package_payload(deb))) as archive:
        libraries = [entry for entry in archive if entry.isfile() and '/libgomp.so.' in entry.name]
        if len(libraries) != 1 or archive.extractfile(libraries[0]).read() != (model/'dependencies/libgomp.so.1').read_bytes():
            raise ValueError('OpenMP library differs from verified Debian package')
    for name in ('libgomp.so.1', 'provenance.json'):
        entries['dependencies/'+name] = model/'dependencies'/name
    boot = json.loads((model/'boot/build-manifest.json').read_text())
    if digest(model/'boot/agenticvm-linux-peer.iso') != boot['iso']['sha256']:
        raise ValueError('Inference boot image changed')
    entries['boot/agenticvm-linux-peer.iso'] = model/'boot/agenticvm-linux-peer.iso'
    for name in ('pong_agent.py', 'pong_synthesis.py', 'peer_agent.py'):
        entries['guest/'+name] = ROOT/'guest'/name
    if replication:
        entries['guest/replica_agent.py'] = ROOT/'guest/replica_agent.py'
    entries['guest/peer_protocol.py'] = ROOT/'src/agenticvm/peer_protocol.py'
    for path in sorted((ROOT/'guest/pong').iterdir()):
        if path.is_file():
            entries['guest/pong/'+path.name] = path
    metadata = {
        'preparation.json': json.dumps({'sources': prepared['sources']}, sort_keys=True, indent=2).encode(),
        'agent.json': json.dumps({'schema': 'agenticvm.agent.v1', 'name': 'lfm-pong-agent', 'version': 1,
            'model': 'LFM2.5-350M-Q4_K_M', 'host': 'windows-x86_64', 'guest': 'Debian GNU/Linux 13',
            'roles': ['orchestrator', 'worker'], 'capabilities': ['scaffolded_pong'],
            'guest_memory_mib': 512, 'model_calls_per_agent_max': 18, 'build_rounds_max': 4,
            'network_adapter': False, 'deterministic_repair_available': True}, sort_keys=True, indent=2).encode(),
        'THIRD-PARTY-NOTICES.txt': (
            'Local development agent bundle; no external redistribution performed.\n'
            'Model: LiquidAI LFM2.5-350M-GGUF, revision 657e078c94084481950a2d555a941481f715536b\n'
            'Model license and card: https://huggingface.co/LiquidAI/LFM2.5-350M-GGUF/tree/657e078c94084481950a2d555a941481f715536b\n'
            'llama.cpp b11711, MIT: https://github.com/ggml-org/llama.cpp/tree/b11711\n'
            'QuickJS-NG v0.17.0, MIT: https://github.com/quickjs-ng/quickjs/tree/v0.17.0\n'
            'libgomp: Debian libgomp1 14.2.0-19, GPL with GCC runtime library exception.\n'
            'Distribution copyright files remain in the immutable Debian root image.\n'
            'Kernel/guest packages: the base bundle includes build and package provenance.\n'
            'Agent implementation source is included in guest/.\n').encode()
    }
    if replication:
        agent = json.loads(metadata['agent.json'])
        agent.update(name='lfm-replica-agent', roles=['self-reproducing-agent'],
                     capabilities=['bounded_identical_child_request', 'lineage_mailbox'],
                     replication_decision_origin='fixed_agent_policy', model_calls_per_agent_max=1)
        agent.pop('build_rounds_max')
        agent.pop('deterministic_repair_available')
        metadata['agent.json'] = json.dumps(agent, sort_keys=True, indent=2).encode()
    payload = release/('lfm-replica-agent-v1.zip' if replication else 'lfm-vm-agent-v1.zip')
    inventory = []
    with zipfile.ZipFile(payload, 'x', compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(set(entries) | set(metadata)):
            item = zipfile.ZipInfo(name, date_time=(2026, 10, 17, 0, 0, 0))
            item.external_attr = (stat.S_IFREG | 0o644) << 16
            sha, size = hashlib.sha256(), 0
            with archive.open(item, 'w') as outgoing:
                if name in entries:
                    with entries[name].open('rb') as incoming:
                        while block := incoming.read(1024*1024):
                            sha.update(block); size += len(block); outgoing.write(block)
                else:
                    data = metadata[name]
                    sha.update(data); size = len(data); outgoing.write(data)
            inventory.append({'path': name, 'bytes': size, 'sha256': sha.hexdigest()})
    return payload, inventory


def plan():
    return {'schema': 'agenticvm.chain.v1', 'name': 'Build Pong', 'supported_workflow': 'scaffolded_pong',
        'distribution': {'protocol': 'BitTorrent', 'scope': 'host loopback', 'catalog': 'pinned SHA-256, trusted local release',
                         'public_discovery': False},
        'agents': [{'id': 'orchestrator', 'vm': 'guest-a-serial', 'identity': 'guest-a', 'memory_mib': 512,
                    'model': 'LFM2.5-350M-Q4_K_M', 'capabilities': ['plan_palette_and_pace', 'delegate_pong', 'independent_quickjs_tests', 'accept_matching_hashes']},
                   {'id': 'worker', 'vm': 'guest-b-serial', 'identity': 'guest-b', 'memory_mib': 512,
                    'model': 'LFM2.5-350M-Q4_K_M', 'capabilities': ['generate_arithmetic_expressions', 'bounded_example_synthesis', 'return_game_artifacts']}],
        'edges': [{'from': 'orchestrator', 'to': 'worker', 'messages': ['build_pong', 'repair_pong', 'accept']},
                  {'from': 'worker', 'to': 'orchestrator', 'messages': ['candidate_artifacts', 'test_results', 'acceptance_receipt']}],
        'communication': {'medium': 'direct virtio-serial', 'encryption': 'TLS 1.3 with mutual certificates and exact peer pin',
                          'guest_ethernet_required': False, 'host_application_message_relay': False,
                          'message_fields': ['v', 'run', 'id', 'sender', 'recipient', 'seq', 'kind', 'reply_to', 'body'],
                          'body_limit_bytes': 16384, 'messages_per_direction_max': 512},
        'lifecycle': ['verify runtime', 'torrent download', 'verify catalog and every package file', 'provision disposable identities',
                      'boot two offline VMs', 'model plan', 'delegate', 'candidate', 'independent test', 'repair or accept',
                      'matching hash receipt', 'remove keys', 'stop VMs', 'export game'],
        'budgets': {'concurrent_vms_max': 2, 'build_rounds_max': 4, 'model_calls_per_agent_max': 18,
                    'guest_js_test_timeout_seconds': 5, 'agent_phase_deadline_seconds': 1000,
                    'torrent_deadline_seconds': 180, 'launcher_child_deadline_seconds': 1800},
        'recovery': {'download': 'recheck existing pieces and resume', 'interrupted_task': 'stop owned VMs, unlink disposable keys; no automatic replay',
                     'exactly_once_execution': False},
        'limits': ['One fixed two-agent workflow in this release; arbitrary graphs are not executed.',
                   'Tiny models need a supplied game scaffold and may need disclosed deterministic repairs.',
                   'The host/hypervisor and launcher folder are trusted.',
                   'A physical 4 GB host and cross-computer operation remain untested.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--replication', action='store_true', help='Build the finite self-reproducing agent release')
    args = parser.parse_args()
    output = plain(args.output or ROOT/('dist/Agent-Replicator-v1' if args.replication else 'dist/Agent-Chain'))
    executable = 'Agent-Replicator.exe' if args.replication else 'Agent-Chain.exe'
    from agenticvm.replicator import plan as replication_plan
    selected_plan = replication_plan() if args.replication else plan()
    if output.parent != ROOT/'dist' or output.exists():
        raise ValueError('Select a fresh direct dist subfolder')
    torrent = module('prepare_torrent', 'prepare-torrent-runtime.py')
    torrent_dir = torrent.prepare()
    release = ROOT/'runtime/torrent-agent-releases'/uuid4().hex
    release.mkdir(parents=True)
    payload, inventory = agent_package(release, replication=args.replication)
    lt = load_libtorrent(ROOT)
    torrent_file = release/'lfm-agent.torrent'
    make_torrent(lt, payload, torrent_file)
    catalog = {'schema': 'agenticvm.agent-catalog.v1', 'agent': 'lfm-replica-agent-v1' if args.replication else 'lfm-pong-agent-v1',
               'payload': {'name': payload.name, 'bytes': payload.stat().st_size, 'sha256': digest(payload)},
               'torrent_sha256': digest(torrent_file), 'files': inventory}
    json_file(release/'agent-catalog.json', catalog)
    portable = module('portable', 'package-portable.py')
    python, archive, verified = portable.prepare_python(download=False)
    portable.build_bundle(output, python, archive, verified)
    shutil.copy2(ROOT/'tools/torrent-runtime-lock.json', output/'tools/torrent-runtime-lock.json')
    for source in torrent_dir.rglob('*'):
        if source.is_file():
            target = output/'tools/torrent-runtime/2.1.1'/source.relative_to(torrent_dir)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    (output/'seed').mkdir()
    (output/'chain').mkdir()
    shutil.copy2(payload, output/'seed'/payload.name)
    for name in ('lfm-agent.torrent', 'agent-catalog.json'):
        shutil.copy2(release/name, output/'chain'/name)
    json_file(output/'chain/pong-chain.json', plan())
    if args.replication:
        json_file(output/'chain/replication-plan.json', selected_plan)
    zig = ROOT/'tools/zig/zig-x86_64-windows-0.15.2/zig.exe'
    zig_spec = json.loads((ROOT/'tools/build-tools-lock.json').read_text())['sources']['zig']
    if digest(zig) != zig_spec['exe_sha256']:
        raise ValueError('Compiler changed')
    subprocess.run([sys.executable, '-I', str(ROOT/'scripts/run-bounded.py'), '--output',
                    str(ROOT/'runtime'/('build-chain-launcher-'+uuid4().hex[:8])), '--', str(zig),
                    'cc', '-target', 'x86_64-windows-gnu', '-nostdlib', '-Os', '-s',
                    '-isystem', str(zig.parent/'lib/libc/include/any-windows-any'),
                    '-Wl,-e,mainCRTStartup', '-Wl,--subsystem,console', '-lkernel32', '-lshell32',
                    *(['-DAGENTICVM_REPLICATOR=1'] if args.replication else []),
                    str(ROOT/'guest/chain-launcher.c'), '-o', str(output/executable)], check=True, cwd=ROOT)
    (output/'Start-Agent-Chain.cmd').write_bytes(b'@echo off\r\n"%~dp0Agent-Chain.exe" %*\r\n')
    (output/'CHAIN-QUICKSTART.txt').write_text(
        'Double-click Agent-Chain.exe. Keep the entire folder together. No Python installation is needed.\n'
        'Windows Hypervisor Platform and firmware virtualization must already be enabled.\n'
        'The console shows: local torrent transfer -> verification -> two Linux agents -> accepted game.\n'
        'The first run downloads from the included local seed over actual BitTorrent; no Internet/public swarm.\n'
        'Each VM has 512 MiB RAM, no NIC, and its own local LFM2.5-350M model.\n'
        'Results: dist/Pong-<run-prefix>/index.html; evidence: runtime/chain-runs/<run-UUID>/report.json.\n'
        'Commands from this folder:\n'
        '  .\\Agent-Chain.exe --describe\n'
        '  .\\Agent-Chain.exe --download-only\n'
        '  .\\Agent-Chain.exe --resume <run-UUID>\n'
        '  .\\Agent-Chain.exe --recover <run-UUID>\n'
        'Ctrl+C requests cleanup. If Windows/app closes unexpectedly, the next launch cleans incomplete VMs.\n'
        'Interrupted tasks are not replayed automatically. Partial downloads can resume.\n'
        'Current chain: one orchestrator and one worker building scaffolded Pong, with independent tests.\n'
        'Generated code may require deterministic repair; provenance records it. 4 GB physical host untested.\n'
        'This development executable is not Authenticode-signed. No system installation or publication performed.\n', encoding='utf-8')
    if args.replication:
        (output/'Start-Agent-Chain.cmd').write_bytes(b'@echo off\r\n"%~dp0Agent-Replicator.exe" %*\r\n')
        (output/'CHAIN-QUICKSTART.txt').write_text('This assembly starts Agent-Replicator.exe. See REPLICATION-QUICKSTART.txt.\n', encoding='utf-8')
        (output/'Start-Agent-Replicator.cmd').write_bytes(b'@echo off\r\n"%~dp0Agent-Replicator.exe" %*\r\n')
        (output/'REPLICATION-QUICKSTART.txt').write_text(
            'Double-click Agent-Replicator.exe. Keep the whole folder together.\n'
            'Windows Hypervisor Platform and firmware virtualization must already be enabled.\n'
            'It downloads the verified LFM replica package through local BitTorrent from the included seed.\n'
            'One seed agent starts. Its request creates a child; that child requests a grandchild.\n'
            'At most two 512 MiB VMs run at once. The third waits for an ancestor to retire.\n'
            'Each copy inherits the same reproduction code and gets its own fresh identity/workspace.\n'
            'The limit is three agents total and two descendant generations; further requests are denied.\n'
            'Parent and child exchange messages over mutually authenticated TLS via the trusted host broker.\n'
            'Guests have no NIC. The broker terminates TLS and can read these messages.\n'
            'The reproduction rule is programmed; each local LFM model generates a greeting.\n'
            'Evidence: runtime/replication-runs/<UUID>/report.json. Keys are removed and VMs stop on completion.\n'
            'Commands: .\\Agent-Replicator.exe --describe, --download-only, or --recover <UUID>.\n'
            'After a crash, the next launch cleans owned VMs and keys without replaying uncertain births.\n'
            'No public swarm, cross-computer reproduction or physical 4 GB hardware test is included.\n', encoding='utf-8')
    # Trust starts with this local launcher folder. The inventory covers code,
    # interpreter, torrent library, QEMU and immutable images before VM execution.
    runtime_files = []
    for path in sorted(output.rglob('*')):
        relative = path.relative_to(output).as_posix()
        if path.is_file() and (relative.startswith(('src/', 'scripts/', 'guest/', 'tools/', 'runtime/')) or relative == executable):
            runtime_files.append({'path': relative, 'bytes': path.stat().st_size, 'sha256': digest(path)})
    json_file(output/'chain/launcher-lock.json', {'schema': 'agenticvm.chain-launcher.v1',
            'kind': 'replication' if args.replication else 'pong-chain',
            'catalog_sha256': digest(output/'chain/agent-catalog.json'), 'runtime_files': runtime_files})
    # Refresh the base assembly manifest after extending it, before any runtime
    # state is created. Original provenance remains in base_package.
    previous = json.loads((output/'package-manifest.json').read_text())
    all_files = [{'path': p.relative_to(output).as_posix(), 'bytes': p.stat().st_size, 'sha256': digest(p)}
                 for p in sorted(output.rglob('*')) if p.is_file() and p.name != 'package-manifest.json']
    json_file(output/'package-manifest.json', {'schema': 'agenticvm.torrent-chain-bundle.v1', 'base_package': previous,
        'files': all_files, 'bytes': sum(e['bytes'] for e in all_files), 'file_count': len(all_files),
        'agent_package': catalog, 'kind': 'replication' if args.replication else 'pong-chain',
        'published': False, 'public_swarm_joined': False})
    smoke = subprocess.run([str(output/executable), '--describe'], capture_output=True, text=True, timeout=30)
    if smoke.returncode or json.loads(smoke.stdout)['name'] != selected_plan['name']:
        raise RuntimeError('Packaged native launcher smoke failed: '+smoke.stderr[-1500:])
    print(json.dumps({'ready': True, 'runnable': str(output/executable), 'agent_package_bytes': payload.stat().st_size,
                      'bundle_bytes': sum(e['bytes'] for e in all_files), 'runtime_files': len(runtime_files)}), flush=True)


if __name__ == '__main__':
    main()
