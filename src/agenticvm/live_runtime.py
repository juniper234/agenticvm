"""Local launcher and recovery for owned continuous Linux communication runs."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from .chain import Checkpoints,exclusive
from .ext2 import read_image_file
from .peers import VM,verify_journal
from .state import StateStore

ROOT = Path(__file__).resolve().parents[2]
PURPOSE = 'sustained encrypted live VM communication'


def recover(run_id):
    if not isinstance(run_id,str) or str(UUID(run_id)) != run_id:
        raise ValueError('Use a canonical run UUID')
    folder = ROOT/'runtime/live-agent-runs'/run_id
    if folder.is_symlink() or getattr(folder,'is_junction',lambda:False)():
        raise ValueError('Redirected live run refused')
    before = verify_journal(folder/'checkpoints.jsonl')
    first = json.loads((folder/'checkpoints.jsonl').read_text().splitlines()[0])
    if first.get('purpose') != PURPOSE or first.get('run_id') != run_id:
        raise ValueError('This is not an owned live communication run')
    journal = Checkpoints(folder,run_id,resume=True)
    runner = SimpleNamespace(directory=folder,run_id=run_id,memory=256,control_calls=0,machines=[],journal=journal)
    errors,results = [],[]
    journal.add('recovery_started',previous_checkpoints=before,tasks_replayed=False)
    try:
        for name in ('live-a','live-b'):
            vm = VM(runner,name)
            if vm.workspace.is_symlink() or getattr(vm.workspace,'is_junction',lambda:False)():
                errors.append({'vm':name,'class':'redirected_workspace_refused'})
                continue
            state = StateStore(vm.workspace).load(required=False)
            if not state:
                continue
            try:
                # VM.stop checks exact PID + creation time + executable before
                # stopping a process. A stale PID after reboot is not an owner.
                vm.stop()
                disk = vm.workspace/'data/default.ext2'
                if disk.is_file():
                    vm.start('--persistent')
                    vm.run('/usr/bin/python3','-I','-c',
                        "import os,pathlib;p=pathlib.Path('/workspace/peer/live.key');p.unlink(missing_ok=True);os.sync();assert not p.exists()")
                    vm.stop()
                    try:
                        read_image_file(disk,'peer/live.key')
                        raise RuntimeError('Disposable identity key remains')
                    except FileNotFoundError:
                        pass
                results.append({'vm':name,'stopped':True,'disposable_key_removed':True})
            except Exception as error:
                errors.append({'vm':name,'class':type(error).__name__,'message':str(error)[:240]})
                try:
                    vm.stop()
                except Exception:
                    pass
        result = {'passed':not errors,'run_id':run_id,'tasks_replayed':False,'vms':results,'errors':errors}
        journal.add('recovery_completed',passed=result['passed'],tasks_replayed=False,errors=errors)
    finally:
        journal.close()
    result['checkpoints'] = verify_journal(folder/'checkpoints.jsonl')
    (folder/'recovery.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main(argv=None):
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ('--describe','--help','-h'):
        print('Agent-Live.exe [run | test | direct | relay | attach | stop RUN-UUID | recover RUN-UUID]\n'
              'Default/run: two simultaneous 256 MiB Linux agents; continuous encrypted contact until Ctrl+C.\n'
              'Test: 600 messages each way, idle heartbeats, relay outage and automatic reconnection.\n'
              'Direct: continuous TLS over a direct virtual serial link, without a host relay.\n'
              'No guest NIC, HTTP, USB, model download or model inference.\n'
              'Separate physical hosts and physical 4 GB hardware remain untested.')
        return 0
    if args and args[0] in ('relay','attach'):
        from .live_bridge import main as bridge
        return bridge(args)
    qemu = ROOT/'tools/qemu/11.1.0/qemu-system-x86_64.exe'
    if not qemu.is_file():
        raise RuntimeError('Keep the complete Agent-Live folder together; bundled QEMU is absent')
    os.environ['AGENTICVM_QEMU'] = str(qemu)
    base = ROOT/'runtime/live-agent-runs'
    base.mkdir(parents=True,exist_ok=True)
    if args and args[0] == 'stop':
        if len(args) != 2 or str(UUID(args[1])) != args[1]:
            raise ValueError('Use stop RUN-UUID')
        folder = base/args[1]
        if folder.is_symlink() or getattr(folder,'is_junction',lambda:False)():
            raise ValueError('Redirected run refused')
        verify_journal(folder/'checkpoints.jsonl')
        first = json.loads((folder/'checkpoints.jsonl').read_text().splitlines()[0])
        if first.get('purpose') != PURPOSE or first.get('run_id') != args[1]:
            raise ValueError('Unknown live run')
        if (folder/'report.json').is_file():
            raise ValueError('This live run has already stopped')
        with (folder/'CANCEL').open('xb') as output:
            output.write(b'stop\n')
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps({'stop_requested':True,'run_id':args[1]}))
        return 0
    with exclusive(base):
        if args and args[0] == 'recover':
            if len(args) != 2:
                raise ValueError('Use recover RUN-UUID')
            result = recover(args[1])
            print(json.dumps(result))
            return 0 if result['passed'] else 1
        for folder in sorted(base.iterdir()):
            if not folder.is_dir() or folder.is_symlink() or getattr(folder,'is_junction',lambda:False)():
                continue
            try:
                if str(UUID(folder.name)) != folder.name:
                    continue
            except ValueError:
                continue
            if not (folder/'checkpoints.jsonl').is_file():
                continue
            report = json.loads((folder/'report.json').read_text()) if (folder/'report.json').is_file() else None
            recovered = json.loads((folder/'recovery.json').read_text()) if (folder/'recovery.json').is_file() else None
            if report is not None and report.get('cleanup_failures') == [] or recovered and recovered.get('passed'):
                continue
            result = recover(folder.name)
            if not result['passed']:
                raise RuntimeError('Interrupted run could not be cleaned; inspect its recovery.json')
        command = args[0] if args else 'run'
        if command not in ('run','test','direct','test-crash'):
            raise ValueError('Use --help for supported commands')
        spec = importlib.util.spec_from_file_location('live_vm_runtime',ROOT/'scripts/verify-live-communication.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        original = sys.argv
        try:
            sys.argv = [str(ROOT/'scripts/verify-live-communication.py'),
                        *(['--continuous'] if command != 'test' else []),
                        *(['--fault-after-start'] if command == 'test-crash' else []),
                        *(['--mode','direct'] if command == 'direct' else [])]
            return module.main()
        finally:
            sys.argv = original
