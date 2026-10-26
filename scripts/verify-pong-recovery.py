"""Prove recovery of a real interrupted persistent Pong-agent VM and key file."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.peers import Runner, VM
from agenticvm.state import StateStore


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--child',help=argparse.SUPPRESS)
    args=parser.parse_args()
    if args.child:
        folder=ROOT/'runtime/pong-agent-runs'/args.child
        runner=Runner(folder,args.child,512,1)
        runner.journal.add('run_started',purpose='two local-model agents build Pong',fault_fixture=True)
        runner.provision()
        vm=VM(runner,'guest-a-serial')
        vm.start('--persistent','--image',ROOT/'runtime/local-model-test/boot/agenticvm-linux-peer.iso')
        vm.install('guest-a','host')
        runner.journal.add('fault_injected',exit_code=23,persistent_guest_key_present=True)
        os._exit(23)
    identifier=str(uuid4())
    folder=ROOT/'runtime/pong-agent-runs'/identifier
    folder.mkdir(parents=True)
    child=subprocess.run([sys.executable,'-I',__file__,'--child',identifier],cwd=ROOT,capture_output=True,timeout=100,
                         creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if child.returncode!=23:raise RuntimeError('Fault fixture did not reach its checkpoint: '+child.stderr.decode(errors='replace')[-1000:])
    assert StateStore(folder/'guest-a-serial').load()['registered']
    assert (folder/'private/guest-a.key').is_file()
    recovered=subprocess.run([sys.executable,'-I',str(ROOT/'scripts/run-pong-agents.py'),'--recover',identifier],
                              cwd=ROOT,capture_output=True,timeout=100,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if recovered.returncode:raise RuntimeError(recovered.stderr.decode(errors='replace')[-1500:])
    report=json.loads((folder/'pong-recovery.json').read_text())
    assert report['passed'] and report['tasks_replayed'] is False
    assert report['guest_key_cleanup']['guests'][0]['private_key_was_present'] is True
    assert report['guest_key_cleanup']['guests'][0]['private_key_removed'] is True
    assert StateStore(folder/'guest-a-serial').load()['registered'] is False
    output=ROOT/'docs/validation/pong-recovery-report.json'
    output.write_text(json.dumps({'passed':True,'injected_exit_code':23,'actual_vm_was_left_running':True,
                                  'persistent_guest_key_removed':True,'recovery':report},indent=2)+'\n')
    print(json.dumps({'passed':True,'report':str(output),'run_id':identifier}))


if __name__=='__main__':main()
