"""Remove disposable TLS key files from completed test disks using owned VMs.

No host devices are mounted. Exact known guest files only; no recursive removal
or claim of cryptographic erasure of unallocated disk blocks.
"""
import json
import argparse
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.peers import verify_journal
from agenticvm.state import StateStore


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run',help='One canonical completed or recovered Pong run UUID')
    parser.add_argument('--after-recovery',action='store_true')
    args=parser.parse_args()
    if args.run and str(UUID(args.run))!=args.run:raise ValueError('Non-canonical run UUID')
    reports=[]
    folders=[ROOT/'runtime/pong-agent-runs'/args.run] if args.run else sorted((ROOT/'runtime/pong-agent-runs').iterdir())
    for folder in folders:
        if not folder.is_dir() or folder.is_symlink() or str(UUID(folder.name))!=folder.name:continue
        if not (folder/'report.json').exists() and not args.after_recovery:continue
        if (folder/'key-cleanup.json').exists():continue
        verify_journal(folder/'checkpoints.jsonl')
        records=[json.loads(line) for line in (folder/'checkpoints.jsonl').read_text().splitlines()]
        recovered=False
        if args.after_recovery:
            for path in folder.glob('recovery-*/report.json'):
                recovery=json.loads(path.read_text())
                chain=verify_journal(path.parent/'checkpoints.jsonl')
                if recovery.get('passed') is True and recovery.get('run_id')==folder.name and recovery.get('tasks_replayed') is False and chain==recovery.get('checkpoints'):
                    recovered=True
        if records[0].get('purpose')!='two local-model agents build Pong' or (records[-1]['event']!='run_completed' and not recovered):
            raise ValueError('Refusing cleanup of an unrecognized or unfinished test')
        evidence={'run_id':folder.name,'passed':False,'guests':[],'filesystem_unlink_only':True}
        for name in ('guest-a-serial','guest-b-serial'):
            workspace=folder/name
            state=StateStore(workspace).load(required=False)
            if not state:continue
            if state['registered']:raise ValueError('Completed test still has a registered VM; inspect first')
            def cli(*args):
                result=subprocess.run([sys.executable,'-B','-m','agenticvm','--workspace',str(workspace),*map(str,args)],
                    cwd=ROOT,env={**os.environ,'PYTHONPATH':str(ROOT/'src')},capture_output=True,timeout=90,
                    creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                value=json.loads(result.stdout)
                if result.returncode or not value.get('ok'):raise RuntimeError(str(value))
                return value['result']
            booted=False
            try:
                booted=True
                cli('start','--profile','agent','--persistent','--memory','256','--image',ROOT/'runtime/linux-peer/agenticvm-linux-peer.iso')
                code="from pathlib import Path; import json; p=Path('/workspace/peer/key.pem'); assert not p.is_symlink() and p.parent.resolve()==Path('/workspace/peer'); was=p.exists(); p.unlink(missing_ok=True); print(json.dumps({'private_key_was_present':was,'private_key_removed':not p.exists()}))"
                output=cli('exec','--','/usr/bin/python3','-I','-c',code)
                if output['exit_code']!=0:raise ValueError('Guest key cleanup failed')
                row=json.loads(output['stdout'])
                cli('exec','--','/bin/sync')
            finally:
                if booted:
                    stopped=cli('stop')
            evidence['guests'].append({'name':name,**row,'socket_cleanup':stopped.get('socket_cleanup')})
        evidence['passed']=all(row['private_key_removed'] and row['socket_cleanup'] for row in evidence['guests'])
        (folder/'key-cleanup.json').write_text(json.dumps(evidence,indent=2)+'\n')
        reports.append(evidence)
        print(json.dumps({'run_id':folder.name,'private_guest_keys_removed':evidence['passed']}),flush=True)
    return 0 if all(report['passed'] for report in reports) else 1


if __name__=='__main__':raise SystemExit(main())
