"""Run the prepared model exclusively inside an owned, offline Linux guest."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT/'runtime/local-model-test'

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--memory',type=int,choices=(256,384,512,768,1024),default=512)
    parser.add_argument('--smoke',action='store_true')
    parser.add_argument('--calibration',action='store_true')
    args=parser.parse_args()
    evidence=FOLDER/f'evidence-{args.memory}-{uuid4().hex[:8]}'
    evidence.mkdir()
    env={**os.environ,'PYTHONPATH':str(ROOT/'src')}
    sys.path.insert(0,str(ROOT/'src'))
    from agenticvm.state import StateStore
    prior=StateStore(FOLDER/'vm').load(required=False)
    if prior and prior.get('registered'):
        raise RuntimeError('A test VM is already registered; inspect it before another experiment')
    def cli(*arguments):
        child=subprocess.run([sys.executable,'-B','-m','agenticvm','--workspace',str(FOLDER/'vm'),*map(str,arguments)],
                             cwd=ROOT,env=env,capture_output=True,timeout=100,
                             creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        value=json.loads(child.stdout)
        if child.returncode or not value.get('ok'):
            raise RuntimeError(json.dumps(value))
        return value['result']
    started=False
    try:
        started=True
        state=cli('start','--profile','agent','--persistent','--memory',args.memory,'--image',FOLDER/'boot/agenticvm-linux-peer.iso')
        (evidence/'start.json').write_text(json.dumps(state,indent=2)+'\n')
        cli('put',ROOT/'guest/test_local_model.py','test_local_model.py')
        dependency=FOLDER/'dependencies/libgomp.so.1'
        if dependency.exists():
            cli('exec','--','/bin/mkdir','-p','/workspace/dependencies')
            cli('put',dependency,'dependencies/libgomp.so.1')
        job=cli('exec','--async','--timeout-ms','0','--','/usr/bin/python3','-I','/workspace/test_local_model.py','--memory',args.memory,
                *(['--smoke'] if args.smoke else []), *(['--calibration'] if args.calibration else []))['job_id']
        deadline=time.monotonic()+600
        while time.monotonic()<deadline:
            snapshot=cli('poll',job,'--wait-ms','1000')
            if snapshot['state']=='exited':
                (evidence/'job.json').write_text(json.dumps(snapshot,indent=2)+'\n')
                break
        else:
            cli('cancel',job)
            raise TimeoutError('Guest experiment deadline')
        for filename in (f'result-{args.memory}.json',f'llama-{args.memory}.log',f'checkpoints-{args.memory}.jsonl'):
            cli('get',filename,evidence/filename)
        report=json.loads((evidence/f'result-{args.memory}.json').read_text())
        print(json.dumps({'runtime_passed':report['runtime_passed'],'memory_mib':args.memory,
                          'quality_score':report.get('quality_score'),'error':report.get('error'),
                          'report':str(evidence/f'result-{args.memory}.json')}),flush=True)
    finally:
        if started:
            result=cli('stop')
            (evidence/'stop.json').write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':
    main()
