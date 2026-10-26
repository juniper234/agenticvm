"""Finite build/test checkpoint loop, scoped to disposable private-LAN VMs."""
import json,subprocess,sys,time
from pathlib import Path
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import save,digest

def main():
    result={'schema':'agenticvm.lan-suite.v1','passed':False,'cases':[],
        'strict_zero_preparation_replication_achieved':False,'authorized_ssh_baseline_only':True}
    begin=time.monotonic()
    for case in ('happy','resume','bad-hash','wrong-grant','ssh-unavailable'):
        print('Native case: '+case,flush=True)
        parent=ROOT/'runtime/lan-enrollment-runs';before={p.name for p in parent.iterdir() if p.is_dir()}
        child=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts/run-lan-enrollment.py'),'--case',case],cwd=ROOT)
        fresh=[p for p in parent.iterdir() if p.is_dir() and p.name not in before]
        if len(fresh)!=1 or not (fresh[0]/'report.json').exists(): raise RuntimeError('Native case did not leave exactly one receipt')
        path=fresh[0]/'report.json';receipt=json.loads(path.read_text())
        result['cases'].append({'case':case,'passed':receipt['passed'],'report':str(path),'sha256':digest(path),
                                'elapsed_seconds':receipt['elapsed_seconds']})
        if child.returncode or not receipt['passed']: break
    else:
        print('Native case: controller crash and idempotent ownership recovery',flush=True)
        child=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts/verify-lan-recovery.py')],cwd=ROOT)
        result['real_controller_crash_recovery_passed']=child.returncode==0
        result['passed']=child.returncode==0
    result['elapsed_seconds']=round(time.monotonic()-begin,3)
    path=ROOT/'docs/validation'/('lan-suite-'+str(uuid4())+'.json');save(path,result)
    print(json.dumps({'passed':result['passed'],'report':str(path)},indent=2),flush=True)
    return 0 if result['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
