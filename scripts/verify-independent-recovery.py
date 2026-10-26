"""Crash the independent-VM controller after stock-default network boot, then abort."""
import json,subprocess,sys,time
from pathlib import Path
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.independent_recovery import NAMES,recover,require_clean_history
from agenticvm.lan_lab import save,digest
from agenticvm.qemu import WindowsProcess

def main():
    require_clean_history();parent=ROOT/'runtime/independent-vm-runs'
    before={p.name for p in parent.iterdir() if p.is_dir()};folder=None
    output=ROOT/'runtime'/('independent-crash-'+str(uuid4())+'.log')
    with output.open('wb') as log:
        child=subprocess.Popen([sys.executable,'-I','-B',str(ROOT/'scripts/run-independent-enrollment.py')],cwd=ROOT,
            stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        deadline=time.monotonic()+300
        while time.monotonic()<deadline:
            if child.poll() is not None: raise RuntimeError('Controller exited before stock-default boot checkpoint')
            fresh=[p for p in parent.iterdir() if p.is_dir() and p.name not in before]
            if len(fresh)>1: raise RuntimeError('Concurrent experiments are ambiguous')
            if fresh: folder=fresh[0]
            if folder and all((folder/name/'ownership.json').exists() for name in NAMES):
                path=folder/'independent-target/boot.log'
                if path.exists() and 'INDEPENDENT_AGENT_ABSENT_AT_BOOT' in path.read_text(errors='replace'): break
            time.sleep(.5)
        else: raise TimeoutError('Independent target never reached network-boot checkpoint')
        owner=json.loads((folder/'owner.json').read_text())
        with WindowsProcess(child.pid,terminate=True) as p:
            if not p.alive() or p.created!=owner['created'] or str(p.executable)!=owner['executable']:
                raise RuntimeError('Controller ownership mismatch')
            p.terminate();p.wait(10)
        child.wait(10);alive=0
        for name in NAMES:
            state=json.loads((folder/name/'ownership.json').read_text())
            with WindowsProcess(state['pid']) as p:
                if p.alive() and p.created==state['created'] and str(p.executable)==state['executable']: alive+=1
        if alive!=4: raise RuntimeError('Four exact owned VMs must survive the controller crash')
        first=recover(folder.name);second=recover(folder.name)
        if not first['passed'] or not second['duplicate'] or first['tasks_replayed']:
            raise RuntimeError('Independent ownership recovery failed')
        result={'schema':'agenticvm.independent-recovery.v1','passed':True,'run_id':folder.name,
            'four_owned_vms_survived_controller_crash':True,'all_owned_vms_stopped':True,
            'disks_keys_removed':True,'second_recovery_idempotent':True,'tasks_replayed':False,
            'stage':'stock-default target booted network Linux; enrollment may be in progress',
            'successful_enrollment_claimed_for_this_crash_run':False,'recovery':first}
        path=ROOT/'docs/validation'/('independent-crash-'+folder.name+'.json');save(path,result)
        print(json.dumps({'passed':True,'report':str(path)},indent=2),flush=True)
    finally:
        if child.poll() is None: child.terminate();child.wait(10)
        if folder and not (folder/'report.json').exists() and not (folder/'recovery.json').exists(): recover(folder.name)

if __name__=='__main__': main()
