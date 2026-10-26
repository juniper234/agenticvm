"""Crash a real PXE controller after network boot; abort owned VMs without replay."""
import json,subprocess,sys,time
from pathlib import Path
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import NAMES,save
from agenticvm.qemu import WindowsProcess
from agenticvm.pxe_recovery import recover

def main():
    parent=ROOT/'runtime/pxe-enrollment-runs';parent.mkdir(parents=True,exist_ok=True)
    before={p.name for p in parent.iterdir() if p.is_dir()};folder=None
    log_path=ROOT/'runtime'/('pxe-crash-injection-'+str(uuid4())+'.log')
    with log_path.open('wb') as log:
        child=subprocess.Popen([sys.executable,'-I','-B',str(ROOT/'scripts/run-pxe-enrollment.py')],
            cwd=ROOT,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        deadline=time.monotonic()+300
        while time.monotonic()<deadline:
            if child.poll() is not None: raise RuntimeError('Controller exited before the PXE crash checkpoint')
            fresh=[path for path in parent.iterdir() if path.is_dir() and path.name not in before]
            if len(fresh)>1: raise RuntimeError('Concurrent PXE runs are ambiguous')
            if fresh: folder=fresh[0]
            if folder and all((folder/name/'ownership.json').exists() for name in NAMES):
                path=folder/'sprout-4/boot.log'
                if path.exists() and 'PXE_AGENT_ABSENT 192.0.2.4' in path.read_text(errors='replace'): break
            time.sleep(.5)
        else: raise TimeoutError('The real target did not boot from the mother before the crash deadline')
        owner=json.loads((folder/'owner.json').read_text())
        with WindowsProcess(child.pid,terminate=True) as process:
            if not process.alive() or process.created!=owner['created'] or str(process.executable)!=owner['executable']:
                raise RuntimeError('Controller ownership mismatch')
            process.terminate();process.wait(10)
        child.wait(10);survived=0
        for name in NAMES:
            state=json.loads((folder/name/'ownership.json').read_text())
            with WindowsProcess(state['pid']) as process:
                if process.alive() and process.created==state['created'] and str(process.executable)==state['executable']: survived+=1
        if survived!=5: raise RuntimeError('Five exact owned VMs must survive the controller crash')
        first=recover(folder.name);second=recover(folder.name)
        if not first['passed'] or not second['duplicate'] or first['tasks_replayed'] or len(first['resources'])!=5:
            raise RuntimeError('PXE ownership recovery failed')
        result={'passed':True,'schema':'agenticvm.pxe-recovery.v1','run_id':folder.name,
            'stage':'target booted Linux from the mother; enrollment may still be in progress',
            'real_controller_crash_injected':True,'five_exact_owned_vms_survived':True,
            'all_owned_vms_stopped':True,'disposable_disks_and_keys_removed':True,'second_recovery_idempotent':True,
            'tasks_replayed':False,'successful_enrollment_claimed_for_this_run':False,'recovery':first,
            'physical_4gb_host_tested':False}
        path=ROOT/'docs/validation'/('pxe-crash-recovery-'+folder.name+'.json');save(path,result)
        print(json.dumps({'passed':True,'report':str(path)},indent=2),flush=True)
    finally:
        if child.poll() is None: child.terminate();child.wait(10)
        if folder and not (folder/'recovery.json').exists() and not (folder/'report.json').exists(): recover(folder.name)

if __name__=='__main__': main()
