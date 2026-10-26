"""Kill the owned three-VM boot controller, then verify exact, idempotent abort."""
import json,subprocess,sys,time
from pathlib import Path
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from agenticvm.realism_recovery import recover,require_clean_history
from agenticvm.realism_lab import PARENT
from agenticvm.lan_lab import save
from agenticvm.qemu import WindowsProcess

def main():
    require_clean_history();PARENT.mkdir(parents=True,exist_ok=True)
    before={p.name for p in PARENT.iterdir() if p.is_dir()};folder=None;result={'passed':False,'tasks_replayed':False}
    log_path=ROOT/'runtime'/('realism-crash-'+str(uuid4())+'.log')
    with log_path.open('wb') as log:
        child=subprocess.Popen([sys.executable,'-I','-B',str(ROOT/'scripts/probe-realism.py'),'--profile','bios-default'],cwd=ROOT,
            stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            if child.poll() is not None: raise RuntimeError('Boot controller finished before the crash checkpoint')
            fresh=[p for p in PARENT.iterdir() if p.is_dir() and p.name not in before]
            if len(fresh)>1: raise RuntimeError('Ambiguous concurrent lab runs')
            if fresh: folder=fresh[0]
            if folder:
                path=folder/'target/boot.log'
                if path.exists() and 'REALISM_NETWORK_BOOT_EXECUTED' in path.read_text(errors='replace'): break
            time.sleep(.1)
        else: raise TimeoutError('Target never reached the network-boot crash checkpoint')
        owner=json.loads((folder/'owner.json').read_text())
        with WindowsProcess(child.pid,terminate=True) as p:
            if not p.alive() or p.created!=owner['created'] or str(p.executable)!=owner['executable']: raise ValueError('Controller identity mismatch')
            p.terminate();p.wait(10)
        child.wait(10);alive=0
        for name in ('mother','target','dhcp'):
            state=json.loads((folder/name/'ownership.json').read_text())
            with WindowsProcess(state['pid']) as p:
                if p.alive() and p.created==state['created'] and str(p.executable)==state['executable']: alive+=1
        if alive!=3: raise ValueError('Three exact owned VMs did not survive controller termination')
        first=recover(folder.name);second=recover(folder.name)
        if not first['passed'] or not second['duplicate'] or first['tasks_replayed']: raise ValueError('Abort/recovery failed')
        result.update(passed=True,run_id=folder.name,three_owned_vms_survived_controller_crash=True,
            recovery=first,second_recovery_idempotent=True,successful_model_enrollment_claimed=False)
    except Exception as error: result['error']=type(error).__name__+': '+str(error)
    finally:
        if child.poll() is None: child.terminate();child.wait(10)
        if folder and not (folder/'report.json').exists() and not (folder/'recovery.json').exists(): recover(folder.name)
    path=ROOT/'docs/validation'/('realism-crash-'+str(uuid4())+'.json');save(path,result)
    print(json.dumps({'passed':result['passed'],'report':str(path),'error':result.get('error')},indent=2),flush=True)
    return 0 if result['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
