"""Inject a real controller crash, then abort only its exact owned lab VMs."""
from pathlib import Path
import json,subprocess,sys,time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agenticvm.lan_lab import ROOT,NAMES,save,completed_guest_report,reconcile
from agenticvm.qemu import WindowsProcess
from agenticvm.lan_recovery import recover

def main(stage='boot',*,delegated=False):
    parent=ROOT/('runtime/delegated-enrollment-runs' if delegated else 'runtime/lan-enrollment-runs');parent.mkdir(parents=True,exist_ok=True)
    before={p.name for p in parent.iterdir() if p.is_dir()}
    output=ROOT/('runtime/delegated-recovery-injection.log' if delegated else 'runtime/lan-recovery-injection.log')
    with output.open('ab') as log:
        child=subprocess.Popen([sys.executable,'-I','-B',str(ROOT/('scripts/run-delegated-enrollment.py' if delegated else 'scripts/run-lan-enrollment.py'))],
            cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
    folder=None;result=None
    try:
        deadline=time.monotonic()+(400 if stage=='joined' else 100)
        joined_proof=None
        while time.monotonic()<deadline:
            if child.poll() is not None: raise RuntimeError('Controller exited before crash checkpoint; inspect '+str(output))
            fresh=[p for p in parent.iterdir() if p.is_dir() and p.name not in before]
            if len(fresh)>1: raise RuntimeError('Concurrent lab folders are ambiguous')
            if fresh: folder=fresh[0]
            booted=folder and all((folder/name/'ownership.json').exists() and
                    (folder/name/'boot.log').exists() and 'LAN_BOOT_READY' in (folder/name/'boot.log').read_text(errors='replace') for name in NAMES)
            if booted:
                if stage=='boot': break
                guest=completed_guest_report((folder/'mother/boot.log').read_text(errors='replace'))
                if guest is not None:
                    if not guest.get('passed'): raise RuntimeError('Enrollment failed before the joined crash checkpoint')
                    joined_proof=reconcile(guest['statuses']);break
            time.sleep(.5)
        else: raise TimeoutError('Five real guests did not reach the crash checkpoint')
        owner=json.loads((folder/'owner.json').read_text())
        bindings=[json.loads((folder/name/'ownership.json').read_text()) for name in NAMES]
        with WindowsProcess(child.pid,terminate=True) as process:
            if not process.alive() or process.created!=owner['created'] or str(process.executable)!=owner['executable']:
                raise RuntimeError('Controller identity mismatch')
            process.terminate();process.wait(10)
        child.wait(10)
        alive=0
        for state in bindings:
            with WindowsProcess(state['pid']) as process:
                if process.alive() and process.created==state['created'] and str(process.executable)==state['executable']: alive+=1
        if alive!=5: raise RuntimeError('Five surviving exact owned guests were required')
        first=recover(folder.name,delegated=delegated);second=recover(folder.name,delegated=delegated)
        if not first['passed'] or not second['duplicate'] or first['tasks_replayed'] or len(first['resources'])!=5:
            raise RuntimeError('Recovery evidence did not reconcile')
        result={'passed':True,'run_id':folder.name,'crash_stage':stage,'joined_model_proof':joined_proof,'real_controller_crash_injected':True,
            'exact_owned_vms_alive_after_crash':alive,'all_five_owned_vms_stopped':True,
            'disposable_disks_and_keys_removed':True,'second_recovery_idempotent':True,'tasks_replayed':False,
            'recovery':first,'physical_hosts_tested':1,'physical_4gb_host_tested':False}
        prefix='delegated' if delegated else 'lan'
        path=ROOT/('docs/validation/'+prefix+('-recovery-joined-report.json' if stage=='joined' else '-recovery-report.json'))
        if path.exists(): path=path.with_name(prefix+'-recovery-report-'+folder.name+'.json')
        save(path,result)
        print(json.dumps({'passed':True,'report':str(path)},indent=2))
    finally:
        if child.poll() is None:
            child.terminate();child.wait(10)
        if folder and not (folder/'recovery.json').exists() and not (folder/'report.json').exists():
            recover(folder.name,delegated=delegated)

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--stage',choices=('boot','joined'),default='boot')
    parser.add_argument('--delegated',action='store_true')
    args=parser.parse_args();main(args.stage,delegated=args.delegated)
