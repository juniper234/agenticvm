"""Independently reconcile completed PXE suite receipts and owned-resource cleanup."""
import argparse,json,sys
from pathlib import Path
from uuid import UUID
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import NAMES,digest,save,reconcile
from agenticvm.pxe_lab import CASES,SOURCES,validated_base
from agenticvm.peers import verify_journal
from agenticvm.qemu import WindowsProcess

def inside(path,parent):
    path=Path(path).resolve();path.relative_to(parent.resolve());return path

def verify(suite_path,crash_path):
    suite_path=inside(suite_path,ROOT/'docs/validation');crash_path=inside(crash_path,ROOT/'docs/validation')
    suite=json.loads(suite_path.read_text());crash=json.loads(crash_path.read_text())
    if not suite['passed'] or suite['host_tests']!={'run':290,'failures':0,'errors':0,'skipped':0}:
        raise ValueError('Host/native suite was incomplete or failed')
    if [row['case'] for row in suite['cases']]!=list(CASES): raise ValueError('All five native scenarios are required')
    log=suite['host_test_log']
    if digest(inside(log['path'],ROOT/'docs/validation'))!=log['sha256']: raise ValueError('Host test log changed')
    base=validated_base();receipts=[];completions=0
    for row in suite['cases']:
        path=inside(row['report'],ROOT/'runtime/pxe-enrollment-runs')
        receipt=json.loads(path.read_text());folder=path.parent
        if str(UUID(receipt['run_id']))!=folder.name or digest(path)!=row['sha256']:
            raise ValueError('A native receipt identity/hash changed')
        if not receipt['passed'] or receipt['cleanup_failures'] or not receipt['all_owned_lab_vms_stopped']:
            raise ValueError('A native run failed or left resources')
        if receipt['host_source_sha256']!=digest(ROOT/'src/agenticvm/pxe_lab.py'):
            raise ValueError('Host acceptance source changed after a native run')
        if receipt['source_sha256']!={name:digest(ROOT/'guest'/name) for name in SOURCES}:
            raise ValueError('Guest source changed after a native run')
        if receipt['base_manifest_sha256']!=digest(ROOT/'runtime/linux-pxe-base-v3/build-manifest.json'):
            raise ValueError('Base image provenance changed')
        if verify_journal(folder/'checkpoints.jsonl')!=receipt['checkpoints']:
            raise ValueError('Checkpoint journal changed')
        initial=json.loads((folder/'sprout-4/initial-inventory.json').read_text())
        if set(initial['files'])!={'','owned-pxe-data'}: raise ValueError('Fresh target contained software before boot')
        launch=json.loads((folder/'sprout-4/launch.json').read_text())
        if not launch['network_boot'] or launch['local_os_boot_disk'] or any(arg in launch['argv'] for arg in ('-kernel','-initrd','-cdrom','-qmp','-virtfs')):
            raise ValueError('Target used a local OS boot path or a host command channel')
        if row['case'] in ('happy','resume'):
            guest_path=folder/'guest-report.json';guest=json.loads(guest_path.read_text())
            if digest(guest_path)!=receipt['guest_report_sha256']: raise ValueError('Model evidence changed')
            proof=reconcile(guest['statuses']);completions+=proof['actual_model_completions']
            if guest['target_receipt']['ssh_present'] or guest['idle_contact_seconds']<60:
                raise ValueError('SSH-free sustained contact evidence missing')
        for name in NAMES:
            if (folder/name/'workspace.ext2').exists(): raise ValueError('Disposable data disk remains')
            state=json.loads((folder/name/'ownership.json').read_text())
            with WindowsProcess(state['pid']) as process:
                if process.alive() and process.created==state['created']: raise ValueError('Owned test VM is still alive')
        if (folder/'private').exists(): raise ValueError('Disposable provisioning keys remain')
        receipts.append({'case':row['case'],'run_id':folder.name,'report':str(path),'sha256':digest(path)})
    if not (suite['real_controller_crash_recovery_passed'] and crash['passed'] and crash['real_controller_crash_injected']
            and crash['five_exact_owned_vms_survived'] and crash['second_recovery_idempotent'] and not crash['tasks_replayed']):
        raise ValueError('Real crash recovery evidence missing')
    crash_folder=ROOT/'runtime/pxe-enrollment-runs'/str(UUID(crash['run_id']))
    if json.loads((crash_folder/'recovery.json').read_text())!=crash['recovery']:
        raise ValueError('Recovery receipt changed')
    for name in NAMES:
        if (crash_folder/name/'workspace.ext2').exists(): raise ValueError('A crash-test private disk remains')
        state=json.loads((crash_folder/name/'ownership.json').read_text())
        with WindowsProcess(state['pid']) as process:
            if process.alive() and process.created==state['created']: raise ValueError('A crash-test VM remains')
    if (crash_folder/'private').exists(): raise ValueError('Crash-test keys remain')
    for relative,expected in suite['source_sha256'].items():
        if digest(inside(ROOT/relative,ROOT))!=expected: raise ValueError('Suite source changed: '+relative)
    old=ROOT/'dist/Garden-Sprout-LFM-v1/Sprout.exe'
    old_sha=digest(old)
    if old_sha!='dd359f7c8a1539e180fdc5df177052ef320dd14d57780d30883b52843ade8bf6':
        raise ValueError('The preserved single-file LFM alternative changed')
    result={'schema':'agenticvm.pxe-validation.v1','passed':True,'host_tests':suite['host_tests'],
        'native_scenarios_passed':6,'verified_model_completions':completions,
        'network_boot_enrollment_without_ssh_verified':True,'strict_unprepared_zero_click_replication_achieved':False,
        'initial_boot_authenticated':False,'physical_4gb_host_tested':False,
        'all_owned_pxe_test_vms_stopped_and_private_disks_keys_removed':True,
        'suite':{'path':str(suite_path),'sha256':digest(suite_path)},'cases':receipts,
        'crash_recovery':{'path':str(crash_path),'sha256':digest(crash_path)},
        'preserved_lfm_alternative_sha256':old_sha,
        'limits':['Preconfigured network boot and a trusted private boot LAN are required.',
            'Initial boot uses plain HTTP; no Secure Boot or hostile-LAN authentication claim.',
            'A network-supplied Debian environment is started; an existing OS is not modified.',
            'One physical host, 2432 MiB guest allocation plus host overhead; physical 4 GB target untested.',
            'Fixed mother enrollment policy, model-generated introductions only; no recursive propagation.',
            'Workspace development launcher; target restart persistence and uncertain-task replay are not validated.']}
    path=ROOT/'docs/validation/pxe-validation-final.json';save(path,result)
    print(json.dumps({'passed':True,'report':str(path)},indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--suite',required=True);parser.add_argument('--crash-report',required=True)
    args=parser.parse_args();verify(args.suite,args.crash_report)
