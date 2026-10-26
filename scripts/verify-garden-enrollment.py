"""Finite native compatibility/recovery acceptance. Never silently repairs a failed case."""
import argparse,io,json,subprocess,sys,time,unittest
from pathlib import Path
from uuid import UUID,uuid4
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import save,digest,reconcile
from agenticvm.realism_lab import PARENT,sources
from agenticvm.realism_recovery import require_clean_history,NAMES,FILES
from agenticvm.peers import verify_journal
from agenticvm.qemu import WindowsProcess

def cleaned(folder):
    if (folder/'private').exists(): raise ValueError('Private enrollment keys remain')
    for name in NAMES:
        for filename in FILES:
            if (folder/name/filename).exists(): raise ValueError('Disposable writable lab input remains')
        path=folder/name/'ownership.json'
        if path.exists():
            state=json.loads(path.read_text())
            with WindowsProcess(state['pid']) as p:
                if p.alive() and p.created==state['created']: raise ValueError('An exact owned VM is still running')

def validate(path):
    report=json.loads(path.read_text());folder=path.parent
    if not report['passed'] or report['cleanup_failures'] or not report['blank_disk_unchanged'] or report['source_changed_during_run']:
        raise ValueError('Native scenario failed or changed input/storage')
    for field in ('source_sha256','additional_source_sha256'):
        for name,sha in report.get(field,{}).items():
            if digest(ROOT/name)!=sha: raise ValueError('Native case source changed: '+name)
    cleaned(folder)
    if verify_journal(folder/'checkpoints.jsonl')!=report['checkpoints']: raise ValueError('Checkpoint journal changed')
    if report['case'] in ('lfm-fault-enrollment','secure-lfm-fault-enrollment'):
        guest=folder/'guest-report.json'
        if digest(guest)!=report['guest_report_sha256']: raise ValueError('Guest model evidence changed')
        proof=reconcile(json.loads(guest.read_text())['statuses'])
        if not report['recovered_after_network_failure'] or report['model_tasks_replayed'] or not report['interrupted_model_download_resumed']:
            raise ValueError('Expected network/download recovery not proved')
        if proof['actual_model_completions']!=10: raise ValueError('Actual model completion evidence missing')
        if not report['linux_dhcp_renewals_observed']: raise ValueError('Actual lease renewal was not observed')
        if report['case']=='secure-lfm-fault-enrollment' and not (report['secure_boot_enabled'] and report['initial_boot_authenticated']):
            raise ValueError('Protected model enrollment lacked authenticated boot')
    return report

def run(arguments):
    PARENT.mkdir(parents=True,exist_ok=True);before={p.name for p in PARENT.iterdir() if p.is_dir()}
    result=subprocess.run([sys.executable,'-I','-B',*map(str,arguments)],cwd=ROOT)
    fresh=[p for p in PARENT.iterdir() if p.is_dir() and p.name not in before]
    if result.returncode or len(fresh)!=1 or not (fresh[0]/'report.json').exists():
        raise RuntimeError('Native case failed; inspect the newly preserved run folder')
    path=fresh[0]/'report.json';validate(path);return path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contact-seconds',type=int,default=300)
    parser.add_argument('--existing-model-run',action='append',default=[])
    parser.add_argument('--existing-probe-run',action='append',default=[])
    parser.add_argument('--existing-protected-run',action='append',default=[])
    a=parser.parse_args()
    if not 60<=a.contact_seconds<=3600: parser.error('Contact window must be 60..3600 seconds')
    require_clean_history();begin=time.monotonic();paths=[]
    report={'schema':'agenticvm.realism-suite.v1','passed':False,'cases':[],
        'physical_hardware_tested':False,'physical_4gb_host_tested':False,'overnight_soak_tested':False,
        'all_enrollment_bootstraps_authenticated':False,'target_cold_reboot_recovery_implemented':False}
    try:
        log=io.StringIO();tests=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.defaultTestLoader.discover(str(ROOT/'tests')))
        logpath=ROOT/'docs/validation'/('realistic-host-tests-'+str(uuid4())+'.txt');logpath.write_text(log.getvalue())
        report['host_tests']={'run':tests.testsRun,'failures':len(tests.failures),'errors':len(tests.errors),'skipped':len(tests.skipped),
            'log':str(logpath),'log_sha256':digest(logpath)}
        if not tests.wasSuccessful(): raise RuntimeError('Host regression tests failed')
        print('Host tests passed: '+str(tests.testsRun),flush=True)
        reused={}
        for ident in a.existing_probe_run+a.existing_model_run+a.existing_protected_run:
            if str(UUID(ident))!=ident: raise ValueError('Canonical run UUID required')
            path=PARENT/ident/'report.json';prior=validate(path)
            key=(prior['case'],prior['profile'],prior.get('tampered'))
            if key in reused: raise ValueError('Duplicate reused scenario')
            reused[key]=path
        for profile,delay in (('uefi-default',0),('network-boot-disabled',0),('linux-os-control',0),
            ('bios-default',0),('uefi-e1000e',10)):
            key=('boot-probe',profile,None)
            if key in reused:
                path=reused[key]
                if json.loads(path.read_text()).get('dhcp_start_delay_seconds',0)!=delay: raise ValueError('Reused DHCP delay does not match')
            else: path=run([ROOT/'scripts/probe-realism.py','--profile',profile,'--delay-dhcp',str(delay)])
            paths.append(path)
        for profile,seconds,secure in (('uefi-stock-rng',60,False),('uefi-virtio',a.contact_seconds,False),('uefi-virtio',60,True)):
            key=('secure-lfm-fault-enrollment' if secure else 'lfm-fault-enrollment','uefi-secure-uki' if secure else profile,None)
            if key in reused:
                path=reused[key]
                if json.loads(path.read_text())['contact_seconds']<seconds: raise ValueError('Reused contact window is too short')
            else: path=run([ROOT/'scripts/run-realistic-enrollment.py','--profile',profile,'--contact-seconds',str(seconds),*(['--secure-boot'] if secure else [])])
            paths.append(path)
        # Actual-model enrollment already proves the positive boot paths for
        # stock UEFI, virtio UEFI and protected UKI. Do not duplicate them with
        # weaker boot-only positives in the same final suite.
        for tampered in (True,):
            key=('secure-network-boot','uefi-secure-uki',tampered)
            path=reused[key] if key in reused else run([ROOT/'scripts/verify-protected-network-boot.py',*(['--tampered'] if tampered else [])])
            paths.append(path)
        before={p.name for p in (ROOT/'docs/validation').glob('secure-boot-controls-*.json')}
        secure=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts/verify-secure-boot.py')],cwd=ROOT)
        fresh=[p for p in (ROOT/'docs/validation').glob('secure-boot-controls-*.json') if p.name not in before]
        if secure.returncode or len(fresh)!=1: raise RuntimeError('Native Secure Boot enforcement controls failed')
        sb=json.loads(fresh[0].read_text())
        if not sb['passed'] or len(sb['cases'])!=2 or not all(x['owned_vm_stopped'] for x in sb['cases']): raise ValueError('Secure Boot evidence incomplete')
        report['secure_boot_controls']={'path':str(fresh[0]),'sha256':digest(fresh[0]),'native_cases':2,'garden_enrollment_claimed':False}
        before={p.name for p in (ROOT/'docs/validation').glob('realism-crash-*.json')}
        crash=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts/verify-enrollment-crash.py')],cwd=ROOT)
        fresh=[p for p in (ROOT/'docs/validation').glob('realism-crash-*.json') if p.name not in before]
        if crash.returncode or len(fresh)!=1: raise RuntimeError('Native controller-crash control failed')
        c=json.loads(fresh[0].read_text())
        if not c['passed'] or c['tasks_replayed'] or not c['second_recovery_idempotent']: raise ValueError('Crash recovery incomplete')
        cleaned(PARENT/c['run_id']);report['controller_crash']={'path':str(fresh[0]),'sha256':digest(fresh[0])}
        for path in paths:
            native=validate(path);report['cases'].append({'case':native['case'],'profile':native['profile'],
                'path':str(path),'sha256':digest(path),'elapsed_seconds':native['elapsed_seconds']})
        report.update(passed=True,native_scenarios_passed=len(paths)+3,actual_model_completions=30,completed_model_exchanges=15,
            protected_actual_model_enrollment_verified=True,protected_boot_requires_preprovisioned_firmware_trust=True,
            actual_model_runs_also_cover_positive_network_boot=True,
            longest_contact_seconds=max(json.loads(p.read_text()).get('contact_seconds',0) for p in paths),
            all_owned_test_vms_stopped_and_writable_disks_keys_removed=True,
            source_sha256={**sources(),**{str(p.relative_to(ROOT)):digest(p) for p in (
                Path(__file__),ROOT/'scripts/verify-secure-boot.py',ROOT/'scripts/verify-enrollment-crash.py',
                ROOT/'scripts/verify-protected-network-boot.py',ROOT/'scripts/run-realistic-enrollment.py',
                ROOT/'scripts/prepare-modern-uefi.py',ROOT/'scripts/prepare-uefi-python.py',ROOT/'scripts/prepare-kernel-network.py',
                ROOT/'scripts/prepare-uki-stub.py',ROOT/'scripts/prepare-efi-variable-module.py',ROOT/'Garden-Realistic-Lab.cmd',
                ROOT/'src/agenticvm/enrollment_realism.py',ROOT/'src/agenticvm/lab_metrics.py',ROOT/'src/agenticvm/secure_network.py',ROOT/'src/agenticvm/uki.py',
                ROOT/'src/agenticvm/lan_lab.py',ROOT/'src/agenticvm/independent_lab.py',ROOT/'src/agenticvm/ext2.py',
                ROOT/'guest/garden_realistic.py',ROOT/'guest/secureboot_probe.zig',ROOT/'guest/secure_boot_http.py',ROOT/'guest/independent_boot_server.py',
                ROOT/'tests/test_realistic_lab.py')}})
    except Exception as error: report['error']={'type':type(error).__name__,'message':str(error)}
    report['elapsed_seconds']=round(time.monotonic()-begin,3)
    path=ROOT/'docs/validation'/('realistic-suite-'+str(uuid4())+'.json');save(path,report)
    print(json.dumps({'passed':report['passed'],'report':str(path),'error':report.get('error')},indent=2),flush=True)
    return 0 if report['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
