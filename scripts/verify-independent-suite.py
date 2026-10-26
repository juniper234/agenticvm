"""Finite, owned-lab loop for untouched-target boot, LFM communication and controls."""
import argparse,io,json,os,re,subprocess,sys,time,unittest
from pathlib import Path
from uuid import UUID,uuid4
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import save,digest,reconcile
from agenticvm.independent_recovery import NAMES,require_clean_history
from agenticvm.independent_lab import firmware_manifest
from agenticvm.peers import verify_journal
from agenticvm.qemu import WindowsProcess

def reused(ident,case):
    if str(UUID(ident))!=ident: raise ValueError('Canonical existing run UUID required')
    path=ROOT/'runtime/independent-vm-runs'/ident/'report.json';receipt=json.loads(path.read_text())
    if not receipt['passed'] or receipt['case']!=case or receipt['cleanup_failures']: raise ValueError('Existing native run did not pass cleanly')
    source=ROOT/('src/agenticvm/independent_lab.py' if case=='lfm-enrollment' else 'scripts/verify-independent-stock-os.py')
    if receipt.get('host_source_sha256',receipt.get('source_sha256'))!=digest(source): raise ValueError('Existing native run source changed')
    if case=='lfm-enrollment':
        for name,sha in receipt['guest_source_sha256'].items():
            if digest(ROOT/'guest'/name)!=sha: raise ValueError('Existing guest source changed: '+name)
    return path

def native(argv):
    parent=ROOT/'runtime/independent-vm-runs';parent.mkdir(parents=True,exist_ok=True)
    before={p.name for p in parent.iterdir() if p.is_dir()}
    result=subprocess.run([sys.executable,'-I','-B',*map(str,argv)],cwd=ROOT)
    fresh=[p for p in parent.iterdir() if p.is_dir() and p.name not in before]
    if result.returncode or len(fresh)!=1 or not (fresh[0]/'report.json').exists(): raise RuntimeError('Native case failed or left no unique completed receipt')
    return fresh[0]/'report.json'

def cleaned(folder):
    if (folder/'private').exists(): raise ValueError('Private provisioning keys remain')
    for name in NAMES:
        for filename in ('workspace.ext2','blank.raw'):
            if (folder/name/filename).exists(): raise ValueError('Disposable test disk remains')
        path=folder/name/'ownership.json'
        if path.exists():
            state=json.loads(path.read_text())
            with WindowsProcess(state['pid']) as p:
                if p.alive() and p.created==state['created']: raise ValueError('An owned test VM is still running')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--existing-enrollment');parser.add_argument('--existing-stock-os');parser.add_argument('--existing-crash')
    args=parser.parse_args();require_clean_history();start=time.monotonic()
    result={'schema':'agenticvm.independent-suite.v1','passed':False,'cases':[],
        'arbitrary_running_os_recruitment_achieved':False,'physical_4gb_host_tested':False,'initial_boot_authenticated':False}
    paths=[]
    try:
        log=io.StringIO();tests=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.defaultTestLoader.discover(str(ROOT/'tests')))
        result['host_tests']={'run':tests.testsRun,'failures':len(tests.failures),'errors':len(tests.errors),'skipped':len(tests.skipped)}
        log_path=ROOT/'docs/validation'/('independent-host-tests-'+str(uuid4())+'.txt');log_path.write_text(log.getvalue())
        result['host_test_log']={'path':str(log_path),'sha256':digest(log_path)}
        if not tests.wasSuccessful(): raise RuntimeError('Host tests failed')
        print('Host tests passed: '+str(tests.testsRun),flush=True)
        paths.append(reused(args.existing_enrollment,'lfm-enrollment') if args.existing_enrollment else native([ROOT/'scripts/run-independent-enrollment.py']))
        paths.append(native([ROOT/'scripts/probe-independent-defaults.py','--no-server']))
        stock=reused(args.existing_stock_os,'stock-alpine-os-control') if args.existing_stock_os else native([ROOT/'scripts/verify-independent-stock-os.py'])
        paths.append(stock);stock_receipt=json.loads(stock.read_text());frame=stock_receipt['framebuffer']
        if digest(Path(frame['path']))!=frame['sha256']: raise ValueError('Stock OS framebuffer changed')
        powershell=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
        ocr=subprocess.run([str(powershell),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(ROOT/'scripts/read-stock-screen.ps1'),'-Path',frame['path']],
            capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        if ocr.returncode: raise RuntimeError('Local stock OS screen OCR failed: '+ocr.stderr[-500:])
        observed=json.loads(ocr.stdout)
        if not re.search(r'alpine\s+linux',observed['text'],re.I) or not re.search(r'login\s*:',observed['text'],re.I):
            raise ValueError('Stock Linux did not reach its login prompt')
        result['stock_os_screen_verification']={**observed,'framebuffer_sha256':frame['sha256'],
            'alpine_login_prompt_verified':True,'raw_control_receipt_sha256':digest(stock)}
        print('Stock Linux login confirmed using local OCR; no guest keyboard or pointer input.',flush=True)
        if args.existing_crash:
            if str(UUID(args.existing_crash))!=args.existing_crash: raise ValueError('Canonical crash run UUID required')
            crash_folder=ROOT/'runtime/independent-vm-runs'/args.existing_crash
        else:
            before={p.name for p in (ROOT/'runtime/independent-vm-runs').iterdir() if p.is_dir()}
            crash=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts/verify-independent-recovery.py')],cwd=ROOT)
            fresh=[p for p in (ROOT/'runtime/independent-vm-runs').iterdir() if p.is_dir() and p.name not in before]
            if crash.returncode or len(fresh)!=1: raise RuntimeError('Real independent controller crash test failed')
            crash_folder=fresh[0]
        crash_path=ROOT/'docs/validation'/('independent-crash-'+crash_folder.name+'.json')
        crash_receipt=json.loads(crash_path.read_text())
        if not crash_receipt['passed'] or not crash_receipt['second_recovery_idempotent'] or crash_receipt['tasks_replayed']:
            raise ValueError('Crash recovery proof failed')
        if json.loads((crash_folder/'recovery.json').read_text())!=crash_receipt['recovery']:
            raise ValueError('Underlying ownership recovery receipt changed')
        cleaned(crash_folder);result['crash_recovery']={'path':str(crash_path),'sha256':digest(crash_path)}
        for path in paths:
            receipt=json.loads(path.read_text());folder=path.parent
            if not receipt['passed'] or receipt['cleanup_failures'] or not receipt['blank_disk_unchanged']:
                raise ValueError('A native case failed or changed target storage')
            cleaned(folder)
            if 'checkpoints' in receipt and verify_journal(folder/'checkpoints.jsonl')!=receipt['checkpoints']:
                raise ValueError('Checkpoint journal changed')
            result['cases'].append({'case':receipt['case'],'path':str(path),'sha256':digest(path),'elapsed_seconds':receipt['elapsed_seconds']})
        enrollment=json.loads(paths[0].read_text());guest_path=paths[0].parent/'guest-report.json'
        if digest(guest_path)!=enrollment['guest_report_sha256']: raise ValueError('Model completion evidence changed')
        proofs=reconcile(json.loads(guest_path.read_text())['statuses'])
        result.update(passed=True,**proofs,independent_blank_qemu_default_boot_enrollment_verified=True,
            native_scenarios_passed=4,all_owned_test_vms_stopped_and_private_disks_keys_removed=True,
            target_disk_unchanged=True,stock_firmware=firmware_manifest(),
            limits=['Observed QEMU PC BIOS blank-disk defaults, not a universal enrollment mechanism.',
                'The boot server must be available when firmware requests network boot.',
                'The agent runs in RAM; the blank disk remains unchanged and restart persistence is not implemented.',
                'Initial PXE/HTTP boot is unauthenticated and assumes a trusted owned LAN.',
                'The stock Linux OS control did not join; no exploit or authentication bypass was used.',
                'Four-model scenario allocates 2304 MiB guest RAM plus host overhead; a physical 4 GB host is untested.'])
    except Exception as error: result['error']={'type':type(error).__name__,'message':str(error)}
    result['elapsed_seconds']=round(time.monotonic()-start,3)
    result['source_sha256']={str(p.relative_to(ROOT)):digest(p) for pattern in (
        'src/agenticvm/independent*.py','src/agenticvm/framebuffer_observer.py','guest/independent*',
        'scripts/*independent*.py','scripts/prepare-stock-qemu*.py','scripts/read-stock-screen.ps1',
        'tests/test_independent_enrollment.py','Garden-Independent-Lab.cmd') for p in ROOT.glob(pattern) if p.is_file()}
    path=ROOT/'docs/validation'/('independent-suite-'+str(uuid4())+'.json');save(path,result)
    print(json.dumps({'passed':result['passed'],'report':str(path),'error':result.get('error')},indent=2),flush=True)
    return 0 if result['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
