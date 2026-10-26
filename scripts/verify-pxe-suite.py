"""Finite PXE build/test loop, confined to the five named disposable VMs."""
import argparse,io,json,subprocess,sys,time,unittest
from pathlib import Path
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.pxe_lab import CASES,SOURCES
from agenticvm.lan_lab import digest,save

def reusable_happy(ident):
    from uuid import UUID
    if str(UUID(ident))!=ident: raise ValueError('Canonical existing run UUID required')
    path=ROOT/'runtime/pxe-enrollment-runs'/ident/'report.json'
    receipt=json.loads(path.read_text())
    if not receipt['passed'] or receipt['case']!='happy' or receipt['cleanup_failures']:
        raise ValueError('Existing happy run did not pass cleanly')
    if receipt['host_source_sha256']!=digest(ROOT/'src/agenticvm/pxe_lab.py'):
        raise ValueError('Host acceptance implementation changed after the existing run')
    if receipt['source_sha256']!={name:digest(ROOT/'guest'/name) for name in SOURCES}:
        raise ValueError('Guest implementation changed after the existing run')
    if receipt['base_manifest_sha256']!=digest(ROOT/'runtime/linux-pxe-base-v3/build-manifest.json'):
        raise ValueError('Boot image changed after existing run')
    return path

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--existing-happy')
    args=parser.parse_args();started=time.monotonic()
    result={'schema':'agenticvm.pxe-suite.v1','passed':False,'cases':[],
        'ssh_used':False,'strict_zero_preparation_replication_achieved':False,
        'initial_boot_authenticated':False,'physical_4gb_host_tested':False}
    log=io.StringIO()
    tests=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.defaultTestLoader.discover(str(ROOT/'tests')))
    result['host_tests']={'run':tests.testsRun,'failures':len(tests.failures),'errors':len(tests.errors),'skipped':len(tests.skipped)}
    host_path=ROOT/'docs/validation'/('pxe-host-tests-'+str(uuid4())+'.txt');host_path.write_text(log.getvalue())
    result['host_test_log']={'path':str(host_path),'sha256':digest(host_path)}
    print('Host tests: '+str(result['host_tests']),flush=True)
    if tests.wasSuccessful():
        for case in CASES:
            if case=='happy' and args.existing_happy: path=reusable_happy(args.existing_happy);code=0
            else:
                print('Native PXE case: '+case,flush=True)
                parent=ROOT/'runtime/pxe-enrollment-runs';parent.mkdir(parents=True,exist_ok=True)
                before={path.name for path in parent.iterdir() if path.is_dir()}
                child=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts/run-pxe-enrollment.py'),'--case',case],cwd=ROOT)
                fresh=[path for path in parent.iterdir() if path.is_dir() and path.name not in before]
                if len(fresh)!=1 or not (fresh[0]/'report.json').exists(): raise RuntimeError('Native case left no unique receipt')
                path=fresh[0]/'report.json';code=child.returncode
            receipt=json.loads(path.read_text())
            result['cases'].append({'case':case,'passed':receipt['passed'],'report':str(path),'sha256':digest(path),
                'elapsed_seconds':receipt['elapsed_seconds'],'actual_model_completions':receipt.get('actual_model_completions',0)})
            if code or not receipt['passed']: break
        else:
            print('Native PXE case: controller crash after target network boot',flush=True)
            child=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts/verify-pxe-recovery.py')],cwd=ROOT)
            result['real_controller_crash_recovery_passed']=child.returncode==0
            result['passed']=child.returncode==0
    result['elapsed_seconds']=round(time.monotonic()-started,3)
    result['actual_model_completions']=sum(row['actual_model_completions'] for row in result['cases'])
    result['source_sha256']={str(path.relative_to(ROOT)):digest(path) for pattern in (
        'src/agenticvm/pxe*.py','guest/pxe*','scripts/*pxe*.py','tests/test_pxe_enrollment.py','Garden-PXE-Lab.cmd')
        for path in ROOT.glob(pattern) if path.is_file()}
    path=ROOT/'docs/validation'/('pxe-suite-'+str(uuid4())+'.json');save(path,result)
    print(json.dumps({'passed':result['passed'],'report':str(path)},indent=2),flush=True)
    return 0 if result['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
