"""Native two-Linux isolation/lease and disposable transaction acceptance."""
from pathlib import Path
import importlib.util,json,sys,time
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.control_client import ControlClient
from agenticvm.control_store import save_json
from agenticvm.errors import AgenticVMError
spec=importlib.util.spec_from_file_location('control_acceptance',ROOT/'scripts/accept-agent-control.py')
acceptance=importlib.util.module_from_spec(spec); spec.loader.exec_module(acceptance)


def main():
    folder=ROOT/'runtime/agent-session-acceptance'/uuid4().hex; folder.mkdir(parents=True)
    client=ControlClient(); names=['orch-'+folder.name[:8],'worker-'+folder.name[:8]]
    report={'schema':'agenticvm.native-sessions.v1','at':time.time(),'ok':False,'source_pins':acceptance.pins(),'sessions':names,'checks':[]}
    receipt=folder/'report.json'
    def check(name,result=True):
        assert acceptance.pins()==report['source_pins'],'Source changed during acceptance'
        report['checks'].append({'name':name,'result':result,'at':time.time()}); save_json(receipt,report); print(name+': passed',flush=True)
    def lease(name):
        result=client.control('lease_acquire','linux',session=name,owner='session-acceptance',seconds=300)
        return client.bound(name,result['token'],result['generation'])
    clients={}
    save_json(receipt,report); print('Receipt: '+str(receipt),flush=True)
    try:
        assert not client.status().get('registered'),'Main guest is already running'
        for name in names:
            client.control('session_create',name=name,guest='linux',disposable=True)
            scoped=lease(name); scoped.start('linux',memory=768,network=False)
            assert scoped.wait('linux','desktop',60)['satisfied']
            clients[name]=lease(name)
            clients[name].write_file('linux','/workspace/identity.txt',name.encode())
        states=[scoped.status('linux') for scoped in clients.values()]
        assert len({state['uuid'] for state in states})==2 and len({state['pid'] for state in states})==2
        assert len({state['workspace_disk'] for state in states})==2 and all(state['guest_ready'] for state in states)
        check('two-concurrent-independent-linux-guests',{'memory_each_mib':768,'network':'none','unique_processes':2,'unique_disks':2})
        for name,scoped in clients.items():
            assert scoped.read_file('linux','/workspace/identity.txt')==name.encode()
        first,second=(clients[name] for name in names)
        for scoped,expected in ((client.bound(names[1],first.lease,second.generation),'lease_required'),
            (client.bound(names[0],first.lease,'wrong-generation'),'generation_changed'),
            (client.bound('foreign',first.lease,first.generation),'invalid_session')):
            try:scoped.action('linux','key',keys='enter')
            except AgenticVMError as error:assert error.code==expected,str(error)
            else:raise AssertionError('Cross-session or stale operation was accepted')
        check('separate-files-and-foreign-lease-generation-denials')
        short=client.control('lease_acquire','linux',session=names[0],owner='session-acceptance',seconds=1,token=first.lease)
        time.sleep(2)
        try:client.bound(names[0],short['token'],short['generation']).action('linux','key',keys='enter')
        except AgenticVMError as error:assert error.code=='lease_required'
        else:raise AssertionError('Expired lease could type')
        clients[names[0]]=lease(names[0])
        check('expired-lease-cannot-type')
        jobs={}
        for name,scoped in clients.items():jobs[name]=scoped.control('job_start','linux',command='sleep 2; printf '+name,seconds=20)['id']
        for name,scoped in clients.items():
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                status=scoped.control('job_status','linux',job=jobs[name])
                if status['state']=='completed':break
                assert status['state'] not in {'failed','stale','timed_out'}; time.sleep(.5)
            assert status['exit_code']==0
            assert scoped.control('job_output','linux',job=jobs[name])['text']==name
            other=jobs[names[1] if name==names[0] else names[0]]
            try:scoped.control('job_status','linux',job=other)
            except AgenticVMError as error:assert error.code=='invalid_job'
            else:raise AssertionError('Foreign job was visible')
        check('independent-jobs-and-foreign-job-denial')
        for scoped in clients.values():scoped.action('linux','stop')
        # Only a disposable session may run automatic rollback.
        scoped=lease(names[0])
        failed=scoped.control('transaction','linux',command='echo changed > /workspace/identity.txt; exit 7',
            verify_command='exit 1',recovery_command='test "$(cat /workspace/identity.txt)" = '+names[0])
        assert failed['ok'] is False and failed.get('recovered') is True and failed['task_error'] and failed['recovery_error'] is None,str(failed)
        check('failed-task-restored-and-cold-verified',{'transaction':failed['id'],'phases':[x['phase'] for x in failed['phases']]})
        scoped=lease(names[0])
        success=scoped.control('transaction','linux',command='printf success > /workspace/transaction.txt',
            verify_command='test "$(cat /workspace/transaction.txt)" = success',recovery_command='test "$(cat /workspace/identity.txt)" = '+names[0])
        assert success['ok'] is True and success['recovery_error'] is None,str(success)
        check('successful-task-retained-and-cold-verified',{'transaction':success['id'],'phases':[x['phase'] for x in success['phases']]})
        report['ok']=True
    except Exception as error:
        report['error']={'type':type(error).__name__,'code':getattr(error,'code',None),'message':str(error)[:4096]}
        print(json.dumps(report['error']),flush=True)
    finally:
        for name in names:
            try:
                status=client.bound(name).status('linux')
                if status.get('registered'):
                    scoped=clients.get(name)
                    if scoped is None or scoped.generation!=status.get('generation'):scoped=lease(name)
                    scoped.action('linux','stop')
                stopped=client.bound(name).status('linux'); assert stopped.get('registered') is False
                check('clean-stop-'+name)
            except Exception as error:
                report['ok']=False; report.setdefault('cleanup_errors',[]).append({'session':name,'message':str(error)[:512]})
        report['source_unchanged']=acceptance.pins()==report['source_pins']; report['ok'] &= report['source_unchanged']; save_json(receipt,report)
    print(json.dumps({'ok':report['ok'],'receipt':str(receipt)}),flush=True)
    return 0 if report['ok'] else 1


if __name__=='__main__':raise SystemExit(main())
