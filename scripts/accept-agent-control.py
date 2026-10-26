"""Native control-plane acceptance. Freeze sources; test owned guests sequentially."""
from pathlib import Path
import argparse,base64,hashlib,json,os,subprocess,sys,time,traceback
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.control_client import ControlClient,PROFILES
from agenticvm.errors import AgenticVMError
from agenticvm.control_store import save_json


def pins():
    files=list((ROOT/'src/agenticvm').glob('*.py'))+[ROOT/'guest/control_job.py',ROOT/'guest/windows_desktop_agent.py',Path(__file__).resolve()]
    files+=list((ROOT/'guest/android-jobs').rglob('*.java'))
    files+=[ROOT/'tools/android/jobs/runner.jar',ROOT/'tools/android/jobs/receipt.json']
    return {str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--profiles',nargs='+',choices=list(PROFILES),default=['windows','linux','android'])
    args=parser.parse_args(); folder=ROOT/'runtime/agent-control-acceptance'/uuid4().hex; folder.mkdir(parents=True)
    client=ControlClient(); report={'schema':'agenticvm.native-agent-control.v1','at':time.time(),'source_pins':pins(),'profiles':{},'ok':False,'computer_use':False}
    receipt=folder/'report.json'
    def save():save_json(receipt,report)
    def freeze():assert report['source_pins']==pins(),'Runtime sources changed during acceptance'
    def ready(vm):
        for _ in range(6):
            result=client.wait(vm,'desktop',60)
            if not result['timed_out']:break
        assert result['satisfied'],str(result)[:1500]
        return result['state']
    def leased(vm,previous=None):
        lease=client.control('lease_acquire',vm,owner='native-acceptance',seconds=300,**({'token':previous.lease} if previous else {}))
        return client.bound('main',lease['token'],lease['generation'])
    def job_done(bound,vm,job,timeout=30):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            freeze(); state=bound.control('job_status',vm,job=job)
            if state['state'] in {'completed','failed','cancelled','timed_out','stale'}:return state
            time.sleep(.25)
        raise TimeoutError('Job completion was not observed: '+json.dumps(state))
    save(); print('Receipt: '+str(receipt),flush=True)
    try:
        for vm in args.profiles:
            entry=report['profiles'][vm]={'checks':[],'ok':False}
            def check(name,result=True):
                freeze(); entry['checks'].append({'name':name,'result':result,'at':time.time()}); save(); print(vm+' / '+name+': passed',flush=True)
            bound=None
            try:
                freeze(); current=client.status(); assert not current.get('registered'),'A guest is already running; do not interrupt it'
                client.start(vm,memory={'linux':768,'android':2560,'windows':2048}[vm],network=False,persistent=True)
                observed=ready(vm); check('native-ready',observed)
                root='C:/workspace/' if vm=='windows' else '/workspace/'
                # Android's /workspace is a file-tool alias, not an OS mount.
                command_root='/data/local/tmp/agenticvm/' if vm=='android' else root
                if vm=='windows':
                    # Verify data from the source-pinned v0.2 run survived the
                    # interrupted host storage optimization, before new writes.
                    previous=client.read_file(vm,root+'native-check.txt')
                    assert 'AgenticVM windows' in previous.decode('utf-8')
                    assert client.read_file(vm,root+'mcp-transfer.bin')==bytes(range(256))*4096
                    check('preexisting-windows-canaries-after-storage-incident')
                bound=leased(vm)
                health=bound.control('health',vm); caps=bound.control('capabilities',vm)
                assert health['guest']['guest_ready'] and caps['jobs'] and caps['checkpoints'] and caps['sync']
                assert caps['network_required_for_control'] is False
                for kind in caps['logs']:
                    log=bound.control('logs',vm,kind=kind,limit=4096)
                    assert log.get('bytes_read',0)<=4096
                check('health-capabilities-bounded-logs',{'jobs':caps['jobs'],'checkpoint_scope':caps['checkpoint_scope']})
                suffix=folder.name[:8]; path=root+'control-canary-'+suffix+'.txt'; before=('checkpoint '+vm+' \u4f60\u597d\n').encode()
                bound.write_file(vm,path,before)
                # Actual guest nonzero exit and bounded separate byte streams.
                command="[Console]::Out.Write(('x'*80000)); [Console]::Error.Write(('y'*80000)); exit 7" if vm=='windows' else 'head -c 80000 /dev/zero; head -c 80000 /dev/zero >&2; exit 7'
                job=bound.control('job_start',vm,command=command,seconds=30)['id']
                done=job_done(bound,vm,job)
                assert done['state']=='completed' and done['exit_code']==7 and done['tree_terminated'] and done['truncated'],str(done)
                reconnect=ControlClient().bound('main',bound.lease,bound.generation)
                for stream in ('stdout','stderr'):
                    output=reconnect.control('job_output',vm,job=job,stream=stream,cursor=0,limit=1234)
                    assert output['cursor']==1234 and output['retained_bytes']==65536
                check('durable-job-exit-truncation-cursors-reconnect',{'id':job,'exit_code':7,'retained_each':65536})
                orphan=command_root+'control-heartbeat-'+suffix+'.txt'
                if vm=='windows':
                    inner="while ($true) { [IO.File]::WriteAllText('"+orphan+"',[DateTime]::UtcNow.Ticks.ToString()); Start-Sleep -Milliseconds 300 }"
                    encoded=base64.b64encode(inner.encode('utf-16-le')).decode()
                    command="Start-Process powershell.exe -WindowStyle Hidden -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','"+encoded+"'); Start-Sleep -Seconds 180"
                else:command='(while :; do cat /proc/uptime > '+orphan+'; sleep 0.3; done) & sleep 180'
                bound=leased(vm,bound)
                cancel=bound.control('job_start',vm,command=command,seconds=180)['id']
                deadline=time.monotonic()+60
                while time.monotonic()<deadline:
                    try:
                        if bound.read_file(vm,orphan):break
                    except AgenticVMError:pass
                    time.sleep(.5)
                else:raise AssertionError('Child heartbeat did not start')
                time.sleep(1)
                cancellation=bound.control('job_cancel',vm,job=cancel)
                assert cancellation['cancellation_requested'],str(cancellation)
                done=job_done(bound,vm,cancel)
                assert done['state']=='cancelled' and done['tree_terminated'],str(done)
                stopped_heartbeat=bound.read_file(vm,orphan); time.sleep(4)
                assert bound.read_file(vm,orphan)==stopped_heartbeat,'Cancelled child heartbeat kept changing'
                check('cancellation-stops-descendant-processes',{'termination_scope':done['termination_scope'],'heartbeat_started':True,'heartbeat_stopped':True})
                timeout=bound.control('job_start',vm,command='Start-Sleep -Seconds 20' if vm=='windows' else 'sleep 20',seconds=1)['id']
                assert job_done(bound,vm,timeout)['state']=='timed_out'
                check('job-deadline')
                bound.control('job_forget',vm,job=timeout)
                try:bound.control('job_status',vm,job=timeout)
                except AgenticVMError as error:assert error.code=='invalid_job'
                else:raise AssertionError('Forgotten job remained registered')
                folder_path=command_root+'.agenticvm/jobs/'+timeout
                missing=bound.action(vm,'exec',command=("if (Test-Path -LiteralPath '"+folder_path+"') { exit 1 }" if vm=='windows' else 'test ! -d '+folder_path))
                assert missing['exit_code']==0,str(missing)
                check('finished-job-forget-reclaims-own-output')
                # Explicit conflict keeps both files until a revision/hash match.
                bound=leased(vm,bound)
                name='sync-'+suffix; relative='control-native/'+folder.name+'/'+vm+'.bin'
                host=client.exchange/relative; host.parent.mkdir(parents=True,exist_ok=True)
                payload=bytes(range(256))*4096; host.write_bytes(payload)
                guest=root+'control-sync-'+suffix+'.bin'
                bound.control('sync_create',vm,name=name,exchange_path=relative,guest_path=guest)
                first=bound.control('sync_apply',vm,name=name,revision=0,direction='push'); assert first['applied']
                assert bound.read_file(vm,guest)==payload
                bound=leased(vm,bound)
                host.write_bytes(b'host edit'); bound.write_file(vm,guest,b'guest edit')
                conflict=bound.control('sync_apply',vm,name=name,revision=1)
                assert conflict['conflict'] and not conflict['applied'] and host.read_bytes()==b'host edit'
                resolved=bound.control('sync_apply',vm,name=name,revision=1,direction='keep-both',host_hash=conflict['observed_host_hash'],guest_hash=conflict['observed_guest_hash'])
                assert (client.exchange/resolved['preserved_exchange_path']).read_bytes()==b'guest edit'
                assert bound.read_file(vm,guest)==b'host edit'
                check('binary-sync-and-both-changed-conflict',{'bytes':len(payload),'revision':resolved['revision']})
                # Native MCP and CLI processes use the same running control service.
                requests=[{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'vm_job_status','arguments':{'vm':vm,'job':job}}},
                    {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'vm_capabilities','arguments':{'vm':vm}}}]
                process=subprocess.run([sys.executable,'-I','-B','-m','agenticvm.desktop_mcp'],input=''.join(json.dumps(x)+'\n' for x in requests).encode(),capture_output=True,timeout=60)
                responses=[json.loads(line) for line in process.stdout.splitlines()]
                assert len(responses)==2 and all(not x.get('error') and not x['result']['isError'] for x in responses)
                process=subprocess.run([sys.executable,'-I','-B','-m','agenticvm.control_cli','--vm',vm,'health'],capture_output=True,timeout=60)
                assert process.returncode==0 and json.loads(process.stdout)['ok']
                check('real-stdio-mcp-and-cli')
                # Cold checkpoint, changed data, reviewed restore, cold canary.
                bound.action(vm,'stop'); bound=leased(vm)
                checkpoint=bound.control('checkpoint_create',vm,label='native-canary-'+suffix)
                bound.start(vm,network=False); ready(vm); bound=leased(vm)
                bound.write_file(vm,path,b'changed after checkpoint\n')
                assert bound.control('job_status',vm,job=job)['state']=='stale'
                try:
                    bound.control('checkpoint_create',vm,label='must-refuse-live')
                except AgenticVMError as error:assert error.code=='vm_must_be_stopped',str(error)
                else:raise AssertionError('Live checkpoint was accepted')
                bound.action(vm,'stop'); bound=leased(vm)
                plan=bound.control('checkpoint_plan',vm,checkpoint=checkpoint['id'])
                restored=bound.control('checkpoint_restore',vm,plan_id=plan['plan_id'],manifest_sha256=plan['manifest_sha256'])
                assert restored['phase']=='restored' and restored['rescue']
                bound.start(vm,network=False); ready(vm); bound=leased(vm)
                assert bound.read_file(vm,path)==before
                check('cold-checkpoint-rescue-restore-and-boot-canary',{'checkpoint':checkpoint['id'],'rescue':restored['rescue'],'scope':checkpoint['scope']})
                entry['ok']=True
            finally:
                current=client.status()
                if current.get('profile')==PROFILES[vm] and current.get('registered'):
                    client.action(vm,'stop')
                stopped=client.status(vm); assert stopped.get('registered') is False
                check('clean-stop')
                if bound is not None:
                    try:
                        lease=client.control('lease_acquire',vm,owner='native-acceptance',seconds=1)
                        client.bound('main',lease['token'],lease['generation']).control('lease_release',vm)
                    except AgenticVMError:pass
        report['ok']=all(x['ok'] for x in report['profiles'].values())
    except Exception as error:
        (folder/'failure-traceback.txt').write_text(traceback.format_exc(),encoding='utf-8')
        report['error']={'type':type(error).__name__,'code':getattr(error,'code',None),'message':str(error)[:4096]}
        print(json.dumps(report['error']),flush=True)
    finally:
        report['source_unchanged']=report['source_pins']==pins(); report['ok']=report['ok'] and report['source_unchanged']; save()
    print(json.dumps({'ok':report['ok'],'receipt':str(receipt)}),flush=True)
    return 0 if report['ok'] else 1


if __name__=='__main__':raise SystemExit(main())
