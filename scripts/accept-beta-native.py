"""Fresh-source sequential native beta checks. No UI automation or host changes."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import sys
import threading
import time
from uuid import uuid4

ROOT=Path(os.environ.get('AGENTICVM_TEST_HOME',Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0,str(ROOT/'src'))
os.environ.setdefault('AGENTICVM_SOCKET_ROOT',str(ROOT/'runtime/ipc'))
from agenticvm.configuration import defaults,digest
from agenticvm.control_client import ControlClient
from agenticvm.desktop import png_dimensions
from agenticvm.resources import memory_status
from agenticvm.viewer import ViewerController,ViewerServer


def pins():
    files=list((ROOT/'src/agenticvm').glob('*.py'))+list((ROOT/'src/agenticvm/web').glob('*.*'))
    return {str(path.relative_to(ROOT)):digest(path) for path in files}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--profiles',nargs='+',choices=['linux','custom','windows','android'],default=['linux','custom','windows','android'])
    parser.add_argument('--iso',type=Path)
    args=parser.parse_args()
    folder=ROOT/'runtime/beta-native'/uuid4().hex;folder.mkdir(parents=True)
    report={'ok':False,'source_pins':pins(),'profiles':{},'resources':memory_status(),'started_at':time.time()}
    def save():
        (folder/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('Receipt: '+str(folder/'report.json'),flush=True);save()
    for vm in args.profiles:
        entry=report['profiles'][vm]={'ok':False,'checks':[]}
        workspace=ROOT/'runtime/glass-app/workspace' if vm=='windows' else folder/(vm+'-workspace')
        controller=ViewerController(workspace,'desktop-app' if vm=='windows' else 'beta',application_root=ROOT)
        if vm=='windows':
            try:
                controller.select_profile('windows')
                current=controller.store.load(required=False)
            except Exception as error:
                entry['blocked']=str(error);save();continue
            if not current or current['registered'] or not Path(current['disk']).is_file() or not (Path(current['disk']).parent/'installed.json').is_file():
                entry['blocked']='Existing independently prepared stopped Windows installation required.';save();continue
        server=ViewerServer(controller,0)
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.05},daemon=True);thread.start()
        ready=folder/(vm+'-ready.json')
        ready.write_text(json.dumps({'pid':os.getpid(),'url':server.url,'workspace':str(controller.workspace),'session':controller.session}),encoding='utf-8')
        client=ControlClient(ready_file=ready,workspace=workspace,session='desktop-app' if vm=='windows' else 'beta',exchange=folder/'exchange')
        def check(name,detail=True):
            if detail is False:raise AssertionError(name+' returned false')
            entry['checks'].append({'name':name,'detail':detail});save();print(vm+' / '+name+': passed',flush=True)
        def wait():
            for _ in range(150):
                state=client.status(vm)
                if state.get('screen_ready') or state.get('guest_ready') and state.get('desktop_ready',True):return state
                time.sleep(1)
            raise AssertionError('Guest readiness deadline')
        try:
            os_id=None
            if vm=='custom':
                if not args.iso or not args.iso.is_file():raise ValueError('--iso is required for custom acceptance')
                incoming=ROOT/'media/incoming';incoming.mkdir(parents=True,exist_ok=True)
                media=incoming/('acceptance-'+folder.name+'.iso');shutil.copy2(args.iso,media)
                result=client.request('/api/config',{'operation':'add_os','name':'Alpine acceptance','filename':media.name,'revision':0})
                os_id=result['os_id'];check('staged-os-import',{'id':os_id,'original_unchanged':digest(media)==digest(args.iso)})
                values={**defaults('custom'),'memory':768,'cpus':2,'disk_gib':4}
                client.request('/api/config',{'operation':'save','profile':'custom','os_id':os_id,'settings':values,'revision':1})
            elif vm=='linux':
                values={**defaults('desktop'),'memory':1024,'cpus':2,'width':1280,'height':720,'network':False}
                client.request('/api/config',{'operation':'save','profile':'desktop','os_id':None,'settings':values,'revision':0})
                check('saved-resource-settings',values)
            client.start(vm,os_id=os_id,network=False)
            state=wait();check('native-ready',{'memory':state.get('memory_mib'),'cpus':state.get('cpus')})
            time.sleep(12 if vm=='custom' else 1)
            data=client.screenshot(vm);(folder/(vm+'.png')).write_bytes(data)
            check('qmp-screen',list(png_dimensions(data)))
            if vm=='custom':
                self_caps=client.control('capabilities','custom');assert self_caps['commands'] is False
                try:client.action('custom','exec',command='whoami')
                except Exception as error:assert error.code=='capability_unavailable'
                else:raise AssertionError('Unprepared OS command accepted')
                client.action('custom','type',text='root\n');time.sleep(2)
                client.action('custom','type',text="printf beta1234 >/dev/sda\n");time.sleep(2)
                check('generic-screen-input-and-command-denial')
            else:
                command='[Environment]::OSVersion.VersionString' if vm=='windows' else 'uname -a; getconf _NPROCESSORS_ONLN'
                result=client.action(vm,'exec',command=command);assert result['exit_code']==0
                if vm=='linux':assert result['stdout'].strip().endswith('2'),result
                check('native-command',result)
                import subprocess
                context=['--ready-file',str(ready),'--workspace',str(workspace),'--session','desktop-app' if vm=='windows' else 'beta','--exchange',str(folder/'exchange')]
                messages=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
                    {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'vm_exec','arguments':{'vm':vm,'command':command}}}]
                child=subprocess.run([sys.executable,'-I','-B','-m','agenticvm.desktop_mcp',*context],cwd=ROOT,
                    input=''.join(json.dumps(message)+'\n' for message in messages),capture_output=True,text=True,timeout=120,creationflags=subprocess.CREATE_NO_WINDOW)
                replies=[json.loads(line) for line in child.stdout.splitlines()]
                assert child.returncode==0 and not replies[1]['result']['isError']
                assert json.loads(replies[1]['result']['content'][0]['text'])['result']['exit_code']==0
                child=subprocess.run([sys.executable,'-I','-B','-m','agenticvm.control_cli',*context,'--vm',vm,'exec',command],
                    cwd=ROOT,capture_output=True,text=True,timeout=120,creationflags=subprocess.CREATE_NO_WINDOW)
                assert child.returncode==0 and json.loads(child.stdout)['result']['exit_code']==0
                check('real-mcp-and-cli-guest-command')
                path=('C:/workspace/' if vm=='windows' else '/workspace/')+'beta-'+folder.name+'.txt'
                payload='Beta saved data 你好\n'.encode()
                client.write_file(vm,path,payload);assert client.read_file(vm,path)==payload
                check('guest-file-roundtrip')
            client.action(vm,'stop');check('clean-stop',client.status(vm)['registered'] is False)
            if vm=='custom':
                disk=Path(controller.store.load()['disk']);before=digest(disk)
                client.start(vm,os_id=os_id,network=False);wait();time.sleep(12)
                client.action(vm,'type',text='root\n');time.sleep(2)
                client.action(vm,'type',text='head -c 8 /dev/sda; echo\n');time.sleep(2)
                (folder/'custom-persistence.png').write_bytes(client.screenshot(vm))
                client.action(vm,'stop');check('persistent-system-disk-retained',{'same_path':Path(controller.store.load()['disk'])==disk,'before_sha256':before,'after_sha256':digest(disk)})
                persistent_hash=digest(disk)
                # Repeat the import under UEFI with its own empty disk, preserving BIOS evidence.
                controller.configuration.save('custom',os_id,{**values,'firmware':'uefi','persistent':False},2)
                client.start(vm,os_id=os_id,network=False);wait();time.sleep(12)
                (folder/'custom-uefi.png').write_bytes(client.screenshot(vm));client.action(vm,'stop')
                assert digest(disk)==persistent_hash
                check('uefi-and-temporary-disk-isolation',{'temporary_disk':controller.store.load()['disk'],'persistent_unchanged':digest(disk)==persistent_hash})
            else:
                client.start(vm,network=False);wait();assert client.read_file(vm,path)==payload
                client.action(vm,'stop');check('cold-boot-persistence')
            entry['ok']=True
        except Exception as error:
            entry['error']={'type':type(error).__name__,'code':getattr(error,'code',None),'message':str(error)}
            print(vm+' / failed: '+str(error),flush=True)
        finally:
            try:
                if controller.store.load(required=False) and controller.store.load().get('registered'):client.action(vm,'stop')
            except Exception as error:entry['cleanup_error']=str(error)
            server.shutdown();server.server_close();thread.join(2);save()
    report['source_unchanged']=report['source_pins']==pins()
    report['ok']=all(item['ok'] for item in report['profiles'].values()) and report['source_unchanged']
    report['finished_at']=time.time();save()
    print(json.dumps({'ok':report['ok'],'receipt':str(folder/'report.json')}))
    return 0 if report['ok'] else 1


if __name__=='__main__':raise SystemExit(main())
