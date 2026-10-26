"""Sequential native acceptance through CLI/MCP's common control service.

No host desktop automation, no mocked guests, no simultaneous VM starts.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.control_client import ControlClient, PROFILES
from agenticvm.desktop import png_dimensions


def pins():
    files = [ROOT/'src/agenticvm'/name for name in ('viewer.py','windows_desktop.py','qemu.py','state.py','desktop.py','android.py','control_client.py','control_cli.py','desktop_mcp.py')]
    files += [ROOT/'scripts/windows-desktop-supervisor.py',ROOT/'guest/windows_desktop_agent.py']
    files += list((ROOT/'src/agenticvm/web').glob('*.*'))
    return {str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profiles',nargs='+',choices=list(PROFILES),default=['windows','linux','android'])
    args = parser.parse_args()
    folder = ROOT/'runtime/glass-acceptance'/str(uuid4())
    folder.mkdir(parents=True)
    client = ControlClient()
    report = {'schema':'agenticvm.native-desktop-acceptance.v1','started_at':time.time(),'source_pins':pins(),
        'computer_use':False,'mocked_guests':False,'sequential':True,'profiles':{},'ok':False}
    receipt = folder/'report.json'

    def save():
        receipt.write_text(json.dumps(report,indent=2),encoding='utf-8')

    def ready(vm, timeout=360, different_pid=None):
        deadline = time.monotonic()+timeout
        while time.monotonic()<deadline:
            assert pins()==report['source_pins'],'Runtime source changed during native acceptance'
            state = client.status(vm)
            if state.get('guest_ready') is True and state.get('desktop_ready') is not False and (different_pid is None or state.get('pid') != different_pid):
                return state
            time.sleep(2)
        raise TimeoutError(vm+' did not reach a ready desktop')

    def mcp(vm):
        text = 'MCP '+vm+' — 你好\n'
        guest_path = ('C:/workspace/' if vm=='windows' else '/workspace/')+'mcp-check.txt'
        transfer_path = ('C:/workspace/' if vm=='windows' else '/workspace/')+'mcp-transfer.bin'
        relative = folder.name+'/'+vm
        source = client.exchange/(relative+'-input.bin')
        source.parent.mkdir(parents=True,exist_ok=True)
        transfer = bytes(range(256))*4096
        source.write_bytes(transfer)
        calls = [('vm_status',{'vm':vm}),('vm_exec',{'vm':vm,'command':'whoami'}),
            ('vm_write_file',{'vm':vm,'path':guest_path,'text':text}),('vm_read_file',{'vm':vm,'path':guest_path}),
            ('vm_screenshot',{'vm':vm}),
            ('vm_import_file',{'vm':vm,'exchange_path':relative+'-input.bin','guest_path':transfer_path}),
            ('vm_export_file',{'vm':vm,'guest_path':transfer_path,'exchange_path':relative+'-output.bin'})]
        requests = [{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
            {'jsonrpc':'2.0','method':'notifications/initialized'}]
        requests += [{'jsonrpc':'2.0','id':i+2,'method':'tools/call','params':{'name':name,'arguments':values}} for i,(name,values) in enumerate(calls)]
        child = subprocess.run([sys.executable,'-I','-B','-m','agenticvm.desktop_mcp'],cwd=ROOT,
            input=''.join(json.dumps(item)+'\n' for item in requests).encode(),capture_output=True,timeout=600)
        assert child.returncode==0,child.stderr.decode('utf-8','replace')
        replies = [json.loads(line) for line in child.stdout.splitlines()]
        assert len(replies)==8
        for response in replies[1:]:
            assert not response.get('error') and response['result'].get('isError') is False,str(response)[:1200]
        read = json.loads(replies[4]['result']['content'][0]['text'])['result']
        assert read['text']==text
        image = replies[5]['result']['content'][0]
        assert image['type']=='image' and image['mimeType']=='image/png'
        data = base64.b64decode(image['data'],validate=True)
        width,height=png_dimensions(data)
        (folder/(vm+'-mcp.png')).write_bytes(data)
        assert (client.exchange/(relative+'-output.bin')).read_bytes()==transfer
        return {'stdio_process':True,'calls':[name for name,_ in calls],'utf8_roundtrip':True,
            'exchange_binary_roundtrip_bytes':len(transfer),'image':[width,height]}

    save()
    print('Receipt: '+str(receipt),flush=True)
    try:
        for vm in args.profiles:
            entry = report['profiles'][vm]={'checks':[],'ok':False}
            def check(name,result=True):
                entry['checks'].append({'check':name,'result':result,'at':time.time()})
                save()
                print(vm+' / '+name+': passed',flush=True)
            try:
                current=client.status()
                assert not current.get('registered'),'A guest is already running; do not interrupt it'
                memory={'linux':768,'android':2560,'windows':2048}[vm]
                client.start(vm,memory=memory,network=False,persistent=True)
                state=ready(vm)
                if vm=='windows':
                    assert state.get('guest_agent')==2 and state.get('serial_baud')==115200,'Update the installed guest tools before acceptance'
                check('native-ready',state)
                data=client.screenshot(vm)
                width,height=png_dimensions(data)
                (folder/(vm+'-display.png')).write_bytes(data)
                check('native-png',{'width':width,'height':height,'sha256':hashlib.sha256(data).hexdigest()})
                command='$env:OS; [Environment]::OSVersion.VersionString' if vm=='windows' else 'uname -a; id'
                result=client.action(vm,'exec',command=command)
                assert result['exit_code']==0 and result['stdout'].strip()
                check('native-command',result)
                content=('AgenticVM '+vm+' — persistence 你好\n').encode('utf-8')
                path=('C:/workspace/' if vm=='windows' else '/workspace/')+'native-check.txt'
                client.write_file(vm,path,content)
                assert client.read_file(vm,path)==content
                check('native-file-roundtrip',{'bytes':len(content)})
                check('mcp-through-real-stdio',mcp(vm))
                result=subprocess.run([sys.executable,'-I','-B','-m','agenticvm.control_cli','--vm',vm,'exec',command],
                    capture_output=True,cwd=ROOT,timeout=60)
                envelope=json.loads(result.stdout)
                assert result.returncode==0 and envelope['ok'] and envelope['result']['exit_code']==0
                check('cli-through-real-process',True)
                if vm=='android':
                    client.action(vm,'key',keys='home')
                    client.action(vm,'swipe',x1=360,y1=1000,x2=360,y2=300)
                else:
                    client.action(vm,'move',x=80,y=700)
                    client.action(vm,'key',keys='escape')
                check('native-input-dispatched',True)
                client.action(vm,'reset')
                state=ready(vm)
                assert client.read_file(vm,path)==content
                check('cold-restart-and-persistence',state)
                if vm=='windows':
                    old=state['pid']
                    result=client.action(vm,'exec',command='shutdown.exe /r /t 2')
                    assert result['exit_code']==0
                    restarted=ready(vm,different_pid=old)
                    assert client.read_file(vm,path)==content
                    check('guest-requested-reboot-supervised',restarted)
                entry['ok']=True
            finally:
                current=client.status()
                if current.get('profile')==PROFILES[vm] and current.get('registered'):
                    client.action(vm,'stop')
                stopped=client.status(vm)
                assert stopped.get('registered') is False
                check('clean-stop',stopped)
                save()
        assert pins()==report['source_pins']
        report['ok']=True
    except Exception as error:
        report['error']=str(error)
        raise
    finally:
        report['finished_at']=time.time()
        save()
        print('Result: '+str(report['ok'])+' / '+str(receipt),flush=True)


if __name__=='__main__':
    main()
