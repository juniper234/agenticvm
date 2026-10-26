"""Exercise the relocated headless launcher and real stdio MCP without a VM."""
from pathlib import Path
import argparse
import json
import os
import subprocess
import sys
import time


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--home',type=Path,required=True);args=parser.parse_args()
    home=args.home.resolve();python=home/'tools/python-runtime/3.13.16/python.exe'
    environment={**os.environ,'AGENTICVM_HOME':str(home),'AGENTICVM_SOCKET_ROOT':str(home/'runtime/ipc')}
    sys.path.insert(0,str(home/'src'))
    from agenticvm.control_client import ControlClient
    from agenticvm.qemu import WindowsProcess
    ready=home/'runtime/glass-app/viewer-ready.json'
    if ready.exists():raise ValueError('Use a fresh test service scope; do not interrupt an existing listener')
    started=time.time()
    child=subprocess.run([str(python),'-I','-B',str(home/'scripts/start-control-service.py')],cwd=home.parent,
        env=environment,capture_output=True,text=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
    launch=json.loads(child.stdout)
    assert child.returncode==0 and launch['ok'] and launch['result']['reused'] is False
    pid=launch['result']['pid'];client=ControlClient(ready_file=ready,workspace=home/'runtime/glass-app/workspace',exchange=home/'runtime/glass-app/exchange')
    report={'ok':False,'home':str(home),'pid':pid,'service_auto_started_guest':None}
    folder=home/'runtime/beta-service-verification';folder.mkdir(parents=True)
    with WindowsProcess(pid,terminate=True) as process:
        assert process.alive() and process.executable==python.resolve()
        created=int(process.created)/10**7-11644473600
        assert started-2<=created<=time.time()+2
        report['process_created']=process.created
        try:
            info=client.request('/api/info');assert info['version']=='0.4.0-beta.1'
            status=client.status();assert status['registered'] is False
            report['service_auto_started_guest']=False
            reuse=subprocess.run([str(python),'-I','-B',str(home/'scripts/start-control-service.py')],cwd=home.parent,
                env=environment,capture_output=True,text=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
            assert json.loads(reuse.stdout)['result']['reused'] is True
            messages=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
                {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}}]
            messages += [{'jsonrpc':'2.0','id':i+3,'method':'tools/call','params':{'name':name,'arguments':{}}}
                         for i,name in enumerate(['vm_settings','vm_status','vm_capabilities'])]
            child=subprocess.run([str(python),'-I','-B','-m','agenticvm.desktop_mcp'],cwd=home.parent,env=environment,
                input=''.join(json.dumps(row)+'\n' for row in messages),capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
            replies=[json.loads(row) for row in child.stdout.splitlines()]
            assert child.returncode==0 and len(replies)==5 and len(replies[1]['result']['tools'])==41
            assert all(row['result'].get('isError') is False for row in replies[2:])
            child=subprocess.run([str(python),'-I','-B',str(home/'scripts/configure-agent-bridge.py')],cwd=home.parent,env=environment,
                capture_output=True,text=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
            config=json.loads((home/'mcp.beta.json').read_text(encoding='utf-8'))
            assert child.returncode==0 and Path(config['mcpServers']['agenticvm-desktop']['command'])==python
            report.update(ok=True,launcher_start_and_reuse=True,stdio_mcp_tools=41,real_read_tools=3,relocated_config=True,
                global_harness_changed=False,tokens_printed=False)
        finally:
            assert not client.status().get('registered')
            process.terminate();assert process.wait(10)
            report['owned_service_stopped']=True
            (folder/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'ok':report['ok'],'receipt':str(folder/'report.json'),'mcp_tools':41,'owned_service_stopped':True}))
    return 0 if report['ok'] else 1


if __name__=='__main__':raise SystemExit(main())
