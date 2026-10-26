"""Consolidate only passing, current-source host and native control receipts."""
from pathlib import Path
import argparse,hashlib,json,sys,time,os

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.control_client import ControlClient
from agenticvm.control_store import checked,save_json
from agenticvm.desktop_mcp import TOOLS


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--host',type=Path,required=True)
    parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--sessions',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'docs/validation/agent-control-checkpoint.json')
    args=parser.parse_args()
    report={'schema':'agenticvm.agent-control-checkpoint.v1','at':time.time(),'ok':False,
        'computer_use':False,'minimum_4gb_host':'not_benchmarked','source_drift':[]}
    try:
        receipts={name:json.loads(getattr(args,name).read_text(encoding='utf-8')) for name in ('host','native','sessions')}
        for name,receipt in receipts.items():
            assert receipt.get('ok') is True and receipt.get('source_unchanged') is True,name+' receipt failed'
            for relative,pin in receipt['source_pins'].items():
                path=ROOT/relative
                if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=pin:
                    report['source_drift'].append({'receipt':name,'path':relative})
        assert not report['source_drift'],'Contributing receipts do not match current source'
        host,native,sessions=(receipts[name] for name in ('host','native','sessions'))
        assert not any(host.get(name) for name in ('failures','errors','skipped'))
        assert set(native['profiles'])=={'linux','android','windows'}
        required={'native-ready','health-capabilities-bounded-logs','durable-job-exit-truncation-cursors-reconnect',
            'cancellation-stops-descendant-processes','job-deadline','finished-job-forget-reclaims-own-output',
            'binary-sync-and-both-changed-conflict','real-stdio-mcp-and-cli','cold-checkpoint-rescue-restore-and-boot-canary','clean-stop'}
        for vm,entry in native['profiles'].items():
            assert entry['ok'] and required<={item['name'] for item in entry['checks']},vm+' lacks required native checks'
        assert {'two-concurrent-independent-linux-guests','separate-files-and-foreign-lease-generation-denials',
            'expired-lease-cannot-type','independent-jobs-and-foreign-job-denial',
            'failed-task-restored-and-cold-verified','successful-task-retained-and-cold-verified'}<={item['name'] for item in sessions['checks']}
        client=ControlClient(); stopped={}
        inventory=client.control('sessions')['sessions']
        for entry in inventory:
            state=client.bound(entry['session']).status(entry['vm'])
            assert not state.get('registered'),entry['session']+' is still registered/running'
            stopped[entry['session']]={'vm':entry['vm'],'registered':False,'status':state['status']}
        # Inspect every saved profile, including the main selector's currently
        # hidden Linux/Android/Windows states. Never stop anything in this audit.
        os.environ['AGENTICVM_SOCKET_ROOT']=str(ROOT/'runtime/ipc')
        from agenticvm.android import AndroidStore
        from agenticvm.windows_desktop import WindowsDesktopStore
        from agenticvm.qemu import WindowsProcess
        roots=[client.workspace,*[checked(client.workspace/'control/sessions'/entry['session']/'workspace',client.workspace)
            for entry in inventory if entry['session']!='main']]
        saved_states=[]
        for workspace in roots:
            for path in (workspace/'sessions').glob('*.json'):
                checked(path,workspace)
                raw=json.loads(path.read_text(encoding='utf-8'))
                store=(WindowsDesktopStore if raw.get('backend')=='windows' else AndroidStore)(workspace,path.stem)
                state=store.load(); assert state['registered'] is False,'Saved profile is still registered: '+str(path)
                pins=([{'pid':state.get('pid'),'created':state.get('process_created'),'executable':state.get('executable')}]
                    if state.get('backend')!='android' else [*state.get('processes',[]),state.get('launcher',{})])
                for pin in pins:
                    if pin.get('pid'):
                        with WindowsProcess(pin['pid']) as process:
                            assert not (process.alive() and process.created==pin.get('created') and process.executable==Path(pin['executable']).resolve()),'An owned guest process is still alive'
                saved_states.append({'session':state['session'],'backend':state['backend'],'registered':False,'owned_processes_alive':0})
        report.update(ok=True,host_tests=host['tests'],mcp_tools=len(TOOLS),
            native_checks={vm:len(value['checks']) for vm,value in native['profiles'].items()},
            session_checks=len(sessions['checks']),receipts={name:str(getattr(args,name).resolve().relative_to(ROOT)) for name in receipts},
            owned_sessions=stopped,saved_profiles=saved_states,source_pins=native['source_pins'],
            limits=['4 GB physical-host performance remains unverified.',
                'Linux checkpoint restores workspace, not its temporary system overlay.',
                'Unix cancellation covers the reserved process group; deliberately detached sessions are outside it.',
                'Sync is optimistic against external editors.',
                'Additional Windows installations require independently prepared identity/account.',
                'Latest UI visual review remains outside scope after Computer Use ended.'])
    except Exception as error:
        report['error']={'type':type(error).__name__,'message':str(error)}
    report['audit_script_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    save_json(args.output,report)
    print(json.dumps({key:value for key,value in report.items() if key not in {'source_pins','owned_sessions','limits'}}))
    return 0 if report['ok'] else 1


if __name__=='__main__':raise SystemExit(main())
