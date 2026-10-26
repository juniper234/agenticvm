"""Direct agent CLI for all three desktop guests. Output is one JSON envelope."""
import argparse
import json
from pathlib import Path
import sys

from .control_client import ControlClient, DEFAULT_DATA


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ready-file', type=Path, default=DEFAULT_DATA/'viewer-ready.json')
    parser.add_argument('--workspace', type=Path, default=DEFAULT_DATA/'workspace')
    parser.add_argument('--exchange', type=Path, default=DEFAULT_DATA/'exchange')
    parser.add_argument('--session', default='desktop-app')
    parser.add_argument('--target-session',default=None,help='Owned session ID (main or a managed name)')
    parser.add_argument('--lease',default=None,help='Current operator lease token')
    parser.add_argument('--generation',default=None,help='Observed VM generation')
    parser.add_argument('--vm', choices=['linux', 'android', 'windows', 'custom'])
    commands = parser.add_subparsers(dest='operation', required=True)
    commands.add_parser('status')
    commands.add_parser('health')
    commands.add_parser('capabilities')
    commands.add_parser('sessions')
    transaction=commands.add_parser('transaction')
    transaction.add_argument('command'); transaction.add_argument('verify_command'); transaction.add_argument('recovery_command')
    create=commands.add_parser('session-create')
    create.add_argument('name'); create.add_argument('guest',choices=['linux','android'])
    create.add_argument('--disposable',action='store_true')
    acquire=commands.add_parser('lease-acquire')
    acquire.add_argument('owner'); acquire.add_argument('--seconds',type=int,default=120); acquire.add_argument('--token')
    commands.add_parser('lease-release')
    job=commands.add_parser('job-start'); job.add_argument('command'); job.add_argument('--seconds',type=int,default=120)
    for name in ('job-status','job-cancel','job-forget','job-output'):
        job=commands.add_parser(name); job.add_argument('job')
        if name=='job-output':
            job.add_argument('--stream',choices=['stdout','stderr'],default='stdout'); job.add_argument('--cursor',type=int,default=0); job.add_argument('--limit',type=int,default=16384)
    checkpoint=commands.add_parser('checkpoint-create'); checkpoint.add_argument('--label',default='checkpoint')
    commands.add_parser('checkpoint-list')
    commands.add_parser('checkpoint-plan').add_argument('checkpoint')
    restore=commands.add_parser('checkpoint-restore'); restore.add_argument('plan_id'); restore.add_argument('manifest_sha256')
    sync=commands.add_parser('sync-create'); sync.add_argument('name'); sync.add_argument('exchange_path'); sync.add_argument('guest_path')
    commands.add_parser('sync-status').add_argument('name')
    sync=commands.add_parser('sync-apply'); sync.add_argument('name'); sync.add_argument('revision',type=int)
    sync.add_argument('--direction',choices=['auto','push','pull','keep-host','keep-guest','keep-both'],default='auto')
    sync.add_argument('--host-hash'); sync.add_argument('--guest-hash')
    logs=commands.add_parser('logs')
    logs.add_argument('kind')
    logs.add_argument('--cursor',type=int,default=0)
    logs.add_argument('--limit',type=int,default=16384)
    wait=commands.add_parser('wait')
    wait.add_argument('--condition',choices=['guest','desktop','stopped'],default='guest')
    wait.add_argument('--timeout',type=int,default=60)
    commands.add_parser('serve', help='Run the VM service without opening the interface')
    start = commands.add_parser('start')
    start.add_argument('--memory', type=int)
    start.add_argument('--network', action=argparse.BooleanOptionalAction, default=None)
    start.add_argument('--cpus', type=int)
    start.add_argument('--os-id')
    commands.add_parser('settings', help='Read saved settings and OS library')
    configure=commands.add_parser('settings-save', help='Save complete next-start settings from a JSON file')
    configure.add_argument('file',type=Path); configure.add_argument('--revision',type=int,required=True); configure.add_argument('--os-id')
    media=commands.add_parser('os-add', help='Register one staged media/incoming file')
    media.add_argument('name'); media.add_argument('filename'); media.add_argument('--revision',type=int,required=True)
    commands.add_parser('stop')
    commands.add_parser('restart')
    commands.add_parser('screenshot').add_argument('exchange_path')
    commands.add_parser('exec').add_argument('command')
    commands.add_parser('type').add_argument('text')
    commands.add_parser('key').add_argument('keys')
    commands.add_parser('scroll').add_argument('steps', type=int)
    for name in ('click', 'move'):
        command = commands.add_parser(name)
        command.add_argument('x', type=int)
        command.add_argument('y', type=int)
    for name in ('read', 'write'):
        command = commands.add_parser(name)
        command.add_argument('path')
        if name == 'write':
            command.add_argument('text')
    for name in ('import', 'export'):
        command = commands.add_parser(name)
        command.add_argument('exchange_path')
        command.add_argument('guest_path')
    args = parser.parse_args(argv)
    if args.operation == 'serve':
        from .viewer import main as serve
        from .control_client import ROOT
        import os
        os.environ.setdefault('AGENTICVM_SOCKET_ROOT', str(ROOT/'runtime/ipc'))
        try:
            existing = ControlClient(ready_file=args.ready_file, workspace=args.workspace, exchange=args.exchange, session=args.session).request('/api/info')
            if Path(existing['workspace']).resolve() == args.workspace.resolve():
                print(json.dumps({'ok': True, 'result': {'status': 'already-listening'}}))
                return 0
        except (OSError, ValueError, KeyError):
            pass
        return serve(['--workspace', str(args.workspace), '--session', args.session, '--port', '0', '--ready-file', str(args.ready_file), '--quiet-launch'])
    client = ControlClient(ready_file=args.ready_file, workspace=args.workspace, exchange=args.exchange, session=args.session)
    if args.target_session is not None or args.lease is not None:
        client=client.bound(args.target_session or 'main',args.lease,args.generation)
    try:
        operation = args.operation
        if operation == 'settings':
            result=client.request('/api/config')
        elif operation == 'settings-save':
            from .control_client import PROFILES
            if args.vm not in PROFILES:
                raise ValueError('--vm is required for settings-save')
            if args.file.stat().st_size > 65536:
                raise ValueError('Settings file exceeds 64 KiB')
            result=client.request('/api/config',{'operation':'save','profile':PROFILES[args.vm], 'os_id':args.os_id,
                'settings':json.loads(args.file.read_text(encoding='utf-8')), 'revision':args.revision})
        elif operation == 'os-add':
            result=client.request('/api/config',{'operation':'add_os','name':args.name,'filename':args.filename,'revision':args.revision}, timeout=1800)
        elif operation.startswith(('job-','checkpoint-','sync-','lease-')) or operation in {'sessions','session-create','transaction'}:
            from .control_plane import OPERATIONS
            name=operation.replace('-','_')
            result=client.control(name,args.vm,**{key:getattr(args,key) for key in OPERATIONS[name] if hasattr(args,key) and getattr(args,key) is not None})
        elif operation == 'status':
            result = client.status(args.vm)
        elif operation in {'health','capabilities'}:
            result=client.control(operation,args.vm)
        elif operation=='logs':
            result=client.control('logs',args.vm,kind=args.kind,cursor=args.cursor,limit=args.limit)
        elif operation=='wait':
            result=client.wait(args.vm,args.condition,args.timeout)
        else:
            if not args.vm:
                raise ValueError('--vm is required for guest actions')
            if operation == 'start':
                result = client.start(args.vm, memory=args.memory, network=args.network, cpus=args.cpus, os_id=args.os_id)
            elif operation == 'screenshot':
                result = client.save_screenshot(args.vm, args.exchange_path)
            elif operation in {'stop', 'restart'}:
                result = client.action(args.vm, 'reset' if operation == 'restart' else operation)
            elif operation in {'type', 'key', 'exec', 'scroll'}:
                field = {'type':'text', 'key':'keys', 'exec':'command', 'scroll':'steps'}[operation]
                result = client.action(args.vm, operation, **{field:getattr(args, field)})
            elif operation in {'click', 'move'}:
                result = client.action(args.vm, operation, x=args.x, y=args.y)
            elif operation == 'write':
                result = client.write_file(args.vm, args.path, args.text.encode('utf-8'))
            elif operation == 'read':
                data = client.read_file(args.vm, args.path)
                result = {'path':args.path, 'text':data.decode('utf-8'), 'bytes':len(data)}
            elif operation == 'import':
                result = client.import_file(args.vm, args.exchange_path, args.guest_path)
            else:
                result = client.export_file(args.vm, args.guest_path, args.exchange_path)
        print(json.dumps({'ok':True,'result':result}, ensure_ascii=True))
        return 0
    except Exception as error:
        print(json.dumps({'ok':False,'error':{'code':getattr(error,'code','control_error'),'message':str(error)}}, ensure_ascii=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
