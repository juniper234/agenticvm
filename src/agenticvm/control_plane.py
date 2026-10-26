"""Typed session control shared by CLI and MCP. Never exposes a host shell."""
import base64

from . import control_diagnostics as diagnostics
from .control_store import fail
from .control_sessions import Sessions,Lease
from .control_jobs import Jobs
from .control_sync import Sync
from .control_checkpoints import Checkpoints

OPERATIONS={
    'health':set(),'capabilities':set(),'logs':{'kind','cursor','limit'},'probe':{'condition'},'status':set(),
    'sessions':set(),'session_create':{'name','guest','disposable'},
    'lease_acquire':{'owner','seconds','token'},'lease_release':set(),
    'action':{'action','command','profile','memory','network','persistent','os_id','cpus','width','height','x','y','button','text','keys','steps','url','path','data_b64','x1','x2','y1','y2'},
    'read':{'path'},'screen':set(),
    'job_start':{'command','seconds'},'job_status':{'job'},'job_output':{'job','stream','cursor','limit'},'job_cancel':{'job'},'job_forget':{'job'},
    'checkpoint_create':{'label'},'checkpoint_list':set(),'checkpoint_plan':{'checkpoint'},'checkpoint_restore':{'plan_id','manifest_sha256'},
    'sync_create':{'name','exchange_path','guest_path'},'sync_status':{'name'},'sync_apply':{'name','revision','direction','host_hash','guest_hash'},
    'transaction':{'command','verify_command','recovery_command'},
}
READ_ONLY={'health','capabilities','logs','probe','status','sessions','read','screen','job_status','job_output','checkpoint_list','sync_status'}
ACTION_FIELDS={
    'start':{'memory','network','persistent','os_id','cpus','width','height'},'stop':set(),'reset':set(),
    'exec':{'command'},'upload':{'path','data_b64'},'click':{'x','y','button'},'move':{'x','y'},
    'key':{'keys'},'type':{'text'},'scroll':{'steps'},'open-url':{'url'},'swipe':{'x1','x2','y1','y2'},
}
REQUIRED={
    'logs':{'kind'},'probe':{'condition'},'session_create':{'name','guest'},'lease_acquire':{'owner'},'action':{'action'},'read':{'path'},
    'job_start':{'command'},'job_status':{'job'},'job_output':{'job'},'job_cancel':{'job'},'job_forget':{'job'},
    'checkpoint_plan':{'checkpoint'},'checkpoint_restore':{'plan_id','manifest_sha256'},'sync_create':{'name','exchange_path','guest_path'},
    'sync_status':{'name'},'sync_apply':{'name','revision'},'transaction':{'command','verify_command','recovery_command'},
}


class ControlPlane:
    def __init__(self, controller):
        self.controller=controller
        self.sessions=Sessions(controller)
        self.exchange=controller.workspace.parent/'exchange'

    def dispatch(self, request):
        if not isinstance(request,dict):
            fail('Expected a control request.','invalid_request')
        operation=request.get('operation')
        if operation not in OPERATIONS or set(request)-({'operation','vm','session','lease','generation'}|OPERATIONS[operation]):
            fail('Unknown control operation or argument.','invalid_request')
        if REQUIRED.get(operation,set())-set(request):
            fail('Required control arguments are missing.','invalid_request')
        session=request.get('session','main')
        if operation in {'sessions','session_create'}:
            if session!='main':
                fail('Use the main registry for session management.','invalid_session')
            if operation=='sessions':
                result=self.sessions.inventory()
            else:
                result=self.sessions.create(request.get('name'),request.get('guest'),request.get('disposable',False))
            return {'ok':True,'result':result}
        controller=self.sessions.resolve(session)
        if not controller.lock.acquire(blocking=False):
            fail('A desktop action is still running.','session_busy')
        try:
            vm=request.get('vm')
            if vm is not None and vm!=diagnostics.PROFILES[controller.profile]:
                fail('The selected VM changed. Observe it before acting.','target_changed')
            if operation not in READ_ONLY|{'lease_acquire'} and vm is None:
                fail('An explicit guest OS is required for mutations.','invalid_request')
            if operation not in READ_ONLY|{'lease_acquire'}:
                Lease(controller).require(request.get('lease'),request.get('generation'))
            arguments={key:request[key] for key in OPERATIONS[operation] if key in request}
            if controller.profile == 'custom' and operation not in {'health','capabilities','logs','probe','status','lease_acquire','lease_release','action','screen'}:
                fail('This imported OS supports screen and keyboard control; compatible guest tools are required for this operation.', 'capability_unavailable')
            if operation=='health':
                result=diagnostics.health(controller)
            elif operation=='capabilities':
                result=diagnostics.capabilities(controller)
                from .control_store import load_json,digest
                android_runner=controller.root/'tools/android/jobs/runner.jar'
                job_ready=controller.profile!='android' or (android_runner.is_file() and digest(android_runner)==load_json(android_runner.parent/'receipt.json',default={}).get('sha256'))
                result.update(jobs=job_ready and controller.profile!='custom',checkpoints=controller.profile!='custom',sync=controller.profile!='custom',sessions=True,
                    jobs_limit=2,job_output_bytes=65536,lease_seconds_max=300,session_id=session,
                    checkpoint_scope='complete-system-disk' if controller.profile=='windows' else 'persistent-data-and-keys' if controller.profile=='android' else 'workspace-only',
                    extra_windows_sessions=False)
            elif operation=='logs':
                result=diagnostics.logs(controller,**arguments)
            elif operation=='probe':
                result=diagnostics.probe(controller,**arguments)
            elif operation=='status':
                result=diagnostics.observe(controller)
            elif operation=='lease_acquire':
                result=Lease(controller).acquire(**arguments)
            elif operation=='lease_release':
                result=Lease(controller).release(request.get('lease'),request.get('generation'))
            elif operation=='action':
                action=arguments.get('action')
                if action not in ACTION_FIELDS or set(arguments)-({'action'}|ACTION_FIELDS[action]):
                    fail('Unknown action or argument for this guest.','invalid_request')
                result=diagnostics.unwrap(controller.action(arguments))
                result['generation']=diagnostics.generation(controller)
            elif operation=='read':
                data=controller.download(arguments.get('path'))[0]
                result={'data_b64':base64.b64encode(data).decode(),'bytes':len(data)}
            elif operation=='screen':
                data=controller.screen()
                result={'data_b64':base64.b64encode(data).decode(),'mime_type':'image/png'}
            elif operation.startswith('job_'):
                result=getattr(Jobs(controller),operation[4:])(**arguments)
            elif operation.startswith('checkpoint_'):
                method={'list':'listing'}.get(operation[11:],operation[11:])
                result=getattr(Checkpoints(controller),method)(**arguments)
            elif operation=='transaction':
                if session=='main' or not self.sessions.records().get(session,{}).get('disposable'):
                    fail('Automatic rollback requires a managed session created as disposable.','rollback_policy_required')
                from .control_transaction import Transaction
                result=Transaction(controller).run(**arguments)
            else:
                method={'status':'inspect'}.get(operation[5:],operation[5:])
                result=getattr(Sync(controller,self.exchange),method)(**arguments)
            return {'ok':True,'result':result}
        finally:
            controller.lock.release()
