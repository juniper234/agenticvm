"""Explicit disposable-session checkpoint -> task -> verify -> recover workflow."""
import time
from uuid import uuid4

from .control_checkpoints import Checkpoints
from .control_diagnostics import observe,unwrap
from .control_guest import Guest
from .control_store import Metadata,fail,save_json


class Transaction:
    def __init__(self,controller):
        self.controller=controller
        self.guest=Guest(controller)
        self.meta=Metadata(controller.workspace/'control'/('profile-'+controller.profile)/'transactions')

    def run(self,command,verify_command,recovery_command):
        for value in (command,verify_command,recovery_command):
            if not isinstance(value,str) or not 1<=len(value.encode('utf-8'))<=8192 or '\x00' in value:
                fail('Supply bounded guest task, verification and recovery commands.','invalid_transaction')
        identifier=uuid4().hex
        record={'id':identifier,'ok':False,'phases':[],'task_error':None,'recovery_error':None,'checkpoint':None}
        def phase(name,result=None):
            record['phases'].append({'phase':name,'at':time.time(),'result':result})
            save_json(self.meta.path(identifier+'.json'),record)
        def stop():
            if observe(self.controller).get('registered'):
                unwrap(self.controller.action({'action':'stop'}))
        def boot():
            unwrap(self.controller.action({'action':'start','network':False,'persistent':True}))
            deadline=time.monotonic()+120
            while time.monotonic()<deadline:
                if observe(self.controller).get('guest_ready'):return
                time.sleep(.5)
            fail('Guest did not become ready.','guest_timeout')
        def check(value):
            result=self.guest.execute(value)
            if result.get('exit_code')!=0:
                fail('Guest command returned '+str(result.get('exit_code'))+': '+result.get('stderr','')[:1024],'transaction_command_failed')
            return result
        phase('begin')
        try:
            stop(); phase('stopped')
            checkpoint=Checkpoints(self.controller).create('transaction-'+identifier[:8])
            record['checkpoint']=checkpoint['id']; phase('checkpoint-committed',checkpoint['id'])
            boot(); phase('task-booted')
            result=check(command); phase('task-executed',result)
            phase('task-verified',check(verify_command))
            stop(); boot(); phase('cold-verified',check(verify_command)); stop()
            record['ok']=True; phase('retained')
        except Exception as error:
            record['task_error']={'code':getattr(error,'code','transaction_error'),'message':str(error)[:2048]}; phase('task-failed')
            if record['checkpoint'] is not None:
                try:
                    stop(); checkpoints=Checkpoints(self.controller)
                    plan=checkpoints.plan(record['checkpoint']); phase('recovery-planned')
                    restored=checkpoints.restore(plan['plan_id'],plan['manifest_sha256']); phase('restored',restored)
                    boot(); phase('recovery-cold-verified',check(recovery_command)); stop()
                    record['recovered']=True; phase('recovered')
                except Exception as recovery:
                    record['recovery_error']={'code':getattr(recovery,'code','recovery_error'),'message':str(recovery)[:2048]}
                    phase('recovery-failed')
            try:stop()
            except Exception as cleanup:
                record['cleanup_error']={'code':getattr(cleanup,'code','cleanup_error'),'message':str(cleanup)[:512]}; phase('cleanup-failed')
        return record
