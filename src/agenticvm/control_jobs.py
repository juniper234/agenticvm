"""Durable bounded guest jobs. Cancellation is a per-job mailbox, never a PID."""
import base64
import json
import re
import shlex
import time
from uuid import uuid4

from .control_diagnostics import generation,PROFILES
from .control_guest import Guest
from .control_store import Metadata,digest,fail,load_json,save_json

FINAL={'completed','cancelled','timed_out','failed','stale'}


class Jobs:
    def __init__(self,controller):
        self.controller=controller
        self.guest=Guest(controller)
        self.meta=Metadata(controller.workspace/'control'/('profile-'+controller.profile)/'jobs')

    def record(self,job):
        if not isinstance(job,str) or re.fullmatch('[0-9a-f]{32}',job) is None:
            fail('Choose a registered job ID.','invalid_job')
        record=load_json(self.meta.path(job+'.json'))
        if not isinstance(record,dict) or record.get('id')!=job or record.get('vm')!=PROFILES[self.controller.profile]:
            fail('Unknown job in this session.','invalid_job')
        expected=self.guest.root+'/.agenticvm/jobs/'+job
        if record.get('folder')!=expected:
            fail('Job metadata paths changed.','invalid_state')
        return record

    def start(self,command,seconds=120):
        if not isinstance(command,str) or not 1<=len(command.encode('utf-8'))<=8192 or '\x00' in command or type(seconds) is not int or not 1<=seconds<=300:
            fail('Use a command up to 8 KiB and a deadline of 1-300 seconds.','invalid_job')
        current=generation(self.controller)
        if current is None:
            fail('Start the guest before creating a job.','vm_not_running')
        with self.meta.lock():
            records=list(self.meta.root.glob('*.json')) if self.meta.root.exists() else []
            if len(records)>=32:
                fail('Forget finished jobs before creating more than 32.','job_limit')
            active=0
            for path in records:
                stored=self.record(path.stem)
                prior=stored if stored.get('state') in FINAL or stored.get('generation')!=current else self.status(path.stem)
                if stored.get('generation')!=current:
                    prior={**stored,'state':'stale'}
                active+=prior['state'] not in FINAL
            if active>=2:
                fail('At most two jobs may run in one session.','job_limit')
            job=uuid4().hex; folder=self.guest.root+'/.agenticvm/jobs/'+job
            record={'id':job,'vm':PROFILES[self.controller.profile],'generation':current,'folder':folder,
                'state':'launch_unknown','created_at':time.time(),'seconds':seconds,'boot_id':self.guest.boot_id()}
            # Persist intent before guest launch. No automatic command retry.
            save_json(self.meta.path(job+'.json'),record)
            self.guest.write(folder+'/request.json',json.dumps({'id':job,'command':command,'seconds':seconds}).encode())
            if self.controller.profile=='android':
                runner=self.controller.root/'tools/android/jobs/runner.jar'
                receipt=load_json(runner.parent/'receipt.json',default={})
                if not runner.is_file() or digest(runner)!=receipt.get('sha256') or digest(self.controller.root/'guest/android-jobs/org/agenticvm/jobs/Runner.java')!=receipt.get('source_sha256'):
                    fail('Build and verify the Android job helper first.','unsupported_capability')
                self.guest.write(folder+'/runner.jar',runner.read_bytes())
                q=shlex.quote
                self.guest.run('CLASSPATH='+q(folder+'/runner.jar')+' nohup /system/bin/app_process /system/bin org.agenticvm.jobs.Runner '+q(folder)+' >'+q(folder+'/monitor.log')+' 2>&1 </dev/null &')
                record['state']='starting'
                save_json(self.meta.path(job+'.json'),record)
                return {key:value for key,value in record.items() if key!='folder'}
            self.guest.write(folder+'/runner.py',(self.controller.root/'guest/control_job.py').read_bytes())
            source='''import subprocess
subprocess.Popen([PYTHON,'-I','-B',RUNNER,FOLDER],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=FLAGS,start_new_session=SESSION)
print('LAUNCHED')'''.replace('PYTHON',repr('C:/ProgramData/AgenticVM/python/pythonw.exe' if self.controller.profile=='windows' else '/usr/bin/python3')).replace('RUNNER',repr(folder+'/runner.py')).replace('FOLDER',repr(folder)).replace('FLAGS','0x08000000' if self.controller.profile=='windows' else '0').replace('SESSION','False' if self.controller.profile=='windows' else 'True')
            self.guest.python(source)
            record['state']='starting'
            save_json(self.meta.path(job+'.json'),record)
            return {key:value for key,value in record.items() if key!='folder'}

    def status(self,job):
        with self.meta.lock():
            record=self.record(job)
            if record['generation']!=generation(self.controller) or record.get('boot_id')!=self.guest.boot_id():
                return {**{k:v for k,v in record.items() if k!='folder'},'state':'stale','reason':'guest_generation_changed'}
            raw=self.guest.optional(record['folder']+'/status.json')
            result=json.loads(raw) if raw is not None else {'id':job,'state':record['state']}
            if result.get('id')!=job or result.get('state') not in FINAL|{'starting','running','launch_unknown'}:
                fail('Invalid guest job receipt.','protocol_error')
            record['state']=result['state']; record['last_receipt']=result
            save_json(self.meta.path(job+'.json'),record)
            return {**result,**{k:v for k,v in record.items() if k not in {'folder','last_receipt'}},'state':result['state']}

    def output(self,job,stream='stdout',cursor=0,limit=16384):
        if stream not in {'stdout','stderr'} or type(cursor) is not int or not 0<=cursor<=65536 or type(limit) is not int or not 1<=limit<=65536:
            fail('Use stdout/stderr and byte cursors within 64 KiB.','invalid_job')
        record=self.record(job)
        if record['generation']!=generation(self.controller) or record.get('boot_id')!=self.guest.boot_id():
            fail('The job belongs to an earlier VM generation.','generation_changed')
        data=self.guest.optional(record['folder']+'/'+stream+'.bin') or b''
        if len(data)>65536:
            fail('Job output exceeded its retention bound.','protocol_error')
        chunk=data[cursor:cursor+limit]
        return {'id':job,'stream':stream,'cursor':cursor+len(chunk),'data_b64':base64.b64encode(chunk).decode(),
            'text':chunk.decode('utf-8','replace'),'eof':cursor+len(chunk)>=len(data),'retained_bytes':len(data)}

    def cancel(self,job):
        record=self.record(job)
        if record['generation']!=generation(self.controller) or record.get('boot_id')!=self.guest.boot_id():
            return {'id':job,'state':'stale','cancellation_requested':False}
        if record['state'] in FINAL:
            return {**record.get('last_receipt',{}),'id':job,'state':record['state'],'cancellation_requested':False}
        # Canonical job folder was created before launch. Upload the mailbox
        # directly: no status read, Python mkdir or arbitrary process ID.
        from .control_diagnostics import unwrap
        unwrap(self.controller.action({'action':'upload','path':record['folder']+'/cancel','data_b64':base64.b64encode(b'cancel\n').decode()}))
        return {'id':job,'state':'cancellation_requested','cancellation_requested':True}

    def forget(self,job):
        with self.meta.lock():
            status=self.status(job)
            if status['state'] not in FINAL:
                fail('A running job cannot be forgotten.','job_running')
            record=self.record(job)
            if status['state']!='stale' and status.get('tree_terminated'):
                folder=record['folder']
                if self.controller.profile=='android':
                    self.guest.run('rm -rf -- '+shlex.quote(folder))
                else:
                    self.guest.python('import shutil\nshutil.rmtree('+repr(folder)+')')
            save_json(self.meta.path('forgotten/'+job+'.json'),status)
            self.meta.path(job+'.json').unlink()
            return {'id':job,'forgotten':True}
