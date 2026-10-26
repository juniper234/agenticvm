"""Stopped-disk checkpoints, staged restore plans, rescue points and journals."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time
from uuid import uuid4

from .control_diagnostics import observe,PROFILES,state
from .control_store import Metadata,checked,digest,fail,load_json,save_json

ANDROID_FILES=('cache.img','cache.img.qcow2','encryptionkey.img','encryptionkey.img.qcow2',
    'userdata-qemu.img','userdata-qemu.img.qcow2','initrd','avd/config.ini','avd/hardware-qemu.ini')


def pending(controller):
    path=controller.workspace/'control'/('profile-'+controller.profile)/'checkpoints/journal.json'
    journal=load_json(checked(path,controller.workspace),default={})
    return journal.get('phase') in {'restoring','restore_failed'}


class Checkpoints:
    def __init__(self,controller):
        self.controller=controller
        self.meta=Metadata(controller.workspace/'control'/('profile-'+controller.profile)/'checkpoints')

    def cold(self):
        current=observe(self.controller)
        if current.get('registered') or current.get('status') not in {'stopped','exited','failed'}:
            fail('Stop the owned guest before checkpoint or restore.','vm_must_be_stopped')
        saved=state(self.controller)
        if not saved:
            fail('This session has no persistent disk yet.','no_session')
        if os.name=='nt':
            from .qemu import WindowsProcess
            pins=([{'pid':saved.get('pid'),'created':saved.get('process_created'),'executable':saved.get('executable')}]
                if self.controller.profile!='android' else [*saved.get('processes',[]),saved.get('launcher',{})])
            for pin in pins:
                if not pin.get('pid'):
                    continue
                with WindowsProcess(pin['pid']) as process:
                    if process.alive() and process.created==pin.get('created') and process.executable==Path(pin['executable']).resolve():
                        fail('An owned guest process is still alive despite stopped metadata.','vm_must_be_stopped')
        return saved

    def image(self,path,logical=None):
        """Inspect only this file; never traverse an unverified backing chain."""
        from .windows_desktop import disk_tool
        path=checked(path,self.controller.workspace)
        logical=logical or path
        info=json.loads(disk_tool('info','--output=json',path))
        detail=info.get('format-specific',{}).get('data',{})
        if info.get('data-file') or detail.get('data-file'):
            fail('External image data files are not allowed.','invalid_checkpoint')
        if self.controller.profile=='windows':
            if info.get('format')!='qcow2' or info.get('virtual-size')!=48*1024**3 or info.get('backing-filename'):
                fail('Windows checkpoints require the independent owned 48 GiB disk.','invalid_checkpoint')
        elif logical.suffix=='.qcow2':
            expected=checked(logical.with_suffix(''),self.controller.workspace)
            backing=info.get('backing-filename')
            full=info.get('full-backing-filename') or str(path.parent/str(backing))
            if (info.get('format')!='qcow2' or not isinstance(backing,str)
                    or backing not in {expected.name,str(expected)} or Path(full).resolve()!=expected.resolve()):
                fail('Android overlay backing must be its owned adjacent base image.','invalid_checkpoint')
        elif logical.name=='userdata-qemu.img':
            # The pinned emulator creates a thin, independent qcow2 base even
            # though its filename ends in .img. The writable overlay backs it.
            if info.get('format') not in {'raw','qcow2'} or info.get('backing-filename') or info.get('virtual-size')!=6*1024**3:
                fail('Android userdata base must be its independent owned 6 GiB image.','invalid_checkpoint')
        elif info.get('format')!='raw' or info.get('backing-filename'):
            fail('Android base images must be independent raw files.','invalid_checkpoint')
        return info

    def preparation(self):
        if self.controller.profile=='android':
            return digest(self.controller.root/'tools/android/prepared.json')
        if self.controller.profile=='windows':
            return digest(self.controller.root/'runtime/windows-desktop/prepared.json')
        return None

    def files(self,saved):
        root=self.controller.workspace
        if self.controller.profile=='desktop':
            if not saved.get('workspace_disk'):
                fail('A persistent workspace is required.','unsupported_capability')
            paths=[Path(saved['workspace_disk'])]
        elif self.controller.profile=='windows':
            paths=[Path(saved['disk'])]
        else:
            if not saved.get('persistent'):
                fail('A persistent Android session is required.','unsupported_capability')
            directory=checked(Path(saved['data_dir']),root)
            paths=[directory/name for name in ANDROID_FILES if (directory/name).exists()]
            if not all((directory/name).is_file() for name in ('userdata-qemu.img','encryptionkey.img')):
                fail('Android persistent disk/key set is incomplete.','invalid_state')
        for path in paths:
            checked(path,root)
            if not path.is_file():
                fail('Persistent disk set is missing.','invalid_state')
            if self.controller.profile=='android' and path.suffix in {'.img','.qcow2'}:
                self.image(path)
        return paths

    def load(self,checkpoint):
        if not isinstance(checkpoint,str) or re.fullmatch('[0-9a-f]{32}',checkpoint) is None:
            fail('Choose an owned checkpoint ID.','invalid_checkpoint')
        record=load_json(self.meta.path(checkpoint+'/manifest.json'))
        if (not isinstance(record,dict) or record.get('id')!=checkpoint or record.get('vm')!=PROFILES[self.controller.profile]
                or record.get('session')!=self.controller.session or record.get('workspace')!=str(self.controller.workspace)
                or record.get('committed') is not True):
            fail('Checkpoint is incomplete or belongs to another session.','invalid_checkpoint')
        return record

    def listing(self):
        with self.meta.lock():
            manifests=self.meta.root.glob('*/manifest.json') if self.meta.root.exists() else []
            return {'checkpoints':[self.load(path.parent.name) for path in manifests],
                'journal':load_json(self.meta.path('journal.json'),default={})}

    def create(self,label='checkpoint'):
        if not isinstance(label,str) or not 1<=len(label)<=80 or any(ord(c)<32 for c in label):
            fail('Use a short checkpoint label.','invalid_checkpoint')
        with self.controller.store.lock(),self.meta.lock():
            if pending(self.controller):
                fail('Finish or recover the pending restore before checkpointing.','recovery_required')
            saved=self.cold(); paths=self.files(saved)
            if self.controller.profile=='android' and not saved.get('last_stop_clean'):
                fail('Android needs a verified clean power-off before checkpointing.','unclean_disk')
            if len(list(self.meta.root.glob('*/manifest.json')))>=32:
                fail('The 32-checkpoint retention limit was reached. Review retained checkpoints before adding more.','checkpoint_limit')
            checkpoint=uuid4().hex
            record={'id':checkpoint,'label':label,'vm':PROFILES[self.controller.profile],
                'session':self.controller.session,'workspace':str(self.controller.workspace),'at':time.time(),
                'scope':'complete-system-disk' if self.controller.profile=='windows' else 'persistent-data-and-keys' if self.controller.profile=='android' else 'workspace-only',
                'committed':False,'files':[],'preparation_sha256':self.preparation(),
                'captured_configuration':{key:saved.get(key) for key in ('uuid','memory_mib','network','persistent')}}
            journal={'phase':'creating','id':checkpoint,'at':time.time()}
            save_json(self.meta.path('journal.json'),journal)
            try:
                if self.controller.profile=='windows':
                    from .windows_desktop import disk_tool
                    disk=paths[0]
                    self.image(disk)
                    self.check_disk(disk)
                    name='avm-'+checkpoint
                    disk_tool('snapshot','-c',name,disk)
                    record['files']=[{'path':str(disk.relative_to(self.controller.workspace)),'snapshot':name}]
                    record['method']='qcow2-internal'
                else:
                    total=sum(path.stat().st_size for path in paths)
                    if shutil.disk_usage(self.controller.workspace).free<total+1024**3:
                        fail('Keep one full disk-set size plus 1 GiB free for a safe checkpoint.','insufficient_disk')
                    for index,path in enumerate(paths):
                        target=self.meta.path(checkpoint+'/'+str(index)+'.gz')
                        target.parent.mkdir(parents=True,exist_ok=True)
                        h=hashlib.sha256(); size=0
                        with path.open('rb') as source,gzip.open(target,'xb',compresslevel=1) as output:
                            while chunk:=source.read(1024**2):
                                h.update(chunk); size+=len(chunk); output.write(chunk)
                        with target.open('ab') as stable:
                            stable.flush(); os.fsync(stable.fileno())
                        record['files'].append({'path':str(path.relative_to(self.controller.workspace)),
                            'blob':str(index)+'.gz','size':size,'sha256':h.hexdigest(),'compressed_sha256':digest(target)})
                    record['method']='gzip-disk-set'
                if self.controller.profile=='desktop':
                    record['base_sha256']=digest(saved['root_disk'])
                record['committed']=True
                save_json(self.meta.path(checkpoint+'/manifest.json'),record)
                save_json(self.meta.path('journal.json'),{**journal,'phase':'created'})
                return record
            except Exception as error:
                save_json(self.meta.path('journal.json'),{**journal,'phase':'create_failed','error':str(error)[:512]})
                raise

    @staticmethod
    def check_disk(path):
        from .windows_desktop import disk_tool
        result=json.loads(disk_tool('check','--output=json',path))
        if any(result.get(key,0) for key in ('check-errors','corruptions','leaks')):
            fail('Disk structural check failed.','invalid_checkpoint')

    def validate(self,record,saved):
        owned={str(path.relative_to(self.controller.workspace)):path for path in self.files(saved)}
        if set(owned)!={item.get('path') for item in record['files']}:
            fail('Checkpoint disk set differs from this session.','invalid_checkpoint')
        if record.get('preparation_sha256')!=self.preparation():
            fail('The prepared base/tool identity changed since this checkpoint.','invalid_checkpoint')
        if self.controller.profile=='desktop' and digest(saved['root_disk'])!=record.get('base_sha256'):
            fail('The immutable Linux base changed.','invalid_checkpoint')
        if record['method']=='qcow2-internal' and self.controller.profile=='windows':
            from .windows_desktop import disk_tool
            snapshots=self.image(next(iter(owned.values()))).get('snapshots',[])
            if not any(item.get('name')=='avm-'+record['id'] for item in snapshots):
                fail('The internal checkpoint is absent.','invalid_checkpoint')
        elif record['method']=='gzip-disk-set' and self.controller.profile!='windows':
            for item in record['files']:
                if re.fullmatch('[0-9]+[.]gz',item.get('blob','')) is None:
                    fail('Invalid checkpoint blob.','invalid_checkpoint')
                blob=self.meta.path(record['id']+'/'+item['blob'])
                if digest(blob)!=item['compressed_sha256']:
                    fail('Checkpoint content changed.','invalid_checkpoint')
        else:
            fail('Checkpoint method differs from this profile.','invalid_checkpoint')
        return owned

    def plan(self,checkpoint):
        with self.controller.store.lock(),self.meta.lock():
            saved=self.cold(); record=self.load(checkpoint); self.validate(record,saved)
            plan={'plan_id':uuid4().hex,'checkpoint':checkpoint,'manifest_sha256':digest(self.meta.path(checkpoint+'/manifest.json')),
                'expires_at':time.time()+300,'scope':record['scope'],'creates_rescue':True,
                'warning':'Replaces saved disk state. Review this plan, then pass its plan_id and manifest_sha256 to restore.'}
            save_json(self.meta.path('plan.json'),plan)
            return plan

    def restore(self,plan_id,manifest_sha256):
        with self.controller.store.lock(),self.meta.lock():
            saved=self.cold(); plan=load_json(self.meta.path('plan.json'),default={})
            if plan.get('plan_id')!=plan_id or plan.get('manifest_sha256')!=manifest_sha256 or plan.get('expires_at',0)<time.time():
                fail('Review a fresh restore plan before applying it.','invalid_restore_plan')
            record=self.load(plan['checkpoint'])
            if digest(self.meta.path(record['id']+'/manifest.json'))!=manifest_sha256:
                fail('Checkpoint changed after the plan.','invalid_restore_plan')
            owned=self.validate(record,saved)
            # Rescue is committed before any replacement. Recovery from a prior
            # failed publish uses an explicit new plan for the recorded rescue.
            prior=load_json(self.meta.path('journal.json'),default={})
            if pending(self.controller):
                if record['id']!=prior.get('rescue'):
                    fail('An interrupted restore must recover its recorded rescue first.','recovery_required')
                rescue={'id':prior['rescue']}
            else:
                rescue=self.create('rescue-before-'+record['id'][:8])
            journal={'phase':'restoring','checkpoint':record['id'],'rescue':rescue['id'],'at':time.time(),'published':[]}
            save_json(self.meta.path('journal.json'),journal)
            try:
                if record['method']=='qcow2-internal':
                    from .windows_desktop import disk_tool
                    disk=next(iter(owned.values()))
                    disk_tool('snapshot','-a','avm-'+record['id'],disk)
                    self.check_disk(disk)
                else:
                    needed=sum(item['size'] for item in record['files'])
                    if shutil.disk_usage(self.controller.workspace).free<needed+1024**3:
                        fail('Keep space for a complete staged disk set plus 1 GiB.','insufficient_disk')
                    staged=[]
                    for item in record['files']:
                        destination=owned[item['path']]
                        temporary=checked(destination.with_name(destination.name+'.restore-'+plan_id),self.controller.workspace)
                        h=hashlib.sha256(); total=0
                        with gzip.open(self.meta.path(record['id']+'/'+item['blob']),'rb') as source,temporary.open('xb') as output:
                            while chunk:=source.read(1024**2):
                                total+=len(chunk)
                                if total>item['size']:
                                    fail('Checkpoint expanded beyond its manifest size.','invalid_checkpoint')
                                h.update(chunk); output.write(chunk)
                            output.flush(); os.fsync(output.fileno())
                        if total!=item['size'] or h.hexdigest()!=item['sha256']:
                            fail('Staged checkpoint verification failed.','invalid_checkpoint')
                        if self.controller.profile=='android' and destination.suffix in {'.img','.qcow2'}:
                            self.image(temporary,destination)
                        staged.append((temporary,destination))
                    for temporary,destination in staged:
                        os.replace(temporary,destination)
                        journal['published'].append(str(destination.relative_to(self.controller.workspace)))
                        save_json(self.meta.path('journal.json'),journal)
                journal['phase']='restored'; journal['cold_boot_verified']=False
                save_json(self.meta.path('journal.json'),journal)
                save_json(self.meta.path('plan.json'),{})
                return journal
            except Exception as error:
                save_json(self.meta.path('journal.json'),{**journal,'phase':'restore_failed','error':str(error)[:512]})
                raise
