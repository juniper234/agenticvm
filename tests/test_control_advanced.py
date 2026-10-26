"""Failure-oriented control contracts. Native guest acceptance is separate."""
from contextlib import nullcontext
from pathlib import Path
import tempfile
import threading
import unittest
import sys
from unittest.mock import Mock,patch

from agenticvm.control_store import Metadata,checked,load_json,save_json
from agenticvm.control_sessions import Sessions,Lease
from agenticvm.control_sync import Sync
from agenticvm.control_checkpoints import Checkpoints,pending
from agenticvm.control_jobs import Jobs
from agenticvm.control_diagnostics import generation
from agenticvm.control_plane import ControlPlane
from agenticvm.control_transaction import Transaction
from agenticvm.errors import AgenticVMError


class MemoryGuest:
    def __init__(self,controller):self.files={}; self.root='/workspace'
    def path(self,path):
        if not path.startswith('/workspace/') or '..' in path.split('/'):
            raise AgenticVMError('bad path','invalid_path')
        return path
    def optional(self,path):return self.files.get(self.path(path))
    def compare_write(self,path,data,expected):
        from agenticvm.control_guest import sha
        if sha(self.optional(path))!=expected:raise AgenticVMError('changed','sync_conflict')
        self.files[self.path(path)]=data
    def boot_id(self):return 'boot-1'


class AdvancedTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name).resolve()
        self.controller=Mock(workspace=self.root/'workspace',root=self.root,profile='desktop',session='test',lock=threading.Lock())
        self.controller.workspace.mkdir()
        self.saved={'uuid':'00000000-0000-4000-8000-000000000001','registered':False,'pid':10,'process_created':'100'}
        self.controller.store.load.side_effect=lambda required=False:self.saved
        self.controller.store.lock.side_effect=lambda:nullcontext()
        self.controller.status.side_effect=lambda:{'ok':True,'result':{'status':'stopped','registered':self.saved['registered']}}
    def tearDown(self):self.temp.cleanup()

    def test_metadata_nested_locks_atomic_and_redirect_denial(self):
        meta=Metadata(self.root/'meta')
        with meta.lock(),meta.lock():save_json(meta.path('record.json'),{'complete':True})
        self.assertEqual(load_json(meta.path('record.json')),{'complete':True})
        with self.assertRaises(AgenticVMError):checked(self.root/'../outside',self.root)

    def test_managed_inventory_cannot_adopt_foreign_or_clone_windows(self):
        sessions=Sessions(self.controller); sessions.create('worker','linux',True)
        self.assertEqual(len(sessions.inventory()['sessions']),2)
        for name,vm in [('worker','linux'),('../escape','linux'),('windows2','windows'),('main','linux')]:
            with self.assertRaises(AgenticVMError):sessions.create(name,vm)
        with self.assertRaises(AgenticVMError):sessions.resolve('foreign')

    def test_leases_serialize_renew_expire_and_invalidate_on_generation(self):
        lease=Lease(self.controller); first=lease.acquire('orchestrator',30)
        with self.assertRaisesRegex(AgenticVMError,'Another'):lease.acquire('worker')
        lease.require(first['token'],None)
        self.assertEqual(first['token'],lease.acquire('orchestrator',30,first['token'])['token'])
        with patch('agenticvm.control_sessions.time.time',return_value=first['expires_at']+1):
            with self.assertRaises(AgenticVMError):lease.require(first['token'],None)
        self.saved['registered']=True
        with self.assertRaisesRegex(AgenticVMError,'generation'):lease.require(first['token'],None)
        self.saved.update(registered=False,pid=11,process_created='101')
        with self.assertRaises(AgenticVMError):lease.require(first['token'],None)
        self.saved['registered']=True
        second=lease.acquire('worker',30); self.assertNotEqual(first['token'],second['token'])
        lease.release(second['token'],generation(self.controller))
        with self.assertRaises(AgenticVMError):lease.require(second['token'],generation(self.controller))

    def sync(self):
        exchange=self.root/'exchange'; exchange.mkdir(); guest=MemoryGuest(self.controller)
        with patch('agenticvm.control_sync.Guest',return_value=guest):sync=Sync(self.controller,exchange)
        return sync,guest,exchange

    def test_sync_binary_roundtrip_and_both_changed_preserves_both(self):
        sync,guest,exchange=self.sync(); original=bytes(range(256))*4096
        (exchange/'data.bin').write_bytes(original); sync.create('pair','data.bin','/workspace/data.bin')
        first=sync.apply('pair',0); self.assertEqual(guest.files['/workspace/data.bin'],original)
        (exchange/'data.bin').write_bytes(b'host edit'); guest.files['/workspace/data.bin']=b'guest edit'
        conflict=sync.apply('pair',first['revision'])
        self.assertFalse(conflict['applied']); self.assertTrue(conflict['conflict'])
        self.assertEqual((exchange/'data.bin').read_bytes(),b'host edit'); self.assertEqual(guest.files['/workspace/data.bin'],b'guest edit')
        resolved=sync.apply('pair',1,'keep-both',conflict['observed_host_hash'],conflict['observed_guest_hash'])
        self.assertEqual((exchange/resolved['preserved_exchange_path']).read_bytes(),b'guest edit')
        self.assertEqual(guest.files['/workspace/data.bin'],b'host edit')

    def test_sync_stale_resolution_missing_source_and_traversal_denied(self):
        sync,guest,exchange=self.sync(); sync.create('pair','missing.bin','/workspace/missing.bin')
        with self.assertRaises(AgenticVMError):sync.apply('pair',0,'push')
        with self.assertRaises(AgenticVMError):sync.create('bad','../outside','/workspace/a')
        (exchange/'missing.bin').write_bytes(b'host'); guest.files['/workspace/missing.bin']=b'guest'
        conflict=sync.inspect('pair'); guest.files['/workspace/missing.bin']=b'new guest'
        with self.assertRaises(AgenticVMError):sync.apply('pair',0,'keep-host',conflict['observed_host_hash'],conflict['observed_guest_hash'])
        self.assertEqual(guest.files['/workspace/missing.bin'],b'new guest')

    def test_sync_remote_failure_does_not_advance_revision_or_publish_host(self):
        sync,guest,exchange=self.sync(); (exchange/'file').write_bytes(b'one'); sync.create('pair','file','/workspace/file')
        guest.compare_write=Mock(side_effect=OSError('disconnected'))
        with self.assertRaises(OSError):sync.apply('pair',0)
        self.assertEqual(sync.record('pair')['revision'],0); self.assertEqual((exchange/'file').read_bytes(),b'one')

    def checkpoint(self):
        disk=self.controller.workspace/'data/test.ext2'; disk.parent.mkdir(); disk.write_bytes(b'A'*65536)
        base=self.root/'base.ext2'; base.write_bytes(b'immutable base'); self.saved.update(workspace_disk=str(disk),root_disk=str(base))
        return Checkpoints(self.controller),disk

    def test_cold_checkpoint_restore_stages_and_preserves_rescue(self):
        checkpoints,disk=self.checkpoint(); record=checkpoints.create('before'); self.assertEqual(record['scope'],'workspace-only')
        disk.write_bytes(b'B'*65536); plan=checkpoints.plan(record['id']); result=checkpoints.restore(plan['plan_id'],plan['manifest_sha256'])
        self.assertEqual(disk.read_bytes(),b'A'*65536); self.assertFalse(result['cold_boot_verified'])
        self.assertTrue(checkpoints.load(result['rescue'])['committed']); self.assertFalse(pending(self.controller))
        with self.assertRaises(AgenticVMError):checkpoints.restore(plan['plan_id'],plan['manifest_sha256'])

    def test_checkpoint_live_corruption_and_foreign_denied(self):
        checkpoints,disk=self.checkpoint(); self.saved['registered']=True
        with self.assertRaises(AgenticVMError):checkpoints.create()
        self.saved['registered']=False; record=checkpoints.create(); checkpoints.meta.path(record['id']+'/0.gz').write_bytes(b'corrupt')
        with self.assertRaises(AgenticVMError):checkpoints.plan(record['id'])
        with self.assertRaises(AgenticVMError):checkpoints.load('../outside')
        self.assertEqual(disk.read_bytes(),b'A'*65536)

    def test_stopped_metadata_cannot_hide_a_live_owned_process(self):
        checkpoints,disk=self.checkpoint(); self.saved['executable']=str(Path(sys.executable).resolve())
        with patch('agenticvm.qemu.WindowsProcess') as process:
            owned=process.return_value.__enter__.return_value
            owned.alive.return_value=True; owned.created='100'; owned.executable=Path(self.saved['executable'])
            with self.assertRaises(AgenticVMError) as error:checkpoints.cold()
            self.assertEqual(error.exception.code,'vm_must_be_stopped')
            owned.created='101' # Reused PID belongs to a different process.
            self.assertEqual(checkpoints.cold(),self.saved)

    def test_overlay_and_windows_backing_references_are_rechecked(self):
        from agenticvm import windows_desktop
        checkpoints=Checkpoints(self.controller); self.controller.profile='android'
        folder=self.controller.workspace/'android-data/test'; folder.mkdir(parents=True)
        base=folder/'cache.img'; base.write_bytes(b'raw')
        overlay=folder/'cache.img.qcow2'; overlay.write_bytes(b'fixture')
        good={'format':'qcow2','backing-filename':'cache.img','full-backing-filename':str(base)}
        with patch.object(windows_desktop,'disk_tool',return_value=__import__('json').dumps(good).encode()):
            self.assertEqual(checkpoints.image(overlay)['format'],'qcow2')
        for bad in ({**good,'backing-filename':'../foreign.img'}, {**good,'full-backing-filename':str(self.root/'foreign.img')},
                    {**good,'format-specific':{'data':{'data-file':'C:/foreign-data'}}}):
            with patch.object(windows_desktop,'disk_tool',return_value=__import__('json').dumps(bad).encode()):
                with self.assertRaises(AgenticVMError):checkpoints.image(overlay)
        self.controller.profile='windows'
        with patch.object(windows_desktop,'disk_tool',return_value=__import__('json').dumps({**good,'virtual-size':48*1024**3}).encode()):
            with self.assertRaises(AgenticVMError):checkpoints.image(overlay)

    def test_checkpoint_rejects_a_changed_immutable_base(self):
        checkpoints,disk=self.checkpoint(); record=checkpoints.create()
        Path(self.saved['root_disk']).write_bytes(b'changed')
        with self.assertRaises(AgenticVMError):checkpoints.plan(record['id'])
        self.assertEqual(disk.read_bytes(),b'A'*65536)

    def test_android_thin_userdata_base_is_independent_despite_img_suffix(self):
        from agenticvm import windows_desktop
        checkpoints=Checkpoints(self.controller); self.controller.profile='android'
        path=self.controller.workspace/'android-data/test/userdata-qemu.img'; path.parent.mkdir(parents=True); path.write_bytes(b'fixture')
        good={'format':'qcow2','virtual-size':6*1024**3,'format-specific':{'data':{'compat':'1.1'}}}
        with patch.object(windows_desktop,'disk_tool',return_value=__import__('json').dumps(good).encode()):
            self.assertEqual(checkpoints.image(path)['format'],'qcow2')
        for bad in ({**good,'backing-filename':'C:/foreign.img'},{**good,'virtual-size':48*1024**3},
                    {**good,'format-specific':{'data':{'data-file':'C:/foreign-data'}}}):
            with patch.object(windows_desktop,'disk_tool',return_value=__import__('json').dumps(bad).encode()):
                with self.assertRaises(AgenticVMError):checkpoints.image(path)

    def test_restore_interruption_blocks_launch_and_keeps_rescue(self):
        checkpoints,disk=self.checkpoint(); record=checkpoints.create(); disk.write_bytes(b'B'*65536); plan=checkpoints.plan(record['id'])
        original=__import__('os').replace
        def fail_disk(source,destination):
            if str(destination)==str(disk):raise OSError('injected interrupted publish')
            return original(source,destination)
        with patch('agenticvm.control_checkpoints.os.replace',side_effect=fail_disk):
            with self.assertRaises(OSError):checkpoints.restore(plan['plan_id'],plan['manifest_sha256'])
        self.assertTrue(pending(self.controller)); journal=load_json(checkpoints.meta.path('journal.json'))
        self.assertTrue(checkpoints.load(journal['rescue'])['committed']); recovery=checkpoints.plan(journal['rescue'])
        checkpoints.restore(recovery['plan_id'],recovery['manifest_sha256']); self.assertEqual(disk.read_bytes(),b'B'*65536); self.assertFalse(pending(self.controller))

    def test_job_foreign_id_and_old_generation_never_write_cancel(self):
        with patch('agenticvm.control_jobs.Guest',return_value=MemoryGuest(self.controller)):jobs=Jobs(self.controller)
        with self.assertRaises(AgenticVMError):jobs.cancel('f'*32)
        job='a'*32; save_json(jobs.meta.path(job+'.json'),{'id':job,'vm':'linux','generation':'old','folder':'/workspace/.agenticvm/jobs/'+job})
        self.assertEqual(jobs.cancel(job)['state'],'stale'); self.assertEqual(jobs.guest.files,{})

    def test_new_mutations_need_lease_and_exact_target(self):
        plane=ControlPlane(self.controller)
        with self.assertRaises(AgenticVMError):plane.dispatch({'operation':'job_start','command':'echo test','vm':'linux'})
        token=plane.dispatch({'operation':'lease_acquire','owner':'test'})['result']['token']
        with self.assertRaises(AgenticVMError):plane.dispatch({'operation':'action','action':'exec','command':'whoami','vm':'windows','lease':token})
        with self.assertRaises(AgenticVMError):plane.dispatch({'operation':'action','action':'exec','command':'whoami','host_path':'C:/','lease':token})
        self.controller.action.assert_not_called()

    def test_failed_checkpoint_prevents_transaction_execution(self):
        transaction=Transaction(self.controller)
        with patch('agenticvm.control_transaction.Checkpoints') as checkpoints:
            checkpoints.return_value.create.side_effect=OSError('disk full')
            with patch.object(transaction.guest,'execute') as execute:
                result=transaction.run('write task','verify task','verify recovery')
                execute.assert_not_called()
        self.assertFalse(result['ok']); self.assertIsNone(result['checkpoint'])
        self.assertIn('disk full',result['task_error']['message']); self.assertIsNone(result['recovery_error'])

    def test_transaction_preserves_task_and_recovery_errors_separately(self):
        transaction=Transaction(self.controller)
        self.controller.action.return_value={'ok':False,'error':{'message':'task boot failed','code':'boot_failure'}}
        with patch('agenticvm.control_transaction.Checkpoints') as checkpoints:
            checkpoints.return_value.create.return_value={'id':'a'*32}
            checkpoints.return_value.plan.side_effect=OSError('recovery plan failed')
            result=transaction.run('task','verify','recover')
        self.assertEqual(result['task_error']['code'],'boot_failure')
        self.assertIn('recovery plan failed',result['recovery_error']['message'])

    def test_missing_control_arguments_fail_before_dispatch(self):
        plane=ControlPlane(self.controller)
        for request in ({'operation':'job_start'},{'operation':'checkpoint_restore','plan_id':'x'}, {'operation':'sync_apply','name':'x'}):
            with self.assertRaises(AgenticVMError) as caught:plane.dispatch(request)
            self.assertEqual(caught.exception.code,'invalid_request')


if __name__=='__main__':unittest.main()
