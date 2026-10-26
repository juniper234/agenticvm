"""Control-plane diagnostic contracts. No guest or host shell is launched."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch
from uuid import uuid4

from agenticvm import control_diagnostics as diag
from agenticvm.control_client import ControlClient
from agenticvm.control_plane import ControlPlane
from agenticvm.errors import AgenticVMError


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.root=Path(self.temporary.name).resolve()
        self.controller=Mock(profile='desktop',workspace=self.root,root=self.root,lock=threading.Lock())
        self.saved={'uuid':str(uuid4()),'registered':False,'memory_mib':768}
        self.controller.store.load.return_value=self.saved
        self.controller.status.return_value={'ok':True,'result':{'registered':False,'status':'stopped','profile':'desktop'}}

    def tearDown(self):
        self.temporary.cleanup()

    def log(self,content):
        folder=self.root/'vms'/('AgenticVM-'+self.saved['uuid'])
        folder.mkdir(parents=True,exist_ok=True)
        path=folder/'boot.log'
        path.write_bytes(content)
        return path

    def test_health_reports_actual_admission_failures_without_weakening_limits(self):
        self.controller.profile='android'
        self.saved['memory_mib']=2560
        memory={'total_physical_mib':4096,'available_physical_mib':1024,'available_commit_mib':1024}
        with patch.object(diag,'memory_status',return_value=memory),patch.object(diag,'whpx_status',return_value={'available':True}),patch.object(diag.shutil,'disk_usage',return_value=Mock(free=7*1024**3,total=64*1024**3)):
            result=diag.health(self.controller)
        self.assertFalse(result['can_start'])
        self.assertEqual({item['code'] for item in result['start_blocks']},{'insufficient_disk','insufficient_host_memory'})
        self.assertEqual(result['disk']['required_free_bytes'],8*1024**3)
        self.assertEqual(result['required_available_physical_mib'],3584)
        self.assertEqual(result['required_available_commit_mib'],3456)

    def test_log_cursors_are_bounded_and_cannot_expose_split_secret_values(self):
        self.log(b'boot complete\npassword=example secret with spaces\na normal line\n')
        cursor,outputs=0,[]
        for _ in range(20):
            result=diag.logs(self.controller,'boot',cursor,16)
            self.assertLessEqual(result['bytes_read'],16)
            self.assertGreaterEqual(result['cursor'],cursor)
            outputs.append(result['text'])
            cursor=result['cursor']
            if result['eof']:
                break
        self.assertNotIn('example',''.join(outputs))
        self.assertNotIn('secret with spaces',''.join(outputs))
        self.log(b'token=abcd with spaces\nnext\n')
        result=diag.logs(self.controller,'boot',0,65536)
        self.assertIn('[redacted]',result['text'])
        self.assertNotIn('abcd',result['text'])

    def test_logs_reject_arbitrary_paths_and_redirected_owned_directory(self):
        path=self.log(b'hello\n')
        with self.assertRaises(AgenticVMError):
            diag.logs(self.controller,'../../private/guest-account.txt')
        with patch.object(Path,'is_junction',autospec=True,side_effect=lambda value:value==path.parent):
            with self.assertRaisesRegex(AgenticVMError,'redirect'):
                diag.logs(self.controller,'boot')

    def test_generation_changes_when_native_process_identity_changes(self):
        self.saved.update(registered=True,pid=12,process_created='100')
        before=diag.generation(self.controller)
        self.saved['process_created']='101'
        self.assertNotEqual(before,diag.generation(self.controller))
        self.saved['registered']=False
        self.assertIsNone(diag.generation(self.controller))

    def test_control_plane_denies_unknown_operations_and_target_changes(self):
        plane=ControlPlane(self.controller)
        for request in ({'operation':'host-exec'},{'operation':'logs','kind':'boot','host_path':'C:/Windows'},
                        {'operation':'capabilities','vm':'windows'},{'operation':'capabilities','session':'foreign'}):
            with self.assertRaises(AgenticVMError):
                plane.dispatch(request)
        self.controller.cli.assert_not_called()
        with self.controller.lock:
            with self.assertRaisesRegex(AgenticVMError,'running'):
                plane.dispatch({'operation':'capabilities'})

    def test_wait_observes_without_replaying_an_action_and_reports_deadline(self):
        client=ControlClient()
        client.control=Mock(side_effect=[{'satisfied':False},{'satisfied':True}])
        with patch('agenticvm.control_client.time.sleep'):
            self.assertFalse(client.wait('linux',timeout_seconds=1)['timed_out'])
        self.assertTrue(all(call.args[0]=='probe' for call in client.control.call_args_list))
        client.control=Mock(return_value={'satisfied':False})
        result=client.wait('linux',timeout_seconds=0)
        self.assertTrue(result['timed_out'])
        self.assertEqual(client.control.call_count,1)


if __name__=='__main__':
    unittest.main()
