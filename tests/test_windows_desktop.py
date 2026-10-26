"""Windows routing and ownership denials. Host-only; no guest launched here."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from agenticvm.errors import AgenticVMError
from agenticvm.state import qemu_socket_directory
from agenticvm.viewer import ViewerController, ViewerError
from agenticvm.windows_desktop import WindowsDesktopBackend, WindowsDesktopStore


class WindowsDesktopTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name).resolve()
        self.store = WindowsDesktopStore(self.root, 'test-windows')
        self.identifier = str(uuid4())
        self.executable = (self.root / 'qemu.exe').resolve()
        self.patch = patch('agenticvm.windows_desktop.find_qemu', return_value=self.executable)
        self.patch.start()
        self.backend = WindowsDesktopBackend(self.store)
        sockets = qemu_socket_directory(self.identifier)
        self.state = dict(schema=1, uuid=self.identifier, session=self.store.session,
            workspace=str(self.root), name='AgenticVM-' + self.identifier, backend='windows',
            profile='windows', run_dir=str(self.root/'vms'/('AgenticVM-'+self.identifier)),
            disk=str(self.root/'windows-data'/self.store.session/'system.qcow2'),
            socket_dir=str(sockets), qmp_socket=str(sockets/'q'), serial_socket=str(sockets/'s'),
            host_control_transport='unix', executable=str(self.executable), backend_sha256='a'*64,
            pid=42, process_created='123456', registered=True, status='running', memory_mib=2048,
            network='none', persistent=True)

    def tearDown(self):
        self.patch.stop()
        self.folder.cleanup()

    def test_valid_owned_manifest_roundtrips(self):
        self.store.save(self.state)
        self.assertEqual(self.store.load(), self.state)

    def test_paths_process_and_resource_tampering_are_denied(self):
        for key, value in (('disk', str(self.root.parent/'host.qcow2')), ('qmp_socket', '127.0.0.1:9999'),
                ('executable', str(self.root/'other.exe')), ('profile', 'desktop'), ('uuid', str(uuid4())),
                ('memory_mib', True), ('pid', -1), ('process_created', 'unknown'), ('network', 'bridge'), ('persistent', False),
                ('watch_socket', str(self.root/'unowned.sock')), ('desired_state', 'restart-forever')):
            with self.subTest(key=key):
                state = copy.deepcopy(self.state)
                state[key] = value
                with self.assertRaises(AgenticVMError):
                    self.store.validate(state)

    def test_reused_process_id_cannot_be_controlled(self):
        process = Mock(created='different', executable=self.executable)
        process.alive.return_value = True
        with patch('agenticvm.windows_desktop.WindowsProcess', return_value=process):
            with self.assertRaisesRegex(AgenticVMError, 'identity changed'):
                self.backend._process(self.state, terminate=True)
        process.close.assert_called_once()

    def test_windows_command_never_runs_in_host_shell_or_linux_cli(self):
        viewer = ViewerController(self.root)
        viewer.select_profile('windows')
        windows = Mock()
        windows.action.return_value = {'exit_code': 0, 'stdout': 'guest'}
        viewer.windows = Mock(return_value=windows)
        viewer.cli = Mock(side_effect=AssertionError('Windows must not route through a host/Linux shell'))
        result = viewer.action({'action': 'exec', 'command': '$env:OS'})
        self.assertEqual(result['result']['stdout'], 'guest')
        windows.action.assert_called_once_with({'action': 'exec', 'command': '$env:OS'})
        viewer.cli.assert_not_called()

    def test_windows_input_still_passes_viewer_validation(self):
        viewer = ViewerController(self.root)
        viewer.select_profile('windows')
        viewer.windows = Mock()
        for request in ({'action':'click','x':-1,'y':0}, {'action':'type','text':'x'*4097},
                {'action':'open-url','url':'file:///C:/Windows'}, {'action':'upload','path':'C:/workspace/a','data_b64':'not base64'}):
            with self.assertRaises((ViewerError, ValueError)):
                viewer.action(request)
        viewer.windows.assert_not_called()

    def test_supervisor_waits_for_lock_without_ignoring_other_failures(self):
        script = Path(__file__).resolve().parents[1]/'scripts/windows-desktop-supervisor.py'
        spec = importlib.util.spec_from_file_location('owned_reboot_supervisor_test',script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        from unittest.mock import MagicMock
        busy, available = MagicMock(), MagicMock()
        busy.__enter__.side_effect = AgenticVMError('Busy','session_busy')
        store = Mock()
        store.lock.side_effect = [busy,available]
        with patch.object(module.time,'sleep'):
            with module.lifecycle_lock(store):
                available.__enter__.assert_called_once()
        available.__exit__.assert_called_once()
        denied = MagicMock()
        denied.__enter__.side_effect = AgenticVMError('Ownership mismatch','ownership_mismatch')
        store.lock = Mock(return_value=denied)
        with self.assertRaisesRegex(AgenticVMError,'Ownership mismatch'):
            with module.lifecycle_lock(store):
                self.fail('Must not enter on ownership failure')
        store.lock.assert_called_once()


if __name__ == '__main__':
    unittest.main()
