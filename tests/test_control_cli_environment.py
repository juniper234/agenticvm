"""In-process CLI calls must not leak their private endpoint configuration."""
import io
import importlib.util
import os
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agenticvm.control_cli import main


class ControlCliEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name)
        self.args=['--workspace',str(self.root),'--ready-file',str(self.root/'ready.json'),
                   '--exchange',str(self.root/'exchange'),'serve']

    def test_reusing_existing_service_does_not_leak_default_socket_root(self):
        with patch.dict(os.environ,{},clear=False):
            os.environ.pop('AGENTICVM_SOCKET_ROOT',None)
            with patch('agenticvm.control_cli.ControlClient') as client, patch('agenticvm.viewer.main') as serve:
                client.return_value.request.return_value={'workspace':str(self.root)}
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main(self.args),0)
                serve.assert_not_called()
                self.assertNotIn('AGENTICVM_SOCKET_ROOT',os.environ)

    def test_default_is_available_only_while_service_runs(self):
        with patch.dict(os.environ,{},clear=False):
            os.environ.pop('AGENTICVM_SOCKET_ROOT',None)
            with patch('agenticvm.control_cli.ControlClient') as client:
                client.return_value.request.side_effect=OSError('not listening')
                def serve(args):
                    self.assertIn('AGENTICVM_SOCKET_ROOT',os.environ)
                    return 0
                with patch('agenticvm.viewer.main',side_effect=serve):
                    self.assertEqual(main(self.args),0)
                self.assertNotIn('AGENTICVM_SOCKET_ROOT',os.environ)

    def test_explicit_root_survives_service_failure(self):
        with patch.dict(os.environ,{'AGENTICVM_SOCKET_ROOT':str(self.root/'ipc')}):
            with patch('agenticvm.control_cli.ControlClient') as client:
                client.return_value.request.side_effect=OSError('not listening')
                with patch('agenticvm.viewer.main',side_effect=RuntimeError('startup failed')):
                    with self.assertRaisesRegex(RuntimeError,'startup failed'):
                        main(self.args)
                self.assertEqual(os.environ['AGENTICVM_SOCKET_ROOT'],str(self.root/'ipc'))

    def test_default_is_removed_after_service_failure(self):
        with patch.dict(os.environ,{},clear=False):
            os.environ.pop('AGENTICVM_SOCKET_ROOT',None)
            with patch('agenticvm.control_cli.ControlClient') as client:
                client.return_value.request.side_effect=OSError('not listening')
                with patch('agenticvm.viewer.main',side_effect=RuntimeError('startup failed')):
                    with self.assertRaisesRegex(RuntimeError,'startup failed'):
                        main(self.args)
                self.assertNotIn('AGENTICVM_SOCKET_ROOT',os.environ)

    def test_importing_windows_supervisor_does_not_change_caller_environment(self):
        source=Path(__file__).resolve().parents[1]/'scripts/windows-desktop-supervisor.py'
        with patch.dict(os.environ,{},clear=False):
            os.environ.pop('AGENTICVM_SOCKET_ROOT',None)
            spec=importlib.util.spec_from_file_location('supervisor_environment_regression',source)
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.assertNotIn('AGENTICVM_SOCKET_ROOT',os.environ)


if __name__=='__main__':unittest.main()
