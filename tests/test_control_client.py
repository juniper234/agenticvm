import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from agenticvm.control_client import ControlClient, safe_path
from agenticvm.desktop_mcp import DesktopBridge, TOOLS
from agenticvm.errors import AgenticVMError


class AgentControlTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.ready = self.root/'ready.json'
        self.receipt = {'url':'http://127.0.0.1:34567/#token='+'a'*40,'workspace':str(self.root/'workspace'),'session':'desktop-app'}
        self.ready.write_text(json.dumps(self.receipt),encoding='utf-8')
        self.client = ControlClient(ready_file=self.ready,workspace=self.root/'workspace',exchange=self.root/'exchange')

    def tearDown(self):
        self.temporary.cleanup()

    def response(self, data=None):
        response = Mock(headers={'Content-Type':'application/json'})
        response.read.return_value = json.dumps({'ok':True,'result':data or {'status':'running'}}).encode()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        return response

    def test_ready_file_cannot_redirect_client_to_another_host_or_workspace(self):
        for key,value in [('url','https://example.com/#token='+'a'*40),('url','http://127.0.0.1:34567/evil#token='+'a'*40),('workspace',str(self.root/'other')),('session','other')]:
            record = {**self.receipt,key:value}
            self.ready.write_text(json.dumps(record),encoding='utf-8')
            self.client.opener = Mock()
            with self.assertRaises(AgenticVMError):
                self.client.status()
            self.client.opener.open.assert_not_called()

    def test_requests_bind_guest_identity_and_never_use_external_proxy(self):
        self.client.opener = Mock()
        self.client.opener.open.return_value = self.response()
        self.client.request('/api/action',{'action':'key','keys':'enter'},vm='windows',identifier='owned-uuid')
        request = self.client.opener.open.call_args.args[0]
        self.assertEqual(request.full_url,'http://127.0.0.1:34567/api/action')
        self.assertEqual(request.get_header('X-agenticvm-profile'),'windows')
        self.assertEqual(request.get_header('X-agenticvm-guest'),'owned-uuid')

    def test_timed_out_mutations_are_never_replayed(self):
        self.client.opener = Mock()
        self.client.opener.open.side_effect = TimeoutError('timed out')
        with self.assertRaises(TimeoutError):
            self.client.request('/api/action',{'action':'key','keys':'enter'})
        self.assertEqual(self.client.opener.open.call_count,1)

    def test_only_pre_dispatch_busy_is_retried(self):
        error = HTTPError('http://127.0.0.1',409,'Busy',{},io.BytesIO(json.dumps({'ok':False,'error':{'code':'busy'}}).encode()))
        self.client.opener = Mock()
        self.client.opener.open.side_effect = [error,self.response()]
        with patch('agenticvm.control_client.time.sleep'):
            self.client.status()
        self.assertEqual(self.client.opener.open.call_count,2)

    def test_exchange_rejects_absolute_and_traversal_paths_before_guest_read(self):
        self.client.read_file = Mock()
        for path in ('../private.txt',str(self.root/'private.txt'),'C:/Windows/private.txt', 'file.txt:stream', 'NUL.txt'):
            with self.assertRaises(AgenticVMError):
                self.client.export_file('windows','C:/workspace/a',path)
        self.client.read_file.assert_not_called()
        self.assertEqual(safe_path('windows/a.txt',self.client.exchange),self.client.exchange/'windows/a.txt')

    def test_lifecycle_busy_can_retry_observation_but_never_replay_a_mutation(self):
        def busy():
            return HTTPError('http://127.0.0.1',409,'Busy',{},io.BytesIO(json.dumps({'ok':False,'error':{'code':'session_busy'}}).encode()))
        self.client.opener = Mock()
        self.client.opener.open.side_effect = [busy(),self.response()]
        with patch('agenticvm.control_client.time.sleep'):
            self.client.status()
        self.assertEqual(self.client.opener.open.call_count,2)
        self.client.opener.open.reset_mock()
        self.client.opener.open.side_effect = busy()
        with self.assertRaises(AgenticVMError):
            self.client.request('/api/action',{'action':'reset'})
        self.assertEqual(self.client.opener.open.call_count,1)

    def test_mcp_routes_commands_to_same_client_and_validates_before_dispatch(self):
        client = Mock()
        client.action.return_value = {'exit_code':0,'stdout':'guest'}
        bridge = DesktopBridge(client)
        result = bridge.call('vm_exec',{'vm':'windows','command':'Get-Date'})
        self.assertFalse(result['isError'])
        client.action.assert_called_once_with('windows','exec',command='Get-Date')
        client.reset_mock()
        for values in ({'vm':'windows','command':'whoami','host_command':'bad'}, {'vm':'host','command':'whoami'}):
            with self.assertRaises(ValueError):
                bridge.call('vm_exec',values)
        client.action.assert_not_called()

    def test_real_stdio_mcp_handshake_and_tools_list_have_no_banner_or_token(self):
        requests = [{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
            {'jsonrpc':'2.0','method':'notifications/initialized'}, {'jsonrpc':'2.0','id':2,'method':'tools/list'}]
        child = subprocess.run([sys.executable,'-I','-B','-m','agenticvm.desktop_mcp'],
            input=''.join(json.dumps(item)+'\n' for item in requests).encode(),capture_output=True,timeout=10)
        self.assertEqual(child.returncode,0,child.stderr.decode())
        replies = [json.loads(line) for line in child.stdout.splitlines()]
        self.assertEqual(len(replies),2)
        self.assertEqual(replies[0]['result']['serverInfo']['name'],'agenticvm-desktop')
        self.assertEqual(len(replies[1]['result']['tools']),len(TOOLS))
        self.assertNotIn(b'#token=',child.stdout)


if __name__ == '__main__':
    unittest.main()
