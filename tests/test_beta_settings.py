"""Configuration/media/bridge boundary checks with real HTTP; no guest launch."""
import http.client
import json
from pathlib import Path
import struct
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from agenticvm.configuration import Configuration, defaults, inspect_media
from agenticvm.control_diagnostics import capabilities
from agenticvm.errors import AgenticVMError
from agenticvm.viewer import ViewerController, ViewerError, ViewerServer


class BetaSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.controller = ViewerController(self.root/'workspace', application_root=self.root)
        self.config = self.controller.configuration
        self.config.snapshot()

    def tearDown(self):
        self.temp.cleanup()

    def media(self, name='disk.raw', content=b'owned test disk'):
        path = self.root/'media/incoming'/name
        path.write_bytes(content)
        return path

    def add(self):
        return self.config.add_os('Test OS', self.media().name, self.config.load()['revision'])

    def test_settings_survive_a_new_controller_without_starting_any_guest(self):
        values = {**defaults('desktop'), 'memory':4096, 'cpus':2, 'width':1280, 'height':720, 'network':False}
        with patch.object(self.controller, 'cli', side_effect=AssertionError('must not launch')):
            result = self.controller.config_request({'operation':'save','profile':'desktop','os_id':None,'settings':values,'revision':0})
        self.assertEqual(result['revision'],1)
        other = ViewerController(self.root/'workspace', application_root=self.root)
        self.assertEqual(other._start_settings(),values)
        self.assertFalse(other.store.load(required=False))

    def test_stale_revision_preserves_the_previous_complete_configuration(self):
        self.config.save('desktop',None,defaults('desktop'),0)
        before = self.config.path.read_bytes()
        with self.assertRaisesRegex(AgenticVMError,'another window'):
            self.config.save('desktop',None,{**defaults('desktop'),'network':False},0)
        self.assertEqual(self.config.path.read_bytes(),before)

    def test_invalid_settings_cannot_publish_partial_changes(self):
        for mutation in [{'memory':True},{'memory':16385},{'cpus':0},{'cpus':True},{'network':'true'},
                         {'width':700},{'height':True},{'host_path':'C:/'},{'memory':767}]:
            with self.subTest(mutation=mutation), self.assertRaises(AgenticVMError):
                self.config.save('desktop',None,{**defaults('desktop'),**mutation},0)
        self.assertEqual(self.config.load()['revision'],0)

    def test_running_guest_blocks_config_and_media_without_any_write(self):
        self.controller.store = Mock()
        self.controller.store.load.return_value={'registered':True}
        with self.assertRaisesRegex(ViewerError,'Stop the current'):
            self.controller.config_request({'operation':'add_os','name':'OS','filename':'disk.raw','revision':0})
        self.assertFalse(self.config.path.exists())

    def test_media_is_copied_and_independent_from_the_original(self):
        source=self.media()
        content=source.read_bytes()
        result=self.config.add_os('<OS & name>',source.name,0)
        identifier=result['os_id']
        copy,entry=self.config.media_file(identifier)
        self.assertEqual(copy.read_bytes(),content)
        self.assertEqual(source.read_bytes(),content)
        self.assertEqual(entry['name'],'<OS & name>')
        source.write_bytes(b'changed original')
        self.assertEqual(self.config.media_file(identifier)[0].read_bytes(),content)
        copy.write_bytes(b'corrupt')
        with self.assertRaisesRegex(AgenticVMError,'changed'):
            self.config.media_file(identifier)

    def test_media_paths_and_network_protocols_cannot_escape_staging(self):
        for filename in ['../disk.raw','C:/disk.raw','https://example.org/x.iso','a\\b.iso','disk.raw:stream','file.txt']:
            with self.subTest(filename=filename),self.assertRaises(AgenticVMError):
                self.config.add_os('OS',filename,0)
        self.assertEqual(self.config.load()['oses'],{})

    def test_qcow_external_backing_encryption_and_data_files_are_rejected(self):
        path=self.media('image.qcow2',b'')
        header=bytearray(104)
        header[:4]=b'QFI\xfb'
        struct.pack_into('>I',header,4,3)
        struct.pack_into('>Q',header,24,32*1024**3)
        path.write_bytes(header)
        inspect_media(path,'qcow2')
        for offset,fmt,value in [(8,'>Q',104),(16,'>I',20),(32,'>I',1),(72,'>Q',4),(24,'>Q',1024**4)]:
            bad=bytearray(header);struct.pack_into(fmt,bad,offset,value);path.write_bytes(bad)
            with self.subTest(offset=offset),self.assertRaises(AgenticVMError):
                self.config.add_os('OS',path.name,0)
        self.assertEqual(self.config.load()['oses'],{})

    def test_unregistered_os_and_unknown_config_fields_fail_closed(self):
        with self.assertRaises(AgenticVMError):self.controller.select_profile('custom','f'*12)
        with self.assertRaises(ViewerError):self.controller.config_request({'operation':'save','extra':True})

    def test_custom_guest_capabilities_and_protocol_denials_are_honest(self):
        result=self.add()
        self.controller.select_profile('custom',result['os_id'])
        caps=capabilities(self.controller)
        self.assertTrue(caps['screen']);self.assertFalse(caps['commands']);self.assertFalse(caps['files'])
        for action in ['exec','upload','open-url']:
            with self.subTest(action=action), self.assertRaisesRegex(ViewerError,'unavailable'):
                self.controller.action({'action':action})
        with self.assertRaisesRegex(ViewerError,'unavailable'):
            self.controller.download('/workspace/private')

    def test_os_specific_settings_do_not_leak_between_guests(self):
        result=self.add();identifier=result['os_id']
        values={**defaults('custom'),'memory':1536,'firmware':'uefi','boot':'disk'}
        self.config.save('custom',identifier,values,1)
        self.assertEqual(self.config.settings('custom',identifier),values)
        self.assertEqual(self.config.settings('desktop'),defaults('desktop'))
        self.assertEqual(self.config.settings('android'),defaults('android'))

    def test_real_http_requires_token_and_same_origin_for_configuration(self):
        server=ViewerServer(self.controller,0)
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True)
        thread.start()
        def call(method, headers, body=None):
            connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
            connection.request(method,'/api/config',body=body,headers=headers)
            response=connection.getresponse();payload=json.loads(response.read());connection.close()
            return response.status,payload
        try:
            self.assertEqual(call('GET',{})[0],401)
            auth={'X-AgenticVM-Token':server.token}
            self.assertEqual(call('GET',auth)[0],200)
            body=json.dumps({'operation':'save','profile':'desktop','os_id':None,'settings':defaults('desktop'),'revision':0})
            self.assertEqual(call('POST',{**auth,'Content-Type':'application/json'},body)[0],403)
            code,payload=call('POST',{**auth,'Content-Type':'application/json','Origin':server.origin},body)
            self.assertEqual(code,200,payload);self.assertEqual(payload['result']['revision'],1)
        finally:
            server.shutdown();server.server_close();thread.join(2)

    def test_staged_junction_is_refused(self):
        outside=self.root/'outside';outside.mkdir();(outside/'disk.raw').write_bytes(b'private')
        incoming=self.root/'media/incoming'
        incoming.rmdir()
        import os,subprocess
        if os.name=='nt':
            subprocess.run(['cmd','/c','mklink','/J',str(incoming),str(outside)],check=True,capture_output=True)
        else:
            incoming.symlink_to(outside,target_is_directory=True)
        try:
            with self.assertRaises(AgenticVMError):self.config.add_os('OS','disk.raw',0)
        finally:
            incoming.rmdir() if os.name=='nt' else incoming.unlink()

    def test_long_install_paths_use_scoped_private_sockets_without_tcp(self):
        import os
        from uuid import uuid4
        from agenticvm.state import qemu_socket_directory
        identifier=str(uuid4())
        long_root=str(Path(self.root.anchor)/('beta folder '+'x'*60))
        with patch.dict(os.environ,{'AGENTICVM_SOCKET_ROOT':long_root}):
            path=qemu_socket_directory(identifier)
            self.assertEqual(path.parent,Path(long_root))
            self.assertLess(len(str(path/'q').encode()),108)
            self.assertEqual(len(path.name),16)
            self.assertNotEqual(qemu_socket_directory(str(uuid4())),path)

    def test_android_long_paths_fail_before_launch_and_logs_have_a_startup_guard(self):
        from agenticvm.android import runtime_paths, check_start_log
        from uuid import uuid4
        identifier=str(uuid4())
        home,avd=runtime_paths(self.root,identifier)
        self.assertTrue(home.is_relative_to(self.root))
        self.assertTrue(avd.is_relative_to(home))
        with self.assertRaisesRegex(AgenticVMError,'too long'):
            runtime_paths(self.root/('x'*200),identifier)
        path=self.root/'emulator.log'
        with path.open('wb') as output:output.truncate(16*1024**2+1)
        with self.assertRaisesRegex(AgenticVMError,'excessive logs'):
            check_start_log(path)
