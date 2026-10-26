"""Independent boot defaults, dynamic discovery, read-only observation and recovery."""
import hashlib,json,socket,stat,struct,sys,tempfile,threading,time,unittest,zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'guest')]
from agenticvm import independent_lab as lab,independent_recovery as recovery
from agenticvm.framebuffer_observer import capture,take
import independent_boot_server

class IndependentBootTests(unittest.TestCase):
    def test_target_has_untouched_boot_firmware_and_mac_defaults(self):
        vm=SimpleNamespace(qemu=Path('qemu.exe'),uuid=str(uuid4()),folder=Path('owned'),port=1234,disk=Path('owned/blank.raw'))
        argv=lab.default_target_argv(vm)
        for option in ('-boot','-bios','-pflash','-kernel','-initrd','-append','-nodefaults','-device','-cdrom','-qmp','-virtfs'):
            self.assertNotIn(option,argv)
        self.assertNotIn('romfile=',str(argv));self.assertNotIn('mac=',str(argv))
        self.assertEqual(argv[argv.index('-nic')+1],'socket,connect=127.0.0.1:1234')
        self.assertNotIn('user',argv[argv.index('-nic')+1]);self.assertNotIn('tap',str(argv))
    def test_independent_disk_is_entirely_zero_not_a_prepared_filesystem(self):
        with tempfile.TemporaryDirectory() as tmp:
            vm=SimpleNamespace(uuid=str(uuid4()),folder=Path(tmp),disk=Path(tmp)/'blank.raw')
            lab.blank_disk(vm);expected=hashlib.sha256()
            for _ in range(512): expected.update(bytes(1024**2))
            self.assertEqual(lab.digest(vm.disk),expected.hexdigest())
            inventory=json.loads((vm.folder/'initial-inventory.json').read_text())
            self.assertIsNone(inventory['parent_vm']);self.assertIsNone(inventory['source_snapshot'])
            self.assertIsNone(inventory['filesystem']);self.assertEqual(inventory['files'],[])
    def test_boot_server_learns_clients_without_mac_preallocation(self):
        text=independent_boot_server.dnsmasq_config()
        self.assertNotIn('dhcp-host=',text);self.assertNotIn('52:54:',text)
        self.assertIn('dhcp-range=192.0.2.4,192.0.2.4,255.255.255.0,2m',text)
        self.assertIn('interface=eth0\n',text);self.assertIn('bind-interfaces\n',text)
        self.assertIn('port=0\n',text);self.assertIn('dhcp-option=option:router\n',text)

class DiscoveryTests(unittest.TestCase):
    def frame(self,options=b'\x35\x01\x01\xff'):
        ethernet=bytes.fromhex('ffffffffffff5254001234560800')
        ip=bytearray(20);ip[0]=0x45;ip[9]=17
        boot=bytearray(240);boot[236:]=bytes.fromhex('63825363')
        return ethernet+ip+struct.pack('!HHHH',68,67,8+len(boot)+len(options),0)+boot+options
    def test_discovers_normal_new_client_and_handles_padding(self):
        self.assertEqual(lab.dhcp_event(self.frame()),{'message_type':1,'mac':'52:54:00:12:34:56'})
        self.assertEqual(lab.dhcp_event(self.frame(b'\0\x35\x01\x03\xff'))['message_type'],3)
    def test_malformed_truncated_and_nonclient_packets_do_not_count(self):
        raw=self.frame()
        for data in (raw[:100],self.frame(b'\x35\x7f\x01'),raw[:34]+struct.pack('!HH',67,68)+raw[38:]):
            self.assertIsNone(lab.dhcp_event(data))
    def test_switch_learns_fresh_hardware_address_and_rejects_later_identity_change(self):
        switch=lab.LearningSwitch();self.addCleanup(switch.close);port=switch.listen(4)
        conn=socket.create_connection(('127.0.0.1',port));self.addCleanup(conn.close)
        raw=self.frame();conn.sendall(struct.pack('!I',len(raw))+raw)
        deadline=time.monotonic()+2
        while 4 not in switch.addresses and time.monotonic()<deadline: time.sleep(.01)
        self.assertEqual(switch.addresses[4],bytes.fromhex('525400123456'))
        changed=raw[:6]+bytes.fromhex('525400abcdef')+raw[12:]
        conn.sendall(struct.pack('!I',len(changed))+changed)
        deadline=time.monotonic()+2
        while not switch.errors and time.monotonic()<deadline: time.sleep(.01)
        self.assertIn('changed its hardware identity',str(switch.errors))

class FramebufferReadOnlyTests(unittest.TestCase):
    def test_capture_sends_no_key_pointer_or_clipboard_messages(self):
        server=socket.socket();server.bind(('127.0.0.1',0));server.listen(1);port=server.getsockname()[1]
        self.addCleanup(server.close);events=[];errors=[]
        def run():
            try:
                with server.accept()[0] as peer:
                    peer.settimeout(3);peer.sendall(b'RFB 003.008\n');self.assertEqual(take(peer,12),b'RFB 003.008\n')
                    peer.sendall(b'\x01\x01');self.assertEqual(take(peer,1),b'\x01');peer.sendall(b'\0'*4)
                    self.assertEqual(take(peer,1),b'\x01')
                    fmt=struct.pack('!BBBBHHHBBBxxx',32,24,0,1,255,255,255,16,8,0)
                    peer.sendall(struct.pack('!HH',2,1)+fmt+struct.pack('!I',4)+b'view')
                    events.append(take(peer,20)[0]);events.append(take(peer,8)[0]);events.append(take(peer,10)[0])
                    peer.sendall(b'\0\0\0\x01'+struct.pack('!HHHHi',0,0,2,1,0)+b'\0\0\xff\0\0\xff\0\0')
            except Exception as error: errors.append(error)
        thread=threading.Thread(target=run,daemon=True);thread.start()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'frame.png';result=capture(port,path)
            self.assertTrue(path.read_bytes().startswith(b'\x89PNG'))
            self.assertEqual(result['rfb_client_message_types_sent'],[0,2,3])
            self.assertFalse(result['keyboard_pointer_clipboard_messages_sent'])
        thread.join(3);self.assertFalse(thread.is_alive());self.assertFalse(errors);self.assertEqual(events,[0,2,3])
    def test_framebuffer_field_sizes_are_bounded(self):
        with self.assertRaises(ValueError): take(None,16*1024**2+1)

class IndependentRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.ident=str(uuid4());self.folder=self.root/'runtime/independent-vm-runs'/self.ident;self.folder.mkdir(parents=True)
        (self.folder/'owner.json').write_text(json.dumps({'pid':10,'created':'a','executable':'python.exe'}))
        target=self.folder/'independent-target';target.mkdir()
        self.qemu=self.root/'qemu.exe';self.state={10:False,11:True};outer=self
        (target/'ownership.json').write_text(json.dumps({'pid':11,'created':'a','executable':str(self.qemu),'uuid':str(uuid4())}))
        (target/'blank.raw').write_bytes(b'owned blank fixture')
        private=self.folder/'private';private.mkdir();(private/'mother.key').write_bytes(b'ephemeral')
        class Process:
            def __init__(self,pid,**kw): self.pid=pid;self.created='a';self.executable=outer.qemu
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def alive(self): return outer.state[self.pid]
            def terminate(self): outer.state[self.pid]=False
            def wait(self,seconds): return not self.alive()
        for name,value in (('ROOT',self.root),('WindowsProcess',Process),('find_qemu',lambda:self.qemu)):
            p=patch.object(recovery,name,value);p.start();self.addCleanup(p.stop)
    def test_aborts_only_owned_vm_removes_keys_and_blank_disk_without_replay(self):
        first=recovery.recover(self.ident);self.assertTrue(first['passed']);self.assertFalse(first['tasks_replayed'])
        self.assertFalse(self.state[11]);self.assertFalse((self.folder/'private').exists())
        self.assertFalse((self.folder/'independent-target/blank.raw').exists());self.assertTrue(recovery.recover(self.ident)['duplicate'])
    def test_live_owner_or_reused_vm_pid_is_not_terminated(self):
        self.state[10]=True
        with self.assertRaisesRegex(RuntimeError,'still running'): recovery.recover(self.ident)
        self.state[10]=False;path=self.folder/'independent-target/ownership.json'
        body=json.loads(path.read_text());body['created']='different';path.write_text(json.dumps(body))
        self.assertFalse(recovery.recover(self.ident)['passed']);self.assertTrue(self.state[11])
    def test_orphans_prevent_silent_new_runs_and_canonical_paths_are_required(self):
        with self.assertRaisesRegex(RuntimeError,'requires explicit'): recovery.require_clean_history()
        for ident in ('../escape','{'+self.ident+'}',self.ident.upper()):
            with self.subTest(ident=ident),self.assertRaises(ValueError): recovery.recover(ident)

if __name__=='__main__': unittest.main()
