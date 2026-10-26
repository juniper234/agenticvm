"""Transport outage, firmware-policy disclosure, appliance size and recovery guards."""
import gzip,importlib.util,json,socket,struct,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'guest')]
from agenticvm import realism_lab as lab,realism_recovery as recovery
from agenticvm.lan_lab import mac,FrameDecoder
import realism_dhcp

class CableTests(unittest.TestCase):
    def test_real_socket_cable_cut_drops_frames_then_recovers_without_reconnecting_transport(self):
        switch=lab.FaultSwitch();self.addCleanup(switch.close)
        mother=socket.create_connection(('127.0.0.1',switch.listen(1)));self.addCleanup(mother.close)
        target=socket.create_connection(('127.0.0.1',switch.listen(4)));self.addCleanup(target.close)
        deadline=time.monotonic()+2
        while len(switch.ports)<2 and time.monotonic()<deadline: time.sleep(.01)
        client=bytes.fromhex('525400123456');frame=mac(1)+client+b'\x88\xb5'+b'owned test'
        packet=struct.pack('!I',len(frame))+frame
        switch.set_blocked(4,True);target.sendall(packet);mother.settimeout(.2)
        with self.assertRaises(socket.timeout): mother.recv(4096)
        self.assertGreater(switch.drops,0)
        switch.set_blocked(4,False);target.sendall(packet);mother.settimeout(2)
        self.assertEqual(FrameDecoder().feed(mother.recv(4096)),[frame])
        self.assertEqual(switch.addresses[4],client);self.assertFalse(switch.errors)
        with self.assertRaises(ValueError): switch.listen(6)
        with self.assertRaises(ValueError): switch.set_blocked(1,True)

class FirmwareAndApplianceTests(unittest.TestCase):
    def test_default_and_prepared_uefi_are_distinct_and_have_no_guest_control_channel(self):
        vm=SimpleNamespace(qemu=Path('qemu.exe'),uuid=str(uuid4()),folder=Path('owned'),port=1234,disk=Path('owned/blank.raw'))
        default=lab.target_argv(vm,'uefi-default');prepared=lab.target_argv(vm,'uefi-e1000')
        self.assertNotIn('bootindex=',str(default));self.assertNotIn('romfile=',str(default))
        self.assertIn('bootindex=1',str(prepared));self.assertIn('efi-e1000.rom',str(prepared))
        hardware=lab.target_argv(vm,'uefi-stock-rng')
        self.assertIn('virtio-rng-pci',str(hardware));self.assertNotIn('bootindex=',str(hardware));self.assertNotIn('romfile=',str(hardware))
        for argv in (default,prepared,lab.target_argv(vm,'uefi-virtio')):
            for forbidden in ('-kernel','-initrd','-append','-qmp','-virtfs','-cdrom','user,','tap,'):
                self.assertNotIn(forbidden,str(argv))
        with self.assertRaises(ValueError): lab.target_argv(vm,'unknown')
    def test_linux_requires_dhcp_and_does_not_mount_any_block_storage(self):
        text=(ROOT/'guest/realism-init.sh').read_text()
        self.assertIn('udhcpc',text);self.assertNotIn('ip addr add 192.0.2.4',text)
        self.assertNotIn('/dev/vd',text);self.assertNotIn('/dev/sd',text);self.assertNotIn('mkfs',text)
        cfg=realism_dhcp.config();self.assertIn('listen-address=192.0.2.5',cfg)
        self.assertNotIn('dhcp-host=',cfg);self.assertIn('option:client-arch,9',cfg)
    def test_dhcp_appliance_fits_256mb_without_python_or_model(self):
        base=lab.validated_base();compressed=lab.initrd(base,infrastructure=True)
        self.assertLess(len(compressed),24*1024**2)
        expanded=gzip.decompress(compressed);self.assertLess(len(expanded),80*1024**2)
        spec=importlib.util.spec_from_file_location('test_realism_cpio',ROOT/'scripts/build-linux-probe.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        entries=module.unpack_newc(expanded)
        self.assertIn('bootfiles/ipxe.efi',entries);self.assertIn('usr/sbin/dnsmasq',entries)
        self.assertNotIn('usr/bin/python3.13',entries);self.assertNotIn('model.gguf',entries)

class UKITrustTests(unittest.TestCase):
    def test_signed_ipxe_zero_file_bss_matches_firmware_accepted_hash(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            from agenticvm.uki import pefile,pe_authenticode_hash
        image=pefile.PE(str(ROOT/'tools/realism/ipxe.efi'));original=list(image.sections)
        self.assertTrue(any(not section.SizeOfRawData for section in image.sections))
        self.assertEqual(pe_authenticode_hash(image).hex(),'75c5a0a2cd42924077eefd373cd68d29f34c2cb6ed7fd8d2ea8d0902b4452340')
        self.assertEqual(image.sections,original)
    def test_firmware_hash_covers_both_kernel_and_entire_ram_environment(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            from agenticvm.uki import build,pefile,pe_authenticode_hash
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'garden.efi';kernel=b'owned kernel test payload';ram=b'owned initrd and bootstrap trust payload'
            receipt=build(ROOT/'tools/uki-stub/linuxx64.efi.stub',kernel,ram,output)
            original=output.read_bytes();pe=pefile.PE(data=original)
            self.assertEqual(pe_authenticode_hash(pe).hex(),receipt['authenticode_sha256'])
            for name,payload in ((b'.linux',kernel),(b'.initrd',ram)):
                section=next(s for s in pe.sections if s.Name.rstrip(b'\0')==name)
                self.assertEqual(section.get_data()[:section.Misc_VirtualSize],payload)
                modified=bytearray(original);modified[section.PointerToRawData]^=1
                self.assertNotEqual(pe_authenticode_hash(pefile.PE(data=bytes(modified))).hex(),receipt['authenticode_sha256'])
            modified=bytearray(original);modified[pe.OPTIONAL_HEADER.get_file_offset()+64]^=1
            self.assertEqual(pe_authenticode_hash(pefile.PE(data=bytes(modified))).hex(),receipt['authenticode_sha256'])

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.ident=str(uuid4());self.folder=self.root/'runtime/realism-runs'/self.ident;self.folder.mkdir(parents=True)
        (self.folder/'owner.json').write_text(json.dumps({'pid':10,'created':'a','executable':'python.exe'}))
        target=self.folder/'target';target.mkdir();self.qemu=self.root/'qemu.exe';self.state={10:False,11:True};outer=self
        self.ownership=target/'ownership.json';self.ownership.write_text(json.dumps({'pid':11,'created':'a','executable':str(self.qemu)}))
        for name in ('blank.raw','nvram.fd'): (target/name).write_bytes(b'owned disposable')
        class Process:
            def __init__(self,pid,**kw): self.pid=pid;self.created='a';self.executable=outer.qemu
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def alive(self): return outer.state[self.pid]
            def terminate(self): outer.state[self.pid]=False
            def wait(self,seconds): return not self.alive()
        for name,value in (('ROOT',self.root),('WindowsProcess',Process),('find_qemu',lambda:self.qemu)):
            p=patch.object(recovery,name,value);p.start();self.addCleanup(p.stop)
    def test_exact_owned_abort_removes_nvram_and_never_replays_enrollment(self):
        first=recovery.recover(self.ident);self.assertTrue(first['passed']);self.assertFalse(first['tasks_replayed'])
        self.assertFalse(self.state[11]);self.assertFalse((self.folder/'target/nvram.fd').exists())
        self.assertTrue(recovery.recover(self.ident)['duplicate'])
    def test_live_owner_and_reused_pid_are_not_terminated(self):
        self.state[10]=True
        with self.assertRaisesRegex(RuntimeError,'still running'): recovery.recover(self.ident)
        self.state[10]=False;body=json.loads(self.ownership.read_text());body['created']='different';self.ownership.write_text(json.dumps(body))
        self.assertFalse(recovery.recover(self.ident)['passed']);self.assertTrue(self.state[11])
        self.assertTrue((self.folder/'target/blank.raw').exists())
    def test_orphans_and_redirected_or_noncanonical_paths_are_refused(self):
        with self.assertRaisesRegex(RuntimeError,'requires recovery'): recovery.require_clean_history()
        for ident in ('../escape','{'+self.ident+'}',self.ident.upper()):
            with self.assertRaises(ValueError): recovery.recover(ident)

if __name__=='__main__': unittest.main()
