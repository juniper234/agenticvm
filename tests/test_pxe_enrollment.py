"""Network boot prerequisites, trusted installer handling, and ownership recovery."""
import gzip,hashlib,importlib.util,json,stat,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'guest')]
from agenticvm import pxe_lab,pxe_recovery
from agenticvm.lan_lab import mac
import pxe_bootstrap,pxe_server

class NetworkBootTests(unittest.TestCase):
    def test_target_has_no_host_control_or_local_os_boot_path(self):
        vm=SimpleNamespace(qemu=Path('qemu.exe'),uuid=str(uuid4()),memory=768,folder=Path('owned'),member=4,
            port=12345,disk=Path('owned/workspace.ext2'),base={'rom':{'path':'trusted/pxe-e1000.rom'}})
        argv=pxe_lab.pxe_argv(vm)
        self.assertIn('order=n,menu=off',argv)
        for option in ('-cdrom','-kernel','-initrd','-append','-qmp','-virtfs','-fsdev'):
            self.assertNotIn(option,argv)
        drives=[argv[i+1] for i,a in enumerate(argv) if a=='-drive']
        self.assertEqual(len(drives),1);self.assertIn('workspace.ext2',drives[0])
        net=argv[argv.index('-netdev')+1]
        self.assertTrue(net.startswith('socket,id=lan,connect=127.0.0.1:'))
        self.assertNotIn('hostfwd',str(argv));self.assertNotIn('tap',str(argv))
        vm.member=5
        self.assertNotIn('-drive',pxe_lab.pxe_argv(vm))
    def test_dhcp_is_interface_scoped_with_unknown_clients_refused_and_no_gateway_or_dns(self):
        config=pxe_server.dnsmasq_config('happy')
        self.assertIn('interface=eth0\n',config);self.assertIn('bind-interfaces\n',config)
        self.assertIn('dhcp-ignore=tag:!sprout\n',config)
        self.assertIn('dhcp-host=52:54:00:4c:41:04,set:sprout,192.0.2.4\n',config)
        self.assertIn('port=0\n',config);self.assertIn('dhcp-option=option:router\n',config)
        self.assertIn('dhcp-option=option:dns-server\n',config)
        self.assertNotIn(':04,set:sprout',pxe_server.dnsmasq_config('unapproved-mac'))
    def test_plain_ram_root_contains_no_agent_or_ssh_and_all_module_parents_exist(self):
        path=ROOT/'runtime/linux-pxe-base-v3/plain-root.cpio.gz'
        self.assertTrue(path.exists(),'Build the pinned PXE image before this integration check')
        spec=importlib.util.spec_from_file_location('pxe_inventory',ROOT/'scripts/build-linux-probe.py')
        probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe);probe.MAX_INITRD=256*1024**2
        entries=probe.unpack_newc(gzip.decompress(path.read_bytes()))
        for name in ('usr/sbin/sshd','usr/bin/ssh','workspace/model.gguf','workspace/peer/lan_agent.py','boot-provision.py'):
            self.assertNotIn(name,entries)
        modules=[name for name in entries if name.endswith('/e1000.ko')]
        self.assertEqual(len(modules),1)
        for name,(mode,data) in entries.items():
            if stat.S_ISDIR(mode): self.assertEqual(data,b'',name+' contains ext2 directory blocks')
            for parent in Path(name).parents:
                if parent.as_posix()!='.': self.assertIn(parent.as_posix(),entries)
    def test_plain_target_data_volume_does_not_hide_an_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            vm=SimpleNamespace(member=4,uuid=str(uuid4()),folder=Path(tmp),disk=Path(tmp)/'workspace.ext2')
            pxe_lab.prepare(vm,None,None,None,None,None,None,None)
            inventory=json.loads((vm.folder/'initial-inventory.json').read_text())
            self.assertEqual(set(inventory['files']),{'','owned-pxe-data'})

class InstallerTrustTests(unittest.TestCase):
    def test_verified_installer_is_compiled_without_running_it(self):
        raw=b"raise RuntimeError('must not run during verification')\n"
        program=pxe_bootstrap.verified_installer(raw,hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(RuntimeError,'must not run'): exec(program,{})
    def test_changed_or_oversized_installer_is_rejected_before_compilation(self):
        raw=b"print('reviewed')\n";pin=hashlib.sha256(raw).hexdigest()
        for data in (raw+b'# changed',b'x'*65537):
            with patch('builtins.compile') as compile_program:
                with self.assertRaisesRegex(ValueError,'before execution'): pxe_bootstrap.verified_installer(data,pin)
                compile_program.assert_not_called()

class PXERecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.ident=str(uuid4());self.folder=self.root/'runtime/pxe-enrollment-runs'/self.ident
        self.folder.mkdir(parents=True);(self.folder/'owner.json').write_text(json.dumps({'pid':10,'created':'a','executable':'python.exe'}))
        self.state={10:False,11:True};self.qemu=self.root/'qemu.exe';outer=self
        class Process:
            def __init__(self,pid,**kw): self.pid=pid;self.created='a';self.executable=outer.qemu
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def alive(self): return outer.state[self.pid]
            def terminate(self): outer.state[self.pid]=False
            def wait(self,seconds): return not self.alive()
        for obj,name,value in ((pxe_recovery,'ROOT',self.root),(pxe_recovery,'WindowsProcess',Process),
                               (pxe_recovery,'find_qemu',lambda:self.qemu)):
            p=patch.object(obj,name,value);p.start();self.addCleanup(p.stop)
        directory=self.folder/'sprout-4';directory.mkdir()
        (directory/'ownership.json').write_text(json.dumps({'pid':11,'created':'a','executable':str(self.qemu),'uuid':str(uuid4())}))
        (directory/'workspace.ext2').write_bytes(b'disposable')
        private=self.folder/'private';private.mkdir();(private/'mother.key').write_bytes(b'ephemeral')
    def test_crash_recovery_stops_owned_vm_cleans_keys_and_is_idempotent(self):
        first=pxe_recovery.recover(self.ident);self.assertTrue(first['passed']);self.assertFalse(first['tasks_replayed'])
        self.assertFalse(self.state[11]);self.assertFalse((self.folder/'private').exists())
        self.assertFalse((self.folder/'sprout-4/workspace.ext2').exists());self.assertTrue(pxe_recovery.recover(self.ident)['duplicate'])
    def test_live_controller_and_reused_pid_are_not_terminated(self):
        self.state[10]=True
        with self.assertRaisesRegex(RuntimeError,'still running'): pxe_recovery.recover(self.ident)
        self.state[10]=False
        path=self.folder/'sprout-4/ownership.json';body=json.loads(path.read_text());body['created']='different';path.write_text(json.dumps(body))
        self.assertFalse(pxe_recovery.recover(self.ident)['passed']);self.assertTrue(self.state[11])
        self.assertTrue((self.folder/'private/mother.key').exists())
    def test_run_paths_cannot_escape_owned_root(self):
        for value in ('../elsewhere','{'+self.ident+'}',self.ident.upper()):
            with self.subTest(value=value),self.assertRaises(ValueError): pxe_recovery.recover(value)

if __name__=='__main__': unittest.main()
