"""Enrollment invariants; native inference is tested separately in real VMs."""
import hashlib,importlib.util,io,json,sqlite3,ssl,struct,sys,tarfile,tempfile,threading,time,unittest
from uuid import uuid4
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT/'guest'))
from agenticvm.lan_lab import FrameDecoder,completed_guest_report
import lan_agent
import lan_install

class Response(io.BytesIO):
    def __init__(self,data,status=200,headers=None,fail=False):
        super().__init__(data);self.status=status;self.headers=headers or {};self.fail=fail;self.reads=0
    def read(self,size=-1):
        self.reads+=1
        if self.fail and self.reads>1: raise OSError('injected interrupted transfer')
        return super().read(min(size,5) if self.fail else size)

class Opener:
    def __init__(self,responses): self.responses=iter(responses);self.requests=[]
    def open(self,request,timeout): self.requests.append(request);return next(self.responses)

class DownloadTests(unittest.TestCase):
    def entry(self,data): return {'name':'agent.tar.gz','bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    def test_interruption_resumes_then_verifies_before_activation(self):
        data=b'approved agent package, not an actual executable'
        opener=Opener([Response(data,fail=True),Response(data[5:],206,{'Content-Range':f'bytes 5-{len(data)-1}/{len(data)}'})])
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'agent.tar.gz'
            result=lan_install.download(opener,'https://192.0.2.1/asset',target,self.entry(data))
            self.assertTrue(result['resumed']);self.assertEqual(target.read_bytes(),data)
            self.assertEqual(opener.requests[1].get_header('Range'),'bytes=5-')
            self.assertFalse(target.with_suffix('.gz.partial').exists())
    def test_bad_hash_is_not_activated(self):
        data=b'valid';wrong=b'evil!'
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'agent.tar.gz'
            with self.assertRaisesRegex(ValueError,'integrity'):
                lan_install.download(Opener([Response(wrong)]),'https://192.0.2.1/asset',target,self.entry(data))
            self.assertFalse(target.exists())
    def test_resume_response_wrong_offset_is_rejected(self):
        data=b'0123456789'
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'agent.tar.gz';target.with_suffix('.gz.partial').write_bytes(data[:5])
            opener=Opener([Response(data[5:],206,{'Content-Range':'bytes 4-9/10'})])
            with self.assertRaisesRegex(ValueError,'offset'):
                lan_install.download(opener,'https://192.0.2.1/asset',target,self.entry(data))
            self.assertFalse(target.exists())
    def test_server_ignoring_range_restarts_cleanly(self):
        data=b'0123456789'
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'agent.tar.gz';target.with_suffix('.gz.partial').write_bytes(b'012')
            result=lan_install.download(Opener([Response(data)]),'https://192.0.2.1/asset',target,self.entry(data))
            self.assertEqual(target.read_bytes(),data);self.assertFalse(result['resumed'])
    def test_changed_existing_asset_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'agent.tar.gz';target.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'Existing installed asset'):
                lan_install.download(Opener([]),'https://192.0.2.1/asset',target,self.entry(b'approved'))
    def test_archive_traversal_and_unexpected_program_are_rejected(self):
        for name in ('../escape','/escape','other-program.py'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                archive=Path(tmp)/'agent.tar.gz'
                with tarfile.open(archive,'w:gz') as tar:
                    item=tarfile.TarInfo(name);item.size=4;tar.addfile(item,io.BytesIO(b'evil'))
                with self.assertRaises(ValueError): lan_install.unpack(archive,Path(tmp)/'installed','agent')
                self.assertFalse((Path(tmp)/'escape').exists())
    def test_bootstrap_cannot_select_other_address_or_identity(self):
        for cfg in ({'identity':'other','mother':'https://192.0.2.1:8443'},
                    {'identity':'sprout-4','mother':'https://example.com'}):
            with self.assertRaisesRegex(ValueError,'preauthorized'): lan_install.install(cfg)
    def test_interrupted_activation_is_not_blindly_replayed(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(lan_install,'BASE',Path(tmp)):
            (Path(tmp)/'enrollment-state.json').write_text(json.dumps({'request_id':'request','manifest_sha256':'pin','phase':'activating'}))
            with self.assertRaisesRegex(ValueError,'reconciliation'):
                lan_install.install({'identity':'sprout-4','mother':'https://192.0.2.1:8443','request_id':'request','manifest_sha256':'pin'})

class FrameTests(unittest.TestCase):
    def test_fragmented_and_coalesced_frames(self):
        frame=b'\x52\x54\x00\x4c\x41\x02'+b'\x52\x54\x00\x4c\x41\x01'+b'\x08\x00payload'
        raw=struct.pack('!I',len(frame))+frame
        decoder=FrameDecoder()
        self.assertEqual(decoder.feed(raw[:2]),[])
        self.assertEqual(decoder.feed(raw[2:]+raw),[frame,frame])
    def test_invalid_sizes_and_input_bounds(self):
        for size in (0,13,65537,2**32-1):
            with self.subTest(size=size),self.assertRaises(ValueError): FrameDecoder().feed(struct.pack('!I',size))
        with self.assertRaises(ValueError): FrameDecoder().feed(b'x'*65537)

class ConsoleRecordTests(unittest.TestCase):
    def test_guest_emits_a_complete_newline_terminated_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'lan-report.json';lan_agent.save(path,{'passed':True})
            self.assertTrue(path.read_bytes().endswith(b'\n'))
            self.assertEqual(completed_guest_report('LAN_REPORT '+path.read_text()),{'passed':True})
    def test_partial_console_record_is_not_a_failed_json_document(self):
        raw='boot ready\nLAN_REPORT {"passed":true,"output":"greeting'
        self.assertIsNone(completed_guest_report(raw))
        self.assertIsNone(completed_guest_report(raw+'"}'))
        self.assertEqual(completed_guest_report(raw+'"}\n'),{'passed':True,'output':'greeting'})
    def test_latest_complete_record_wins_and_bounds_are_enforced(self):
        raw='LAN_REPORT {"sequence":1}\nLAN_REPORT {"sequence":2}\nLAN_REPORT {"partial":'
        self.assertEqual(completed_guest_report(raw),{'sequence':2})
        with self.assertRaises(json.JSONDecodeError): completed_guest_report('LAN_REPORT {malformed}\n')
        with self.assertRaises(ValueError): completed_guest_report('x'*(4*1024**2+1))

class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.node=object.__new__(lan_agent.Node)
        self.node.config={'garden':'garden','request_id':'request','grant':'owner-approved-grant'}
        self.node.lock=threading.RLock();self.node.known={};self.node.enrollment=time.monotonic()+10
        self.node.registry_path=Path(self.tmp.name)/'registry.json'
        self.body={'request_id':'request','identity':'sprout-4','certificate':'public fixture','grant':'owner-approved-grant'}
        self.patcher=patch.object(lan_agent,'pin',lambda cert:hashlib.sha256(cert.encode()).hexdigest())
        self.patcher.start();self.addCleanup(self.patcher.stop)
    def test_duplicate_keeps_one_identity_and_changed_identity_is_rejected(self):
        first=self.node.register('192.0.2.4',self.body)
        second=self.node.register('192.0.2.4',self.body)
        self.assertFalse(first['duplicate']);self.assertTrue(second['duplicate'])
        self.assertEqual(len(self.node.known),1)
        with self.assertRaisesRegex(ValueError,'consumed'):
            self.node.register('192.0.2.4',{**self.body,'certificate':'different fixture'})
    def test_target_scope_request_and_grant_enforced(self):
        for address,body in [('192.0.2.5',self.body),('192.0.2.4',{**self.body,'request_id':'other'}),
                             ('192.0.2.4',{**self.body,'grant':'wrong'}),('192.0.2.4',{**self.body,'extra':'field'})]:
            with self.subTest(address=address,body=body),self.assertRaises(ValueError): self.node.register(address,body)
        self.assertFalse(self.node.registry_path.exists())
    def test_enrollment_is_closed_before_mother_decision_and_after_timeout(self):
        for deadline in (None,time.monotonic()-1):
            self.node.enrollment=deadline
            with self.assertRaisesRegex(ValueError,'not open'): self.node.register('192.0.2.4',self.body)
        self.assertFalse(self.node.known)
    def test_download_admission_does_not_consume_identity(self):
        body={key:self.body[key] for key in ('request_id','identity','grant')}
        self.assertEqual(self.node.admit('192.0.2.4',body),{'ok':True,'admitted':True})
        self.assertFalse(self.node.known)
        with self.assertRaises(ValueError): self.node.admit('192.0.2.4',{**body,'grant':'invalid'})

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        from agenticvm import lan_recovery
        self.recovery=lan_recovery
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.run_id=str(uuid4())
        self.folder=self.root/'runtime/lan-enrollment-runs'/self.run_id;self.folder.mkdir(parents=True)
        (self.folder/'owner.json').write_text(json.dumps({'pid':10,'created':'one','executable':'python.exe'}))
        self.patch=patch.object(lan_recovery,'ROOT',self.root);self.patch.start();self.addCleanup(self.patch.stop)
        self.state={10:False,11:True};self.qemu=self.root/'qemu.exe'
        outer=self
        class Process:
            def __init__(self,pid,**kw): self.pid=pid;self.created='one';self.executable=outer.qemu
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def alive(self): return outer.state[self.pid]
            def terminate(self): outer.state[self.pid]=False
            def wait(self,seconds): return not self.alive()
        for obj,name,value in ((lan_recovery,'WindowsProcess',Process),(lan_recovery,'find_qemu',lambda:self.qemu)):
            p=patch.object(obj,name,value);p.start();self.addCleanup(p.stop)
        target=self.folder/'mother';target.mkdir()
        (target/'ownership.json').write_text(json.dumps({'pid':11,'created':'one','executable':str(self.qemu),'uuid':str(uuid4())}))
        (target/'workspace.ext2').write_bytes(b'disposable private fixture')
        private=self.folder/'private';private.mkdir();(private/'mother.key').write_bytes(b'ephemeral fixture')
    def test_aborts_owned_resources_without_replay_and_is_idempotent(self):
        first=self.recovery.recover(self.run_id)
        self.assertTrue(first['passed']);self.assertFalse(first['tasks_replayed'])
        self.assertFalse(self.state[11]);self.assertFalse((self.folder/'mother/workspace.ext2').exists())
        self.assertFalse((self.folder/'private').exists())
        second=self.recovery.recover(self.run_id)
        self.assertTrue(second['duplicate']);self.assertEqual(first['resources'],second['resources'])
    def test_live_owner_is_not_interrupted(self):
        self.state[10]=True
        with self.assertRaisesRegex(RuntimeError,'still running'): self.recovery.recover(self.run_id)
        self.assertTrue(self.state[11]);self.assertTrue((self.folder/'private/mother.key').exists())
    def test_identity_mismatch_is_retained_for_review(self):
        owner=self.folder/'mother/ownership.json';data=json.loads(owner.read_text());data['created']='different';owner.write_text(json.dumps(data))
        result=self.recovery.recover(self.run_id)
        self.assertFalse(result['passed']);self.assertTrue(self.state[11])
        self.assertTrue((self.folder/'mother/workspace.ext2').exists())
        self.assertTrue((self.folder/'private/mother.key').exists())
    def test_run_path_cannot_escape_owned_root(self):
        for value in ('../elsewhere','{'+self.run_id+'}',self.run_id.upper()):
            with self.subTest(value=value),self.assertRaises(ValueError): self.recovery.recover(value)

class RealTLSTests(unittest.TestCase):
    """Real TLS on host loopback; application snapshots are explicit fixtures."""
    def setUp(self):
        from agenticvm.lan_lab import certificate
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.folder=Path(self.tmp.name)
        self.mother=certificate(self.folder,'mother','192.0.2.1')
        self.peer=certificate(self.folder,'offshoot-1','192.0.2.2')
        (self.folder/'identity.pem').write_bytes((self.folder/'offshoot-1.pem').read_bytes())
        (self.folder/'identity.key').write_bytes((self.folder/'offshoot-1.key').read_bytes())
        patcher=patch.object(lan_agent,'BASE',self.folder);patcher.start();self.addCleanup(patcher.stop)
        self.node=object.__new__(lan_agent.Node);self.node.identity='offshoot-1';self.node.lock=threading.RLock()
        self.node.known={'mother':self.mother,'offshoot-1':self.peer};self.node.snapshot=lambda:{'ready':True,'fixture':True}
        self.server=lan_agent.SecureServer(('127.0.0.1',0),lan_agent.Handler);self.server.node=self.node;self.server.control=False
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
    def client(self,identity='mother'):
        ctx=ssl.create_default_context(cadata=self.peer['certificate']);ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        # Host loopback address differs from the real lab-only IP SAN. The
        # endpoint is still pinned exactly; native tests check actual IP SANs.
        ctx.check_hostname=False;ctx.load_cert_chain(self.folder/(identity+'.pem'),self.folder/(identity+'.key'))
        return ctx
    def test_actual_mutual_tls_and_exact_endpoint_pin(self):
        result,tls=lan_agent.request('127.0.0.1',self.server.server_port,'/status',self.client(),expected=self.peer['sha256'],timeout=3)
        self.assertTrue(result['ready']);self.assertEqual(tls['version'],'TLSv1.3')
        with self.assertRaisesRegex(ValueError,'Pinned TLS'):
            lan_agent.request('127.0.0.1',self.server.server_port,'/status',self.client(),expected='0'*64,timeout=3)
    def test_uri_identity_cannot_be_relabelled_after_ca_trust(self):
        from agenticvm.lan_lab import certificate
        outsider=certificate(self.folder,'outsider','192.0.2.1')
        self.node.known['mother']=outsider
        with self.assertRaisesRegex(ValueError,'rejected: 403'):
            lan_agent.request('127.0.0.1',self.server.server_port,'/status',self.client('outsider'),expected=self.peer['sha256'],timeout=3)

if __name__=='__main__': unittest.main()
