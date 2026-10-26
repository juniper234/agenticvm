"""One-file installation's local garden: two seeds, then one joining sprout.

Host administration enrolls public certificates and observes status. All agent
messages travel as end-to-end TLS ciphertext through the blind serial router.
This version deliberately caps the garden at three VMs and never spreads.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import threading
import time
from uuid import UUID,uuid4

from .chain import exclusive
from .ext2 import Node,build_ext2,read_image_file
from .garden_wire import Decoder,MAX_CHUNK,packet
from .peers import Runner,VM,verify_journal
from .qemu import QemuBackend,WindowsProcess
from .state import StateStore
from .transport import SocketTransport

ROOT = Path(__file__).resolve().parents[2]
PURPOSE = 'garden sprout enrollment v1'


def save(path,value):
    temporary = path.with_name(path.name+'.tmp')
    with temporary.open('w',encoding='utf-8') as stream:
        stream.write(json.dumps(value,indent=2,ensure_ascii=True)+'\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def plain(path):
    path = path.absolute()
    if any(p.is_symlink() or getattr(p,'is_junction',lambda:False)() for p in (path,*path.parents)):
        raise ValueError('Redirected garden paths are refused')
    return path


class Router:
    def __init__(self):
        self.lock = threading.Lock()
        self.peers = {}
        self.stopped = threading.Event()
        self.errors = []
        self.bytes = {}
        self.prefix = bytearray()

    def add(self,member,vm):
        store = StateStore(vm.workspace)
        state = store.load()
        with QemuBackend(store,Path(state['executable']))._process(state) as process:
            if not process.alive():
                raise ConnectionError('Garden VM is not alive')
            sock = SocketTransport(state['peer_socket'],3).socket
        sock.settimeout(.25)
        writer = threading.Lock()
        thread = threading.Thread(target=self._read,args=(member,sock),name='garden-router-'+str(member),daemon=True)
        with self.lock:
            if member in self.peers:
                sock.close()
                raise ValueError('Member already routed')
            self.peers[member] = (sock,writer,thread)
        thread.start()

    def _read(self,member,sock):
        decoder = Decoder()
        try:
            while not self.stopped.is_set():
                try:
                    data = sock.recv(MAX_CHUNK)
                except socket.timeout:
                    continue
                if not data:
                    raise ConnectionError('Owned VM serial channel closed')
                for destination,content in decoder.feed(data):
                    with self.lock:
                        target = self.peers.get(destination)
                        key = str(member)+'->'+str(destination)
                        self.bytes[key] = self.bytes.get(key,0)+len(content)
                        if len(self.prefix)<1024*1024:
                            self.prefix.extend(content[:1024*1024-len(self.prefix)])
                    if destination == member or target is None:
                        raise ValueError('Unenrolled garden routing destination')
                    remote,writer,_ = target
                    with writer:
                        remote.sendall(packet(member,content))
        except Exception as error:
            if not self.stopped.is_set():
                self.errors.append({'member':member,'class':type(error).__name__,'message':str(error)[:200]})
                self.stopped.set()

    def close(self):
        self.stopped.set()
        for sock,_,_ in tuple(self.peers.values()):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        for _,_,thread in tuple(self.peers.values()):
            thread.join(2)


def guest_status(vm):
    return json.loads(vm.run('/usr/bin/python3','-I','-c',
        "import pathlib;print(pathlib.Path('/workspace/peer/garden-status.json').read_text())"))


def inspect_status(snapshots,identities,members,*,require_model=False):
    """Require application validation, durable ACKs and pinned TLS on all edges."""
    for member in members:
        status = snapshots[str(member)]
        sequence = status.get('heartbeat_sequence',0)
        if (status.get('errors') or status.get('wire_error') or status['interfaces'] != ['lo'] or
                status.get('running') is not True or type(sequence) is not int or sequence < 1):
            return False
        if require_model:
            from .garden_model import MODEL_NAME,MODEL_SHA
            model = status.get('model',{}).get('server',{})
            if (status.get('model_inference') is not True or not model.get('ready') or not model.get('server_alive') or
                    not model.get('weights_verified_inside_vm') or model.get('name')!=MODEL_NAME or
                    model.get('weights_sha256')!=MODEL_SHA or status['model'].get('error')):
                return False
        for other in members:
            if member == other:
                continue
            edge = status['links'].get(str(other),{})
            tls = edge.get('tls',{})
            counts = edge.get('state',{})
            minimum = 2 if require_model else 5
            if not (edge.get('connected') and edge.get('received_verified',0)>=minimum and
                    min(counts.get(k,0) for k in ('sent','received','acked'))>=minimum and
                    tls.get('tls') == 'TLSv1.3' and tls.get('alpn') == ('agenticvm-garden-lfm/1' if require_model else 'agenticvm-garden/1') and
                    tls.get('peer_cert_sha256') == identities[other]['sha256']):
                return False
            if require_model:
                app = edge.get('application',{})
                if app.get('generated_count',0)<2 or app.get('received_hello',0)<1 or app.get('received_reply',0)<1:
                    return False
    return True


class HealthTracker:
    """Detect frozen/rolled-back guest status without comparing VM clocks."""
    def __init__(self):
        self.observed = {}

    def observe(self,snapshots,*,now=None):
        now = time.monotonic() if now is None else now
        for member,status in snapshots.items():
            sequence = status.get('heartbeat_sequence')
            if type(sequence) is not int or sequence < 1 or status.get('running') is not True:
                return False
            previous,changed = self.observed.get(member,(0,now))
            if sequence < previous:
                return False
            if sequence > previous:
                changed = now
            if now-changed >= 10:
                return False
            self.observed[member] = sequence,changed
        return True


def original_pair_continued(before,after,*,lfm=False):
    for left,right in (('1','2'),('2','1')):
        old,new = before[left]['links'][right],after[left]['links'][right]
        if not new['connected'] or new['connections']!=old['connections']:
            return False
        if lfm:
            # Model conversations intentionally become idle after their two
            # introductions. Live encrypted ping/pong, not extra model text,
            # demonstrates the original connection survived enrollment.
            activity = lambda e:sum(e.get('events',{}).get(k,0) for k in ('heartbeat_acknowledged','heartbeat_received'))
            if activity(new)<=activity(old):
                return False
        elif new['state']['received']<=old['state']['received']:
            return False
    return True


def cleanup(runner,machines):
    failures = []
    for member,vm in machines.items():
        try:
            state = StateStore(vm.workspace).load(required=False)
            if not state or not state['registered']:
                continue
            for job in vm.jobs:
                try:
                    vm.cli('cancel',job)
                except Exception:
                    pass
            vm.run('/usr/bin/python3','-I','-c',
                "import pathlib,os;p=pathlib.Path('/workspace/peer/live.key');p.unlink(missing_ok=True);os.sync();assert not p.exists()")
            vm.stop()
            try:
                read_image_file(vm.workspace/'data/default.ext2','peer/live.key')
                raise RuntimeError('Disposable garden key remains')
            except FileNotFoundError:
                pass
        except Exception as error:
            failures.append({'member':member,'class':type(error).__name__,'message':str(error)[:250]})
    failures.extend(runner.cleanup())
    return failures


def run(*,seed_only=False,lfm=False):
    base = plain(ROOT/'runtime/gardens')
    base.mkdir(parents=True,exist_ok=True,mode=0o700)
    # The OS lock is authoritative, not a stale PID in a JSON file. Another
    # launch can request this fixed third sprout, but cannot create duplicates.
    try:
        guard = exclusive(base)
        guard.__enter__()
    except RuntimeError:
        active = json.loads((base/'active.json').read_text())
        garden = str(UUID(active['garden']))
        folder = plain(base/garden)
        with WindowsProcess(active['pid']) as process:
            if not process.alive() or process.created != active['created'] or process.executable != Path(active['executable']).resolve():
                raise RuntimeError('The active garden owner could not be verified')
        if not (folder/'JOIN').exists():
            (folder/'JOIN').write_text('sprout-3\n')
        end = time.monotonic()+(600 if lfm else 180)
        while time.monotonic()<end:
            path = folder/'join-report.json'
            if path.exists():
                report = json.loads(path.read_text())
                if not report.get('passed'):
                    raise RuntimeError('Garden join failed; inspect '+str(path))
                if report.get('model_inference') != lfm:
                    raise RuntimeError('This active garden has a different agent profile')
                if lfm:
                    health_path = folder/'health.json'
                    if not health_path.exists() or time.time()-health_path.stat().st_mtime>15:
                        time.sleep(.5)
                        continue
                    identities = {int(k):v for k,v in report['identities'].items()}
                    if not inspect_status(json.loads(health_path.read_text()),identities,(1,2,3),require_model=True):
                        raise RuntimeError('The LFM garden is no longer healthy')
                print('Sprout 3 is in the garden. Encrypted messages verified with both existing sprouts.',flush=True)
                print('Garden: '+str(folder),flush=True)
                return 0
            time.sleep(.5)
        raise TimeoutError('Garden enrollment did not finish within three minutes')
    try:
        # Refuse to overwrite an interrupted garden; recovery is explicit. A
        # stale garden cannot silently be adopted or have its tasks replayed.
        for prior in base.iterdir():
            if prior.is_dir() and (prior/'checkpoints.jsonl').is_file() and not (prior/'stopped.json').is_file():
                raise RuntimeError('An interrupted garden needs recovery: '+str(prior))
        return controller(base,seed_only=seed_only,lfm=lfm)
    finally:
        guard.__exit__(None,None,None)


def controller(base,*,seed_only=False,lfm=False):
    model_folder = model_lock = None
    if lfm:
        from .garden_model import assets
        model_folder,model_lock = assets(ROOT)
    garden = str(uuid4())
    folder = plain(base/garden)
    folder.mkdir(mode=0o700)
    memory_mib = 512 if lfm else 256
    runner = Runner(folder,garden,memory_mib,1)
    runner.journal.add('run_started',purpose=PURPOSE,max_members=3,guest_memory_mib=memory_mib,model_inference=lfm)
    with WindowsProcess(os.getpid()) as process:
        save(base/'active.json',{'garden':garden,'pid':os.getpid(),'created':process.created,'executable':str(process.executable)})
    source = {'garden_agent.py':ROOT/'guest/garden_agent.py','live_agent.py':ROOT/'guest/live_agent.py',
              'peer_agent.py':ROOT/'guest/peer_agent.py','peer_protocol.py':ROOT/'src/agenticvm/peer_protocol.py',
              'live_channel.py':ROOT/'src/agenticvm/live_channel.py','garden_wire.py':ROOT/'src/agenticvm/garden_wire.py'}
    if lfm:
        source.update({'local_lfm.py':ROOT/'guest/local_lfm.py','garden_chat.py':ROOT/'guest/garden_chat.py'})
    router = Router()
    machines,identities,topology = {},{},{}
    started = time.monotonic()
    report = {'passed':False,'garden':garden,'guest_memory_mib':memory_mib,'guest_network':False,'http':False,'usb':False,
              'model_inference':lfm,'physical_hosts_tested':1,'physical_4gb_tested':False,
              'inter_agent_http':False,'local_inference_http':lfm,'model_lock':model_lock,
              'source_sha256':{name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in source.items()}}

    def sprout(member):
        print('Starting sprout '+str(member)+' ('+str(memory_mib)+' MiB Linux'+(', LFM2.5' if lfm else '')+')...',flush=True)
        vm = VM(runner,'sprout-'+str(member))
        machines[member] = vm
        if lfm:
            from .garden_model import prepare_disk
            prepare_disk(vm,source,model_folder)
            vm.start('--persistent','--peer-channel','--image',model_folder/'agenticvm-linux-peer.iso')
        else:
            disk = vm.workspace/'data/default.ext2'
            disk.parent.mkdir(parents=True)
            nodes = {'':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000),'peer':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000)}
            nodes.update({'peer/'+name:Node(stat.S_IFREG|0o600,path,1000,1000) for name,path in source.items()})
            build_ext2(disk,nodes,label='AGENTICVM_DATA')
            vm.start('--persistent','--peer-channel')
        state = StateStore(vm.workspace).load()
        top = json.loads(vm.run('/usr/bin/python3','-I','-c',
            "import json,pathlib,os;print(json.dumps({'uid':os.getuid(),'interfaces':sorted(p.name for p in pathlib.Path('/sys/class/net').iterdir()),'routes':pathlib.Path('/proc/net/route').read_text(),'dns':pathlib.Path('/etc/resolv.conf').read_text(),'mounts':pathlib.Path('/proc/mounts').read_text()}))"))
        if state['network'] != 'none' or top['uid'] != 1000 or top['interfaces'] != ['lo'] or top['dns'].strip() or len(top['routes'].splitlines()) != 1 or any(t in top['mounts'] for t in (' 9p ',' virtiofs ',' cifs ',' nfs ')):
            raise RuntimeError('Garden guest isolation check failed')
        topology[str(member)] = top
        public = json.loads(vm.run('/usr/bin/python3','-I','/workspace/peer/garden_agent.py','--member',str(member),'--initialize'))
        identities[member] = public
        vm.download('peer/live.pem',folder/('sprout-'+str(member)+'.pem'))
        router.add(member,vm)
        runner.journal.add('sprout_installed',member=member,uuid=state['uuid'],public_identity=public)

    def configure():
        for member,vm in machines.items():
            for other in machines:
                if member != other:
                    vm.upload(folder/('sprout-'+str(other)+'.pem'),'peer/sprout-'+str(other)+'.pem')
            config = {'garden':garden,'peers':{str(n):identities[n] for n in machines if n != member}}
            path = folder/('config-'+str(member)+'.json')
            save(path,config)
            vm.upload(path,'peer/garden.next.json')
            vm.run('/bin/mv','/workspace/peer/garden.next.json','/workspace/peer/garden.json')

    def start_agent(member):
        vm = machines[member]
        result = vm.cli('exec','--async','--timeout-ms','0','--','/usr/bin/env','MALLOC_ARENA_MAX=1','/usr/bin/python3','-I',
                        '/workspace/peer/garden_agent.py','--member',str(member),*(['--lfm'] if lfm else []))
        vm.jobs.append(result['job_id'])

    def snapshots():
        return {str(n):guest_status(vm) for n,vm in machines.items()}

    def wait_ready(members):
        end = time.monotonic()+(300 if lfm else 75)
        last = None
        freshness = HealthTracker()
        while time.monotonic()<end:
            if router.errors:
                raise RuntimeError('Garden byte router failed: '+json.dumps(router.errors))
            try:
                last = snapshots()
                if not freshness.observe(last):
                    raise ValueError('A garden agent stopped publishing fresh status')
                if inspect_status(last,identities,members,require_model=lfm):
                    return last
                if any(s['errors'] or s['wire_error'] for s in last.values()):
                    raise ValueError('Guest rejected garden: '+json.dumps(last)[:3000])
            except RuntimeError as error:
                # A just-started guest may not have written its first status.
                if 'No such file' not in str(error):
                    raise
            time.sleep(.5)
        save(folder/'last-status.json',last)
        raise TimeoutError('Garden peers did not pass authentication/application checks')

    try:
        print('Garden: '+garden+'\nCtrl+C stops this garden.',flush=True)
        sprout(1)
        sprout(2)
        configure()
        start_agent(1)
        start_agent(2)
        before = wait_ready((1,2))
        save(folder/'seed-status.json',before)
        runner.journal.add('two_sprout_garden_verified',members=2,all_directions_acked=True)
        print('Two sprouts are communicating. The garden is ready.',flush=True)
        if seed_only:
            while not (folder/'JOIN').exists():
                if (folder/'STOP').exists():
                    raise KeyboardInterrupt()
                time.sleep(.25)
        runner.journal.add('new_sprout_requested',member=3,installation_entry='Sprout.exe')
        sprout(3)
        # Existing agents reload enrollment in place; neither seed process nor
        # its already-established TLS session is restarted to add the third.
        configure()
        start_agent(3)
        after = wait_ready((1,2,3))
        seed_continued = original_pair_continued(before,after,lfm=lfm)
        checks = {'three_real_vms_running':all(vm.cli('status')['status']=='running' for vm in machines.values()),
                  'six_directions_authenticated_delivered_verified_acked':inspect_status(after,identities,(1,2,3),require_model=lfm),
                  'original_pair_continued_without_tls_restart':seed_continued,
                  'independent_guest_generated_keys':len({i['sha256'] for i in identities.values()})==3,
                  'router_has_no_endpoint_private_keys':not list(folder.glob('*.key')),
                  'payload_marker_absent_from_router_ciphertext':b'Hello from the garden' not in router.prefix,
                  'router_forwarded_all_six_directions':len(router.bytes)==6 and all(router.bytes.values()),
                  'guest_isolation_checked':len(topology)==3,
                  'profile_address_space_limit_matches':all(s['address_space_limit_bytes']==(2048 if lfm else 128)*1024**2 for s in after.values()),
                  'bounded_thread_stacks_and_single_allocator_arena':all(s['thread_stack_bytes']==256*1024 and s['allocator_arena_max']==1 for s in after.values())}
        if lfm:
            from .garden_model import verify_conversation
            checks.update(verify_conversation(after))
        report.update(passed=all(checks.values()),checks=checks,before=before,after=after,topology=topology,
                      identities={str(k):v for k,v in identities.items()},router_bytes=router.bytes,
                      seconds_to_join=round(time.monotonic()-started,3),seed_agents_restarted=False)
        runner.journal.add('sprout_join_verified',member=3,passed=report['passed'],checks=checks)
        report['checkpoints'] = verify_journal(folder/'checkpoints.jsonl')
        save(folder/'join-report.json',report)
        save(base/'last-join.json',{'garden':garden,'passed':report['passed'],'report':str(folder/'join-report.json')})
        if not report['passed']:
            raise RuntimeError('Sprout enrollment validation failed')
        print('Sprout 3 joined the garden. Encrypted messages verified with both existing sprouts.',flush=True)
        print('All three remain connected. Ctrl+C stops this garden.\nEvidence: '+str(folder/'join-report.json'),flush=True)
        freshness = HealthTracker()
        freshness.observe(after)
        next_check = time.monotonic()+2
        while not (folder/'STOP').exists():
            if router.errors:
                raise RuntimeError('Garden serial link failed: '+json.dumps(router.errors))
            if time.monotonic()>=next_check:
                current = snapshots()
                save(folder/'health.json',current)
                if not freshness.observe(current) or not inspect_status(current,identities,(1,2,3),require_model=lfm):
                    raise RuntimeError('Garden contact no longer healthy')
                next_check = time.monotonic()+5
            time.sleep(.25)
    except KeyboardInterrupt:
        report['stop_requested'] = True
    except Exception as error:
        report.update(passed=False,error={'class':type(error).__name__,'message':str(error)[:3000]})
        report['job_diagnostics'] = {}
        for member,vm in machines.items():
            for job in vm.jobs:
                try:
                    report['job_diagnostics'][str(member)] = vm.cli('poll',job,'--wait-ms','0')
                except Exception as diagnostic:
                    report['job_diagnostics'][str(member)] = {'error':str(diagnostic)[:250]}
        save(folder/'failure.json',report)
        print('Garden failed: '+str(error),flush=True)
    finally:
        router.close()
        failures = cleanup(runner,machines)
        runner.journal.add('garden_stopped',cleanup_failures=failures,tasks_replayed=False)
        runner.journal.close()
        save(folder/'stopped.json',{'cleanup_failures':failures,'all_owned_vms_stopped':not failures,
                                  'checkpoints':verify_journal(folder/'checkpoints.jsonl')})
        if failures:
            print('Garden cleanup needs attention: '+json.dumps(failures),flush=True)
    return 0 if report['passed'] and not failures else 1


def main(argv=None):
    import signal
    if hasattr(signal,'SIGBREAK'):
        signal.signal(signal.SIGBREAK,signal.default_int_handler)
    args = list(sys.argv[1:] if argv is None else argv)
    if any(arg not in ('--seed-only','--lfm') for arg in args) or len(args)!=len(set(args)):
        raise ValueError('Open Sprout.exe to join the local garden')
    os.environ['AGENTICVM_QEMU'] = str(ROOT/'tools/qemu/11.1.0/qemu-system-x86_64.exe')
    return run(seed_only='--seed-only' in args,lfm='--lfm' in args)
