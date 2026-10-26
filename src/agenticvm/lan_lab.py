"""Owned, isolated four-agent LAN acceptance; preauthorized SSH, no exploit.

No physical adapter, external address, network discovery or recursive installer
is accepted. A bounded Ethernet switch joins only this run's QEMU processes.
"""
from __future__ import annotations
import gzip,hashlib,io,json,os,secrets,socket,stat,struct,subprocess,sys,tarfile,threading,time
from pathlib import Path
from uuid import uuid4
from .ext2 import Node,build_ext2,read_image_file
from .qemu import WindowsProcess,find_qemu
from .resources import check_memory_budget,whpx_status
from .peers import Journal,verify_journal

ROOT=Path(__file__).resolve().parents[2]
MODEL_SHA='7e6f72643caafc9a68256686638c4d7916f2cec76d1df478d4c3ddcd95a6aed4'
LLAMA_SHA='05e4fb108c568a8717ef146e86edaee753dabe1f2713c33ea7cb380c74d63cc7'
GOMP_SHA='6456b504ac347bd50c419667440b691f6966ad8aff5309d2f06c977fe2f9debe'
NAMES=('mother','offshoot-1','offshoot-2','sprout-4','negative-control')
class ExpectedDenial(Exception):
    """A deliberately invalid enrollment was refused by the running guests."""
OPENSSL=Path(r'C:\Program Files\Git\usr\bin\openssl.exe')
SSH_KEYGEN=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/OpenSSH/ssh-keygen.exe'

def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()
def save(path,value):
    with path.open('x',encoding='utf-8') as stream: json.dump(value,stream,indent=2);stream.write('\n')
def mac(member): return bytes((0x52,0x54,0,0x4c,0x41,member))

def completed_guest_report(data):
    """Only newline-terminated console records are eligible for decoding."""
    if len(data)>4*1024**2: raise ValueError('Guest console exceeds its observation bound')
    for line in reversed(data.split('\n')[:-1]):
        if line.startswith('LAN_REPORT '): return json.loads(line.removeprefix('LAN_REPORT '))
    return None

class FrameDecoder:
    def __init__(self): self.buffer=bytearray()
    def feed(self,data):
        if len(data)>65536 or len(self.buffer)+len(data)>131076: raise ValueError('Ethernet stream buffer exceeded')
        self.buffer.extend(data);result=[]
        while len(self.buffer)>=4:
            size=struct.unpack('!I',self.buffer[:4])[0]
            if not 14<=size<=65536: raise ValueError('Invalid Ethernet frame length')
            if len(self.buffer)<size+4: break
            result.append(bytes(self.buffer[4:4+size]));del self.buffer[:4+size]
        return result

class Switch:
    """L2 transport only. No IP stack, command API or guest filesystem access."""
    def __init__(self):
        self.lock=threading.RLock();self.stop=threading.Event();self.ports={};self.listeners=[]
        self.errors=[];self.stats={};self.prefix=bytearray()
    def listen(self,member):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(.5)
        self.listeners.append(listener)
        threading.Thread(target=self._serve,args=(member,listener),daemon=True).start()
        return listener.getsockname()[1]
    def _serve(self,member,listener):
        conn=None
        try:
            while not self.stop.is_set():
                try: conn,_=listener.accept();break
                except socket.timeout: continue
            if conn is None: return
            conn.settimeout(.5);writer=threading.Lock()
            with self.lock: self.ports[member]=(conn,writer)
            decoder=FrameDecoder()
            while not self.stop.is_set():
                try: data=conn.recv(65536)
                except socket.timeout: continue
                if not data: return
                for frame in decoder.feed(data):
                    if frame[6:12]!=mac(member): raise ValueError('Unassigned Ethernet source')
                    destination=next((n for n in range(1,6) if frame[:6]==mac(n)),None)
                    with self.lock:
                        targets=[(n,pair) for n,pair in self.ports.items() if n!=member and (destination is None or n==destination)]
                        for n,_ in targets:
                            key=f'{member}->{n}';self.stats[key]=self.stats.get(key,0)+len(frame)
                        if len(self.prefix)<4*1024**2: self.prefix.extend(frame[:4*1024**2-len(self.prefix)])
                    packet=struct.pack('!I',len(frame))+frame
                    for n,(peer,guard) in targets:
                        with guard: peer.sendall(packet)
        except OSError as error:
            if not self.stop.is_set(): self.errors.append(type(error).__name__+': '+str(error))
        except Exception as error: self.errors.append(type(error).__name__+': '+str(error))
        finally:
            with self.lock: self.ports.pop(member,None)
            if conn: conn.close()
    def close(self):
        self.stop.set()
        for listener in self.listeners: listener.close()
        with self.lock: peers=list(self.ports.values())
        for peer,_ in peers:
            try: peer.shutdown(socket.SHUT_RDWR)
            except OSError: pass

class LabVM:
    def __init__(self,folder,member,switch,base,qemu,memory):
        self.folder=folder;folder.mkdir();self.member=member;self.base=base;self.qemu=qemu
        self.memory=memory;self.uuid=str(uuid4());self.process=None;self.binding=None
        self.port=switch.listen(member);self.disk=folder/'workspace.ext2'
    def start(self):
        def value(path): return str(path).replace(',',',,')
        argv=[str(self.qemu),'-L',str(self.qemu.parent/'share'),'-name','Garden-LAN-'+self.uuid,
            '-uuid',self.uuid,'-machine','q35','-accel','whpx','-m',str(self.memory),'-smp','1',
            '-nodefaults','-display','none','-monitor','none','-no-reboot',
            '-cdrom',str(ROOT/self.base['iso']['path']),'-boot','order=d,menu=off',
            '-drive',f'file={value(ROOT/self.base["root"]["path"])},format=raw,if=virtio,readonly=on',
            '-drive',f'file={value(self.disk)},format=raw,if=virtio',
            '-chardev','file,id=boot,path='+value(self.folder/'boot.log'),'-device','isa-serial,index=1,chardev=boot',
            '-netdev',f'socket,id=lan,connect=127.0.0.1:{self.port}',
            '-device','e1000,netdev=lan,romfile=,mac='+':'.join(f'{n:02x}' for n in mac(self.member))]
        save(self.folder/'launch.json',{'argv':argv,'uuid':self.uuid,'guest_control_channel':False,'memory_mib':self.memory})
        with (self.folder/'stdout.log').open('wb') as out,(self.folder/'stderr.log').open('wb') as err:
            self.process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)
        with WindowsProcess(self.process.pid) as process:
            if not process.alive() or process.executable!=self.qemu: raise RuntimeError('Owned QEMU did not start')
            self.binding={'pid':self.process.pid,'created':process.created,'executable':str(process.executable),'uuid':self.uuid}
        save(self.folder/'ownership.json',self.binding)
    def stop(self):
        if self.process and self.process.poll() is None:
            with WindowsProcess(self.binding['pid'],terminate=True) as process:
                if process.alive():
                    if process.created!=self.binding['created'] or process.executable!=self.qemu: raise RuntimeError('VM ownership mismatch')
                    process.terminate()
            self.process.wait(10)

def certificate(folder,name,address):
    key=folder/(name+'.key');pem=folder/(name+'.pem')
    result=subprocess.run([str(OPENSSL),'req','-x509','-newkey','ed25519','-nodes','-days','1',
        '-keyout',str(key),'-out',str(pem),'-subj','/CN='+name,
        '-addext',f'subjectAltName=URI:urn:agenticvm:lan:{name},IP:{address}',
        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,digitalSignature,keyCertSign,cRLSign'],
        capture_output=True,timeout=15)
    if result.returncode: raise RuntimeError('Lab identity generation failed')
    import ssl
    text=pem.read_text()
    return {'identity':name,'address':address,'certificate':text,'sha256':hashlib.sha256(ssl.PEM_cert_to_DER_cert(text)).hexdigest()}

def tar_agent():
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
        for name in ('lan_agent.py','local_lfm.py'):
            data=(ROOT/'guest'/name).read_bytes().replace(b'\r\n',b'\n')
            item=tarfile.TarInfo(name);item.size=len(data);item.mode=0o500;item.mtime=0
            archive.addfile(item,io.BytesIO(data))
    return buffer.getvalue()

def asset_inputs():
    paths={'model.gguf':ROOT/'runtime/local-model-test/downloads/LFM2.5-350M-Q4_K_M.gguf',
           'llama.tar.gz':ROOT/'runtime/local-model-test/downloads/llama-b11711-bin-ubuntu-x64.tar.gz',
           'libgomp.so.1':ROOT/'runtime/local-model-test/dependencies/libgomp.so.1'}
    for name,expected in zip(paths,(MODEL_SHA,LLAMA_SHA,GOMP_SHA)):
        if digest(paths[name])!=expected: raise ValueError('Pinned local inference asset changed: '+name)
    return paths

def prepare_disk(vm,private,public,config,assets,package,manifest,host_public):
    nodes={'':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000)}
    def add(name,data,mode=0o600,uid=1000): nodes[name]=Node(stat.S_IFREG|mode,data,uid,uid)
    add('lab-address',f'192.0.2.{vm.member}\n'.encode())
    if vm.member==4 and config.get('test_case')!='ssh-unavailable':
        add('ssh_host_key',private/'ssh_host_key',0o600,0)
        add('authorized_keys',b'restrict '+host_public)
        add('sshd_config',b'''Port 2222
ListenAddress 192.0.2.4
HostKey /workspace/ssh_host_key
PidFile /workspace/sshd.pid
AuthorizedKeysFile /workspace/authorized_keys
StrictModes yes
AllowUsers garden
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
UsePAM no
PermitEmptyPasswords no
DisableForwarding yes
PermitTTY no
MaxAuthTries 1
MaxSessions 2
MaxStartups 2
LogLevel VERBOSE
''',0o600,0)
    if vm.member<=3:
        name=NAMES[vm.member-1]
        add('identity.key',private/(name+'.key'));add('identity.pem',public[name]['certificate'].encode())
        add('lan-config.json',encoded(config))
        add('peer/lan_agent.py',ROOT/'guest/lan_agent.py');add('peer/local_lfm.py',ROOT/'guest/local_lfm.py')
        delegated=config.get('workflow')=='delegated-v2'
        if delegated:
            add('peer/delegated_agent.py',ROOT/'guest/delegated_agent.py')
            add('peer/bounded_torrent.py',ROOT/'src/agenticvm/bounded_torrent.py')
        add('model.gguf',assets['model.gguf'],0o400);add('dependencies/libgomp.so.1',assets['libgomp.so.1'],0o400)
        with tarfile.open(assets['llama.tar.gz']) as archive:
            for member in archive:
                path=Path(member.name)
                if member.name.startswith('/') or '..' in path.parts or member.size>32*1024**2: raise ValueError('Unsafe inference archive')
                target='llama/'+member.name
                if member.isfile(): add(target,archive.extractfile(member).read(),member.mode&0o755)
                elif member.issym() and '/' not in member.linkname:
                    nodes[target]=Node(stat.S_IFLNK|0o777,member.linkname.encode(),1000,1000)
                elif not member.isdir(): raise ValueError('Unexpected inference tar type')
        add('lab/start.sh',b'#!/bin/sh\nexec /usr/bin/python3 -I /workspace/peer/lan_agent.py\n',0o500)
        if delegated:
            add('lab/start.sh',b'#!/bin/sh\nexec /usr/bin/python3 -I /workspace/peer/delegated_agent.py\n',0o500)
        if vm.member==(2 if delegated else 1):
            add('lab/enroll_key',private/'enroll_key')
            target_pub=(private/'ssh_host_key.pub').read_text().strip().split()
            add('lab/known_hosts',('[192.0.2.4]:2222 '+target_pub[0]+' '+target_pub[1]+'\n').encode())
            add('lab/lan_install.py',ROOT/'guest/lan_install.py')
        if vm.member==1:
            add('lab/manifest.json',encoded(manifest))
            add('lab/assets/agent.tar.gz',package);add('lab/assets/llama.tar.gz',assets['llama.tar.gz'],0o400)
    # The writer creates missing parents as root-owned; application ledgers,
    # model logs and activation need writable directories owned by the guest.
    for name in list(nodes):
        for parent in Path(name).parents:
            if parent.as_posix()!='.':
                nodes.setdefault(parent.as_posix(),Node(stat.S_IFDIR|0o700,uid=1000,gid=1000))
    build_ext2(vm.disk,nodes,size_mib=512 if vm.member<=4 else 128,label='GARDEN_LAN_DATA')
    inventory={name:{'mode':node.mode,'uid':node.uid,'bytes':node.size} for name,node in nodes.items()}
    save(vm.folder/'initial-inventory.json',{'member':vm.member,'files':inventory,'disk_sha256':digest(vm.disk)})
    if vm.member>=4:
        for name in ('peer/lan_agent.py','peer/local_lfm.py','model.gguf','lan-config.json','lab/start.sh'):
            try: read_image_file(vm.disk,name)
            except FileNotFoundError: pass
            else: raise ValueError('Fresh target contains agent software')

def reconcile(statuses):
    """Match ten real model calls to both ends of five directed exchanges."""
    calls={};messages={};pairs=[]
    for name,status in statuses.items():
        model=status['model']
        if not (status['ready'] and not status['error'] and model['server_alive'] and model['weights_verified_inside_vm'] and model['weights_sha256']==MODEL_SHA):
            raise ValueError('A real guest model is not ready')
        if status['interfaces']!=['eth0','lo'] or status['dns'].strip(): raise ValueError('Unexpected guest network')
        if len(status['routes'].splitlines())!=2: raise ValueError('A guest has an unexpected route')
        for row in status['calls']:
            proof=row['proof'];ident=row['id']
            if row['state']!='ready' or ident in calls or proof['call_id']!=ident: raise ValueError('Missing/duplicate model completion')
            if (json.loads(proof['raw_content'])!={'text':proof['text']} or proof['text_sha256']!=hashlib.sha256(proof['text'].encode()).hexdigest() or
                proof['prompt_sha256']!=hashlib.sha256(proof['prompt'].encode()).hexdigest() or proof['completion_tokens']<1):
                raise ValueError('Invalid model provenance')
            calls[ident]=proof
        for entry in status['delivered']:
            hello,reply=entry['hello'],entry['reply'];peer=hello['to']
            if hello['from']!=name or reply['from']!=peer or reply['to']!=name or reply['reply_to']!=hello['id']:
                raise ValueError('Wrong application receipt routing')
            if hello not in statuses[peer]['received']: raise ValueError('Recipient has no matching greeting')
            for body in (hello,reply):
                if body['id'] in messages: raise ValueError('Duplicate delivered model message')
                messages[body['id']]=body
            pairs.append((name,peer))
    expected={('mother','offshoot-1'),('mother','offshoot-2'),('mother','sprout-4'),('sprout-4','offshoot-1'),('sprout-4','offshoot-2')}
    if set(pairs)!=expected or len(calls)!=10 or set(calls)!=set(messages): raise ValueError('Five exchanges and ten completions required')
    for ident,body in messages.items():
        proof=calls[ident]
        if body['text']!=proof['text'] or body['model']['completion_tokens']!=proof['completion_tokens'] or body['model']['weights_sha256']!=MODEL_SHA:
            raise ValueError('Delivered content differs from actual completion')
        if body['kind']=='reply':
            source=messages[body['reply_to']]
            if proof['source_message_id']!=source['id'] or json.dumps(source['text']) not in proof['prompt']:
                raise ValueError('Reply was not generated from actual received input')
    return {'actual_model_completions':10,'completed_model_exchanges':5,'all_ten_completions_delivered_and_correlated':True,
            'generated_tokens':sum(row['completion_tokens'] for row in calls.values()),
            'response_examples':sorted(set(row['text'] for row in calls.values()))}

def run(case='happy',*,delegated=False,contact_seconds=30):
    from .chain import exclusive
    parent=ROOT/('runtime/delegated-enrollment-runs' if delegated else 'runtime/lan-enrollment-runs');parent.mkdir(parents=True,exist_ok=True)
    with exclusive(parent):
        for prior in parent.iterdir():
            if not prior.is_dir(): continue
            if (prior/'owner.json').exists() and not (prior/'recovery.json').exists():
                result=json.loads((prior/'report.json').read_text()) if (prior/'report.json').exists() else None
                if result is None or result.get('cleanup_failures'):
                    raise RuntimeError('Prior LAN lab requires explicit ownership recovery: '+prior.name)
        return _run(case,delegated=delegated,contact_seconds=contact_seconds)

def _run(case='happy',*,delegated=False,contact_seconds=30):
    if case not in ('happy','resume','bad-hash','wrong-grant','ssh-unavailable'): raise ValueError('Unapproved lab case')
    if type(contact_seconds) is not int or not 10<=contact_seconds<=120: raise ValueError('Contact window must be 10..120 seconds')
    if os.name!='nt' or not whpx_status()['available']: raise RuntimeError('Windows WHPX is required; no feature changes are made')
    base=json.loads((ROOT/'runtime/linux-lan-base-v3/build-manifest.json').read_text())
    for key in ('root','iso','package_lock','boot_profile'):
        if digest(ROOT/base[key]['path'])!=base[key]['sha256']: raise ValueError('LAN base/source changed: '+key)
    memory=check_memory_budget(4*512+128)
    folder=ROOT/('runtime/delegated-enrollment-runs' if delegated else 'runtime/lan-enrollment-runs')/str(uuid4());folder.mkdir(parents=True)
    private=folder/'private';private.mkdir()
    with WindowsProcess(os.getpid()) as owner:
        save(folder/'owner.json',{'pid':os.getpid(),'created':owner.created,'executable':str(owner.executable)})
    journal=Journal(folder,folder.name);switch=Switch();machines=[];cleanup=[];report={'passed':False,'run_id':folder.name}
    started=time.monotonic();expected_denial=case in ('bad-hash','wrong-grant','ssh-unavailable')
    report['case']=case
    report['base_manifest_sha256']=digest(ROOT/'runtime/linux-lan-base-v3/build-manifest.json')
    report['source_sha256']={name:digest(ROOT/'guest'/name) for name in ('lan-init.sh','lan_agent.py','lan_install.py','local_lfm.py')}
    if delegated:
        report['workflow']='delegated-v2'
        report['source_sha256']['delegated_agent.py']=digest(ROOT/'guest/delegated_agent.py')
        report['torrent_source_sha256']=digest(ROOT/'src/agenticvm/bounded_torrent.py')
    try:
        public={name:certificate(private,name,f'192.0.2.{i}') for i,name in enumerate(NAMES[:3],1)}
        for name in ('enroll_key','ssh_host_key'):
            result=subprocess.run([str(SSH_KEYGEN),'-q','-t','ed25519','-N','','-f',str(private/name)],capture_output=True,timeout=10)
            if result.returncode: raise RuntimeError('Ephemeral lab SSH fixture generation failed')
        host_public=(private/'enroll_key.pub').read_bytes()
        assets=asset_inputs();package=tar_agent()
        manifest={'schema':'agenticvm.lan-assets.v1','files':{name:{'bytes':path.stat().st_size,'sha256':digest(path)} for name,path in assets.items()}}
        manifest['files']['agent.tar.gz']={'bytes':len(package),'sha256':hashlib.sha256(package).hexdigest()}
        if delegated:
            from .bounded_torrent import metadata
            package_path=folder/'agent.tar.gz';package_path.write_bytes(package)
            for name,path in {**assets,'agent.tar.gz':package_path}.items():
                manifest['files'][name]['torrent']=metadata(path,name=name)
        if case=='bad-hash': manifest['files']['agent.tar.gz']['sha256']='0'*64
        request_id=str(uuid4());grant=secrets.token_urlsafe(32);qemu=find_qemu()
        print('Preparing isolated LAN case: '+case+'; target has no garden agent/model.',flush=True)
        for i,name in enumerate(NAMES,1):
            machines.append(LabVM(folder/name,i,switch,base,qemu,512 if i<=4 else 128))
        for i,(name,vm) in enumerate(zip(NAMES,machines),1):
            cfg={'identity':name,'garden':folder.name,'mother_certificate':public['mother']['certificate'],'peers':public,'test_case':case}
            if i==1: cfg.update(request_id=request_id,grant=grant,manifest_sha256=hashlib.sha256(encoded(manifest)).hexdigest())
            if delegated:
                cfg.update(workflow='delegated-v2',request_id=request_id,target_uuid=machines[3].uuid,
                    manifest_sha256=hashlib.sha256(encoded(manifest)).hexdigest(),contact_seconds=contact_seconds,
                    bootstrap_sha256=hashlib.sha256((ROOT/'guest/lan_install.py').read_bytes().replace(b'\r\n',b'\n')+b'\0'+
                        (ROOT/'src/agenticvm/bounded_torrent.py').read_bytes().replace(b'\r\n',b'\n')).hexdigest())
            prepare_disk(vm,private,public,cfg,assets,package,manifest,host_public)
        journal.add('prepared',target_uuid=machines[3].uuid,prerequisite='preauthorized key-only SSH',guest_control_channels=False)
        # All fixtures exist before launch. No target file/run API exists.
        for vm in machines: vm.start()
        print('Five owned lab VMs started; observing network-only enrollment.',flush=True)
        journal.add('all_vms_started',ownership=[vm.binding for vm in machines],host_memory=memory)
        deadline=time.monotonic()+660;guest=None
        while time.monotonic()<deadline:
            if switch.errors: raise RuntimeError('Virtual LAN failed: '+str(switch.errors))
            for vm in machines:
                if vm.process.poll() is not None:
                    raise RuntimeError(f'{NAMES[vm.member-1]} exited; inspect '+str(vm.folder/'stderr.log'))
                if delegated and vm.member!=1 and (vm.folder/'boot.log').exists():
                    failure=completed_guest_report((vm.folder/'boot.log').read_text(errors='replace'))
                    if failure is not None and not failure.get('passed'):
                        raise RuntimeError(f'{NAMES[vm.member-1]} failed: '+failure.get('error','Unknown guest failure'))
            path=machines[0].folder/'boot.log'
            if path.exists():
                guest=completed_guest_report(path.read_text(errors='replace'))
            if guest is not None: break
            time.sleep(1)
        if guest is None: raise TimeoutError('Native LAN acceptance exceeded eleven minutes')
        save(folder/'guest-report.json',guest)
        if not guest.get('passed'):
            expected={'bad-hash':'integrity verification failed','wrong-grant':'HTTP Error 403','ssh-unavailable':'Connection refused'}
            if expected_denial and expected[case] in guest.get('error',''):
                report.update(passed=True,expected_installation_denial=True,denial_reason=guest['error'],
                    prepared_target_automatic_enrollment_verified=False,zero_preparation_replication_achieved=False,
                    no_guest_control_channels=True,no_target_post_launch_interventions=True,
                    physical_4gb_host_tested=False,physical_hosts_tested=1)
                journal.add('expected_installation_denial',case=case)
                # Cleanup below also independently checks that no program or
                # model was activated in the refused target.
                raise ExpectedDenial()
            raise RuntimeError('Mother reported failure: '+str(guest.get('error')))
        if expected_denial: raise ValueError('A deliberately invalid enrollment unexpectedly succeeded')
        if guest['garden']!=folder.name: raise ValueError('Receipt belongs to another garden')
        proofs=reconcile(guest['statuses'])
        if case=='resume' and not guest['installed']['downloads'][0]['resumed']:
            raise ValueError('Interrupted native download did not resume')
        if delegated:
            from .delegated_lab import verify_delegation
            report['delegated_enrollment']=verify_delegation(guest,machines[3].uuid)
        target_boot=(machines[3].folder/'boot.log').read_text(errors='replace')
        negative_boot=(machines[4].folder/'boot.log').read_text(errors='replace')
        if 'LAN_AGENT_ABSENT 192.0.2.4' not in target_boot or 'LAN_AGENT_ABSENT 192.0.2.5' not in negative_boot:
            raise ValueError('Agent-free boot evidence missing')
        if 'LAN_BOOT_READY 192.0.2.5' not in negative_boot or 'LAN_REPORT' in negative_boot:
            raise ValueError('Negative control did not remain unchanged')
        if switch.stats.get('1->4',0)<assets['model.gguf'].stat().st_size:
            raise ValueError('LAN bytes cannot account for the target model download')
        messages=[entry['hello']['id'] for status in guest['statuses'].values() for entry in status['delivered']]
        if any(marker.encode() in switch.prefix for marker in messages): raise ValueError('Application ID visible in captured Ethernet prefix')
        report.update(passed=True,**proofs,target_uuid=machines[3].uuid,guest_report_sha256=digest(folder/'guest-report.json'),
            guest_memory_mib=[vm.memory for vm in machines],lan_bytes=dict(switch.stats),
            encrypted_capture_prefix_bytes=len(switch.prefix),plaintext_application_ids_absent_in_bounded_capture=True,
            zero_preparation_replication_achieved=False,prepared_target_automatic_enrollment_verified=True,
            precondition='Key-only SSH with pinned host identity was provisioned before the run',
            mother_policy='one fixed allowlisted lab target; no model-directed installation, scanning or recursion',
            no_guest_control_channels=True,no_target_post_launch_interventions=True,
            no_public_lan_or_internet_connection=True,physical_hosts_tested=1,physical_4gb_host_tested=False,
            idle_encrypted_contact_seconds=guest['idle_contact_seconds'],negative_control_agent_not_installed=True,
            duplicate_request_same_agent_process=True)
        journal.add('enrollment_verified',**proofs,target_uuid=machines[3].uuid)
        # Let every guest's periodic sync complete before stopping owned QEMU.
        time.sleep(4)
    except ExpectedDenial:
        pass
    except Exception as error:
        report['error']={'type':type(error).__name__,'message':str(error)}
        journal.add('validation_failed',error=report['error'])
    finally:
        switch.close()
        for vm in reversed(machines):
            try: vm.stop()
            except Exception as error: cleanup.append({'vm':vm.member,'error':str(error)})
        # Read-only checks run only after exact owned processes have stopped.
        if not cleanup:
            for vm in machines:
                if vm.member==1 and not report['passed']:
                    try:
                        diagnostic=read_image_file(vm.disk,'lan-report.json',maximum=1024**2)
                        (vm.folder/'failed-guest-report.json').write_bytes(diagnostic)
                    except FileNotFoundError: pass
                if vm.member==5 or (expected_denial and vm.member==4):
                    for forbidden in ('model.gguf','peer/lan_agent.py','identity.key'):
                        try: read_image_file(vm.disk,forbidden,maximum=256*1024**2)
                        except FileNotFoundError: pass
                        else: cleanup.append({'member':vm.member,'unexpected_activated_file':forbidden})
                if vm.member==4 and not report['passed']:
                    try:
                        diagnostic=read_image_file(vm.disk,'sshd.log',maximum=128*1024)
                        (vm.folder/'sshd-diagnostic.log').write_bytes(diagnostic)
                    except FileNotFoundError: pass
                # Disposable test disk includes private identities. Remove the
                # exact disk file after evidence capture, never a recursive path.
                if vm.disk.exists(): vm.disk.unlink()
            for path in private.iterdir():
                if path.is_file(): path.unlink()
            private.rmdir()
        report['cleanup_failures']=cleanup;report['all_owned_lab_vms_stopped']=not cleanup
        report['lan_bytes']=dict(switch.stats);report['switch_errors']=list(switch.errors)
        report['disposable_private_disks_removed']=not cleanup
        if cleanup: report['passed']=False
        report['elapsed_seconds']=round(time.monotonic()-started,3)
        journal.add('lab_cleanup',failures=cleanup);journal.close()
        report['checkpoints']=verify_journal(folder/'checkpoints.jsonl')
        save(folder/'report.json',report)
    if report['passed']:
        prefix='delegated-enrollment' if delegated else 'lan-enrollment'
        destination=ROOT/('docs/validation/'+prefix+'-report.json' if case=='happy' else 'docs/validation/'+prefix+'-'+case+'-report.json')
        if destination.exists():
            # Preserve earlier receipts instead of silently replacing a run.
            destination=destination.with_name(prefix+'-report-'+folder.name+'.json')
        save(destination,{**report,'raw_report':str(folder/'report.json'),'raw_report_sha256':digest(folder/'report.json')})
    print(json.dumps({'passed':report['passed'],'report':str(folder/'report.json'),'error':report.get('error'),'elapsed_seconds':report['elapsed_seconds']},indent=2),flush=True)
    return 0 if report['passed'] else 1
