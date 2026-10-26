"""Independent blank VM defaults on an owned virtual LAN. No exploit or target prep."""
from __future__ import annotations
import gzip,hashlib,importlib.util,json,os,socket,stat,struct,subprocess,threading,time
from pathlib import Path
from uuid import uuid4
from .lan_lab import ROOT,Switch,FrameDecoder,LabVM,mac,digest,save,encoded
from .pxe_lab import validated_base
from .ext2 import Node,build_ext2,read_image_file
from .qemu import WindowsProcess,find_qemu
from .resources import check_memory_budget,whpx_status
from .chain import exclusive
from .peers import Journal,verify_journal

FIRMWARE=ROOT/'tools/qemu-stock-firmware/20260811'

def dhcp_event(frame):
    if len(frame)<14+20+8+240 or frame[12:14]!=b'\x08\x00': return None
    ip=frame[14:];ihl=(ip[0]&15)*4
    if ip[0]>>4!=4 or ihl<20 or ip[9]!=17 or len(ip)<ihl+8+240: return None
    udp=ip[ihl:];source,destination=struct.unpack('!HH',udp[:4])
    if (source,destination)!=(68,67): return None
    boot=udp[8:]
    if boot[236:240]!=b'\x63\x82\x53\x63': return None
    cursor=240
    while cursor<len(boot):
        kind=boot[cursor];cursor+=1
        if kind==255: break
        if kind==0: continue
        if cursor>=len(boot): return None
        size=boot[cursor];cursor+=1;value=boot[cursor:cursor+size];cursor+=size
        if len(value)!=size: return None
        if kind==53 and size==1: return {'message_type':value[0],'mac':frame[6:12].hex(':')}
    return None

class LearningSwitch(Switch):
    """L2 learning, at most four owned ports, one unknown client, no IP gateway."""
    def __init__(self):
        super().__init__();self.addresses={n:mac(n) for n in (1,2,3)};self.dhcp=[];self.ingress={}
    def _serve(self,member,listener):
        conn=None
        try:
            while not self.stop.is_set():
                try: conn,_=listener.accept();break
                except socket.timeout: continue
            if conn is None: return
            conn.settimeout(.5)
            with self.lock: self.ports[member]=(conn,threading.Lock())
            decoder=FrameDecoder()
            while not self.stop.is_set():
                try: data=conn.recv(65536)
                except socket.timeout: continue
                if not data: return
                for frame in decoder.feed(data):
                    source=frame[6:12]
                    with self.lock:
                        if member not in self.addresses:
                            if member!=4 or source[0]&1 or source in self.addresses.values(): raise ValueError('Invalid newly learned client')
                            self.addresses[member]=source
                        if self.addresses[member]!=source: raise ValueError('A virtual port changed its hardware identity')
                        self.ingress[member]=self.ingress.get(member,0)+1
                        event=dhcp_event(frame)
                        if event and len(self.dhcp)<128: self.dhcp.append(event)
                        destination=next((n for n,address in self.addresses.items() if address==frame[:6]),None)
                        targets=[pair for n,pair in self.ports.items() if n!=member and (destination is None or n==destination)]
                        for n in self.ports:
                            if n!=member and (destination is None or n==destination):
                                key=f'{member}->{n}';self.stats[key]=self.stats.get(key,0)+len(frame)
                    packet=struct.pack('!I',len(frame))+frame
                    for peer,guard in targets:
                        with guard: peer.sendall(packet)
        except OSError as error:
            if not self.stop.is_set(): self.errors.append(str(error))
        except Exception as error: self.errors.append(type(error).__name__+': '+str(error))
        finally:
            with self.lock: self.ports.pop(member,None)
            if conn: conn.close()

def firmware_manifest():
    path=FIRMWARE/'stock-firmware.json';record=json.loads(path.read_text())
    for name,item in record['files'].items():
        if digest(FIRMWARE/name)!=item['sha256']: raise ValueError('Stock firmware changed: '+name)
    return {'path':str(path),'sha256':digest(path),'files':record['files']}

def default_target_argv(vm,iso=None):
    def escaped(path): return str(path).replace(',',',,')
    # Platform, NIC model/MAC, BIOS, option ROM and boot order are stock defaults.
    # Capacity, isolated cable and output-only observation are explicit lab choices.
    argv=[str(vm.qemu),'-L',str(FIRMWARE),'-name','Independent-'+vm.uuid,'-uuid',vm.uuid,
        '-accel','whpx','-m','768','-display','none','-monitor','none','-no-reboot',
        '-serial','file:'+str(vm.folder/'boot.log'),'-debugcon','file:'+str(vm.folder/'firmware.log'),
        '-global','isa-debugcon.iobase=0x402',
        '-nic',f'socket,connect=127.0.0.1:{vm.port}',
        '-drive','file='+escaped(vm.disk)+',format=raw']
    if iso: argv+=['-cdrom',str(iso)]
    return argv

class IndependentVM(LabVM):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.disk=self.folder/'blank.raw'
    def start(self,iso=None):
        argv=default_target_argv(self,iso)
        save(self.folder/'launch.json',{'argv':argv,'uuid':self.uuid,'boot_order_override':False,
            'firmware_or_rom_override':False,'target_mac_override':False,'garden_files_on_target':False,
            'explicit_lab_choices':['768 MiB capacity','private virtual Ethernet cable','output-only logging'],
            'stock_os_iso':str(iso) if iso else None})
        with (self.folder/'stdout.log').open('wb') as out,(self.folder/'stderr.log').open('wb') as err:
            self.process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)
        with WindowsProcess(self.process.pid) as p:
            if not p.alive() or p.executable!=self.qemu: raise RuntimeError('Independent VM failed to start')
            self.binding={'pid':self.process.pid,'created':p.created,'executable':str(p.executable),'uuid':self.uuid}
        save(self.folder/'ownership.json',self.binding)

def blank_disk(vm):
    with vm.disk.open('xb') as disk: disk.truncate(512*1024**2)
    save(vm.folder/'initial-inventory.json',{'vm_uuid':vm.uuid,'parent_vm':None,'source_snapshot':None,
        'bytes':vm.disk.stat().st_size,'sha256':digest(vm.disk),'all_zero_disk':True,
        'filesystem':None,'files':[],'installed_os':False,'garden_agent':False,'garden_config':False})

def initrd(base,*,probe=True,public=None):
    spec=importlib.util.spec_from_file_location('independent_cpio',ROOT/'scripts/build-linux-probe.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    entries={'init':(stat.S_IFREG|0o755,(ROOT/'guest/independent-ram-init.sh').read_bytes().replace(b'\r\n',b'\n'),0,0)}
    if probe: entries['probe-only']=(stat.S_IFREG|0o644,b'owned private-LAN boot probe\n',0,0)
    else:
        entries['boot-trust.json']=(stat.S_IFREG|0o644,encoded({'mother_certificate':public['mother']['certificate'],
            'installer_sha256':digest(ROOT/'guest/lan_install.py')}),0,0)
        entries['boot-provision.py']=(stat.S_IFREG|0o644,(ROOT/'guest/pxe_bootstrap.py').read_bytes(),0,0)
    return (ROOT/base['ram_root']['path']).read_bytes()+gzip.compress(module.make_newc(entries),mtime=0)

def script():
    return b'#!ipxe\nkernel http://192.0.2.1:8080/vmlinuz console=ttyS0,115200n8 rdinit=/init panic=1\ninitrd http://192.0.2.1:8080/initrd.gz\nboot\n'

def image(path,files):
    nodes={'':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000)}
    for name,(data,mode) in files.items(): nodes[name]=Node(stat.S_IFREG|mode,data,1000,1000)
    for name in list(nodes):
        for parent in Path(name).parents:
            if parent.as_posix()!='.': nodes.setdefault(parent.as_posix(),Node(stat.S_IFDIR|0o700,uid=1000,gid=1000))
    build_ext2(path,nodes,size_mib=512,label='INDEPENDENT_LAB_SERVER')

def probe(server=True):
    if os.name!='nt' or not whpx_status()['available']: raise RuntimeError('WHPX is required')
    base=validated_base();firmware=firmware_manifest();check_memory_budget(1024)
    parent=ROOT/'runtime/independent-vm-runs';parent.mkdir(parents=True,exist_ok=True)
    with exclusive(parent): return _probe(parent,base,firmware,server)

def _probe(parent,base,firmware,server):
    folder=parent/str(uuid4());folder.mkdir();qemu=find_qemu();switch=LearningSwitch();machines=[];begin=time.monotonic()
    with WindowsProcess(os.getpid()) as p: save(folder/'owner.json',{'pid':os.getpid(),'created':p.created,'executable':str(p.executable)})
    journal=Journal(folder,folder.name);report={'passed':False,'run_id':folder.name,'case':'stock-defaults-probe' if server else 'no-server-control',
        'stock_firmware':firmware,'source_sha256':digest(Path(__file__)),'recruitment_achieved':False,
        'arbitrary_running_os_recruitment_achieved':False,'physical_4gb_host_tested':False};cleanup=[]
    try:
        target=IndependentVM(folder/'independent-target',4,switch,base,qemu,768);machines.append(target);blank_disk(target)
        before=digest(target.disk);save(folder/'independent-target/before.json',{'sha256':before})
        if server:
            mother=LabVM(folder/'mother',1,switch,base,qemu,256);machines.append(mother)
            image(mother.disk,{'lab-address':(b'192.0.2.1\n',0o600),'lan-config.json':(b'{}',0o600),
                'pxe-open':(b'one owned lab client\n',0o600),'pxe_server.py':(ROOT/'guest/independent_boot_server.py',0o600),
                'lab/start.sh':(b'#!/bin/sh\nwhile [ ! -f /workspace/pxe-ready ]; do sleep 0.2; done\necho INDEPENDENT_SERVER_READY\nwhile :; do sleep 30; done\n',0o500),
                'pxe/boot.ipxe':(script(),0o600),'pxe/vmlinuz':(ROOT/base['vmlinuz']['path'],0o600),
                'pxe/initrd.gz':(initrd(base),0o600)})
            mother.start();deadline=time.monotonic()+60
            while time.monotonic()<deadline:
                path=mother.folder/'boot.log'
                if path.exists() and 'INDEPENDENT_SERVER_READY' in path.read_text(errors='replace'): break
                if mother.process.poll() is not None: raise RuntimeError('Mother boot server exited')
                time.sleep(.2)
            else: raise TimeoutError('Private boot service did not become ready')
        journal.add('independent_target_created',uuid=target.uuid,disk_sha256=before,garden_configuration=False)
        target.start();journal.add('target_started_with_stock_defaults',ownership=target.binding)
        deadline=time.monotonic()+(90 if server else 45);executed=False
        while time.monotonic()<deadline:
            if target.process.poll() is not None: raise RuntimeError('Independent VM exited; inspect firmware/boot/stderr logs')
            if switch.errors: raise RuntimeError('Virtual LAN failed: '+str(switch.errors))
            path=target.folder/'boot.log'
            if path.exists() and 'INDEPENDENT_DEFAULT_FIRMWARE_EXECUTED_NETWORK_PAYLOAD' in path.read_text(errors='replace'):
                executed=True;break
            time.sleep(.5)
        report.update(default_network_boot_observed=executed,dhcp_client_events=list(switch.dhcp),
            dynamically_learned_mac=switch.addresses.get(4,b'').hex(':'),target_boot_overrides=False)
        report['passed']=executed if server else (not executed and any(row['message_type']==1 for row in switch.dhcp))
        journal.add('observed',network_boot=executed)
    except Exception as error: report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        switch.close()
        for vm in reversed(machines):
            try: vm.stop()
            except Exception as error: cleanup.append(str(error))
        if not cleanup:
            if server and 'mother' in locals() and mother.disk.exists():
                for name in ('pxe-dhcp.log','pxe-server.log','pxe-transfers.json','learned-leases.json'):
                    try: (folder/name).write_bytes(read_image_file(mother.disk,name,maximum=1024**2))
                    except FileNotFoundError: pass
            if 'target' in locals() and target.disk.exists():
                report['blank_disk_unchanged']=digest(target.disk)==before
                if not report['blank_disk_unchanged']: report['passed']=False
            for vm in machines:
                if vm.disk.exists(): vm.disk.unlink()
        if cleanup: report['passed']=False
        report.update(cleanup_failures=cleanup,all_owned_vms_stopped=not cleanup,disposable_disks_removed=not cleanup,
            elapsed_seconds=round(time.monotonic()-begin,3),lan_bytes=dict(switch.stats))
        journal.add('cleanup',failures=cleanup);journal.close();report['checkpoints']=verify_journal(folder/'checkpoints.jsonl')
        save(folder/'report.json',report)
        save(ROOT/'docs/validation'/('independent-probe-'+folder.name+'.json'),report)
    print(json.dumps({'passed':report['passed'],'report':str(folder/'report.json'),'network_boot':report.get('default_network_boot_observed'),'error':report.get('error')},indent=2),flush=True)
    return 0 if report['passed'] else 1

def seed_image(vm,private,public,cfg,assets,package,manifest,ram):
    """Existing mother/offshoot fixtures only. Never called for the new target."""
    import tarfile
    name=('mother','offshoot-1','offshoot-2')[vm.member-1]
    files={'lab-address':(f'192.0.2.{vm.member}\n'.encode(),0o600),
        'identity.key':(private/(name+'.key'),0o600),'identity.pem':(public[name]['certificate'].encode(),0o600),
        'lan-config.json':(encoded(cfg),0o600),'peer/lan_agent.py':(ROOT/'guest/lan_agent.py',0o600),
        'peer/local_lfm.py':(ROOT/'guest/local_lfm.py',0o600),
        'model.gguf':(assets['model.gguf'],0o400),'dependencies/libgomp.so.1':(assets['libgomp.so.1'],0o400)}
    links={}
    with tarfile.open(assets['llama.tar.gz']) as archive:
        for item in archive:
            if item.name.startswith('/') or '..' in Path(item.name).parts or item.size>32*1024**2: raise ValueError('Unsafe inference archive')
            if item.isfile(): files['llama/'+item.name]=(archive.extractfile(item).read(),item.mode&0o755)
            elif item.issym() and '/' not in item.linkname: links['llama/'+item.name]=item.linkname.encode()
            elif not item.isdir(): raise ValueError('Unexpected inference archive member')
    entry='pxe_agent.py' if vm.member==1 else 'lan_agent.py'
    files['lab/start.sh']=(('#!/bin/sh\nexec /usr/bin/python3 -I /workspace/peer/'+entry+'\n').encode(),0o500)
    if vm.member==1:
        files.update({'peer/pxe_agent.py':(ROOT/'guest/pxe_agent.py',0o600),
            'pxe_server.py':(ROOT/'guest/independent_boot_server.py',0o600),
            'lab/manifest.json':(encoded(manifest),0o600),'lab/lan_install.py':(ROOT/'guest/lan_install.py',0o600),
            'lab/assets/agent.tar.gz':(package,0o400),'lab/assets/llama.tar.gz':(assets['llama.tar.gz'],0o400),
            'pxe/boot.ipxe':(script(),0o600),'pxe/vmlinuz':(ROOT/vm.base['vmlinuz']['path'],0o600),'pxe/initrd.gz':(ram,0o600)})
    nodes={'':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000)}
    for path,(data,mode) in files.items(): nodes[path]=Node(stat.S_IFREG|mode,data,1000,1000)
    for path,data in links.items(): nodes[path]=Node(stat.S_IFLNK|0o777,data,1000,1000)
    for path in list(nodes):
        for parent in Path(path).parents:
            if parent.as_posix()!='.': nodes.setdefault(parent.as_posix(),Node(stat.S_IFDIR|0o700,uid=1000,gid=1000))
    build_ext2(vm.disk,nodes,size_mib=512,label='INDEPENDENT_GARDEN_SEED')

def enroll():
    from .lan_lab import certificate,asset_inputs,tar_agent,completed_guest_report,reconcile
    import secrets
    base=validated_base();firmware=firmware_manifest();memory=check_memory_budget(3*512+768)
    parent=ROOT/'runtime/independent-vm-runs';parent.mkdir(parents=True,exist_ok=True)
    with exclusive(parent):
        folder=parent/str(uuid4());folder.mkdir();private=folder/'private';private.mkdir()
        with WindowsProcess(os.getpid()) as p: save(folder/'owner.json',{'pid':os.getpid(),'created':p.created,'executable':str(p.executable)})
        journal=Journal(folder,folder.name);switch=LearningSwitch();machines=[];begin=time.monotonic();cleanup=[]
        report={'schema':'agenticvm.independent-enrollment.v1','passed':False,'run_id':folder.name,'case':'lfm-enrollment',
            'stock_firmware':firmware,'physical_4gb_host_tested':False,'arbitrary_running_os_recruitment_achieved':False,
            'host_source_sha256':digest(Path(__file__)),
            'guest_source_sha256':{name:digest(ROOT/'guest'/name) for name in ('independent_boot_server.py','independent-ram-init.sh','pxe_agent.py','lan_agent.py','lan_install.py','pxe_bootstrap.py','local_lfm.py')}}
        try:
            # The unrelated target is created as a raw blank machine before seeds are prepared.
            target=IndependentVM(folder/'independent-target',4,switch,base,find_qemu(),768);machines.append(target);blank_disk(target)
            before=digest(target.disk)
            public={name:certificate(private,name,f'192.0.2.{i}') for i,name in enumerate(('mother','offshoot-1','offshoot-2'),1)}
            assets=asset_inputs();package=tar_agent();ram=initrd(base,probe=False,public=public)
            manifest={'schema':'agenticvm.lan-assets.v1','files':{name:{'bytes':path.stat().st_size,'sha256':digest(path)} for name,path in assets.items()}}
            manifest['files']['agent.tar.gz']={'bytes':len(package),'sha256':hashlib.sha256(package).hexdigest()}
            request_id=str(uuid4());grant=secrets.token_urlsafe(32);seeds=[]
            for i,name in enumerate(('mother','offshoot-1','offshoot-2'),1):
                cfg={'identity':name,'garden':folder.name,'mother_certificate':public['mother']['certificate'],'peers':public,'test_case':'happy'}
                if i==1: cfg.update(request_id=request_id,grant=grant,manifest_sha256=hashlib.sha256(encoded(manifest)).hexdigest())
                vm=LabVM(folder/name,i,switch,base,find_qemu(),512);machines.append(vm);seeds.append(vm)
                seed_image(vm,private,public,cfg,assets,package,manifest,ram)
            journal.add('prepared',independent_target_uuid=target.uuid,target_disk_sha256=before,host_memory=memory,
                target_garden_configuration=False,target_boot_override=False,target_mac_override=False)
            for vm in seeds: vm.start()
            deadline=time.monotonic()+240
            while time.monotonic()<deadline:
                if switch.errors: raise RuntimeError(str(switch.errors))
                path=seeds[0].folder/'boot.log'
                if path.exists():
                    text=path.read_text(errors='replace')
                    failure=completed_guest_report(text)
                    if failure and not failure.get('passed'): raise RuntimeError(str(failure))
                    if 'PXE_BOOT_SERVICE_READY' in text: break
                time.sleep(.5)
            else: raise TimeoutError('Mother failed to open provisioning')
            target.start();journal.add('independent_target_powered_on',ownership=target.binding)
            print('Independent blank VM started with stock firmware, MAC and boot defaults; observing actual LFM enrollment.',flush=True)
            deadline=time.monotonic()+480;guest=None
            while time.monotonic()<deadline:
                if switch.errors: raise RuntimeError(str(switch.errors))
                if any(vm.process.poll() is not None for vm in machines): raise RuntimeError('An owned VM exited')
                guest=completed_guest_report((seeds[0].folder/'boot.log').read_text(errors='replace'))
                if guest is not None: break
                time.sleep(1)
            if not guest or not guest.get('passed'): raise RuntimeError('Independent LFM enrollment failed: '+str(guest))
            proof=reconcile(guest['statuses'])
            if guest['garden']!=folder.name or guest['ssh_used'] or guest['target_receipt']['ssh_present']:
                raise ValueError('Wrong garden or unexpected SSH')
            target_log=(target.folder/'boot.log').read_text(errors='replace')
            if 'INDEPENDENT_AGENT_ABSENT_AT_BOOT' not in target_log: raise ValueError('Agent-free boot evidence absent')
            if not switch.dhcp or not any(event['message_type']==3 for event in switch.dhcp): raise ValueError('No actual DHCP client handshake')
            save(folder/'guest-report.json',guest)
            report.update(passed=True,**proof,independent_blank_vm_default_boot_enrollment_verified=True,
                target_garden_files_preinstalled=False,target_boot_order_overridden=False,target_mac_overridden=False,
                target_firmware_or_rom_overridden=False,target_storage_mounted_or_formatted=False,
                ssh_used=False,no_target_post_launch_commands=True,initial_boot_authenticated=False,
                guest_memory_mib=[512,512,512,768],idle_encrypted_contact_seconds=guest['idle_contact_seconds'],
                dynamically_learned_mac=switch.addresses[4].hex(':'),dhcp_client_events=list(switch.dhcp),
                guest_report_sha256=digest(folder/'guest-report.json'),
                limit='QEMU PC BIOS blank-disk defaults only; no claim for arbitrary existing OSes or other firmware')
            journal.add('model_contact_verified',**proof);time.sleep(4)
        except Exception as error:
            report['error']={'type':type(error).__name__,'message':str(error)};journal.add('failed',error=report['error'])
        finally:
            switch.close()
            for vm in reversed(machines):
                try: vm.stop()
                except Exception as error: cleanup.append(str(error))
            if not cleanup:
                mother=folder/'mother/workspace.ext2'
                if mother.exists():
                    for name in ('pxe-dhcp.log','pxe-transfers.json','pxe-server.log','learned-leases.json','lan-report.json'):
                        try: (folder/('mother-'+name)).write_bytes(read_image_file(mother,name,maximum=2*1024**2))
                        except FileNotFoundError: pass
                if 'target' in locals() and target.disk.exists():
                    report['blank_disk_unchanged']=digest(target.disk)==before
                    if not report['blank_disk_unchanged']: report['passed']=False
                for vm in machines:
                    if vm.disk.exists(): vm.disk.unlink()
                for path in private.iterdir(): path.unlink()
                private.rmdir()
            if cleanup: report['passed']=False
            report.update(cleanup_failures=cleanup,all_owned_vms_stopped=not cleanup,disposable_disks_keys_removed=not cleanup,
                elapsed_seconds=round(time.monotonic()-begin,3),lan_bytes=dict(switch.stats))
            journal.add('cleanup',failures=cleanup);journal.close();report['checkpoints']=verify_journal(folder/'checkpoints.jsonl')
            save(folder/'report.json',report);save(ROOT/'docs/validation'/('independent-lfm-'+folder.name+'.json'),report)
        print(json.dumps({'passed':report['passed'],'report':str(folder/'report.json'),'error':report.get('error')},indent=2),flush=True)
        return 0 if report['passed'] else 1
