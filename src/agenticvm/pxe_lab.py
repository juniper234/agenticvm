"""Real, owned five-VM PXE enrollment acceptance. No SSH or physical LAN access."""
from __future__ import annotations
import gzip,hashlib,importlib.util,io,json,os,secrets,stat,subprocess,time
from pathlib import Path
from uuid import uuid4
from .lan_lab import (ROOT,NAMES,Switch,LabVM,certificate,asset_inputs,tar_agent,encoded,digest,save,
                      completed_guest_report,reconcile,mac)
from .ext2 import Node,build_ext2,read_image_file
from .qemu import WindowsProcess,find_qemu
from .resources import whpx_status,check_memory_budget
from .peers import Journal,verify_journal
from .chain import exclusive

CASES=('happy','resume','bad-bootstrap','wrong-grant','unapproved-mac')
SOURCES=('pxe-init.sh','pxe-lan-init.sh','pxe_agent.py','pxe_server.py','pxe_bootstrap.py','lan_agent.py','lan_install.py','local_lfm.py')

def boot_script():
    return b'''#!ipxe
kernel http://192.0.2.1:8080/vmlinuz console=ttyS1,115200n8 rdinit=/init panic=1
initrd http://192.0.2.1:8080/initrd.gz
boot
'''

def pxe_argv(vm):
    """No CD-ROM, direct kernel argument, local OS root, monitor or guest agent."""
    def value(path): return str(path).replace(',',',,')
    argv=[str(vm.qemu),'-L',str(vm.qemu.parent/'share'),'-name','Garden-PXE-'+vm.uuid,
        '-uuid',vm.uuid,'-machine','q35','-accel','whpx','-m',str(vm.memory),'-smp','1',
        '-nodefaults','-display','none','-monitor','none','-no-reboot','-boot','order=n,menu=off',
        '-device','VGA',
        '-chardev','file,id=firmware,path='+value(vm.folder/'firmware.log'),
        '-device','isa-debugcon,iobase=0x402,chardev=firmware',
        '-chardev','file,id=boot,path='+value(vm.folder/'boot.log'),'-device','isa-serial,index=1,chardev=boot',
        '-netdev',f'socket,id=lan,connect=127.0.0.1:{vm.port}',
        '-device','e1000,netdev=lan,romfile='+value(ROOT/vm.base['rom']['path'])+',mac='+':'.join(f'{n:02x}' for n in mac(vm.member))]
    if vm.member==4:
        argv+=['-drive',f'file={value(vm.disk)},format=raw,if=virtio']
    return argv

class PXEVM(LabVM):
    def start(self):
        if self.member<=3: return super().start()
        argv=pxe_argv(self)
        save(self.folder/'launch.json',{'argv':argv,'uuid':self.uuid,'network_boot':True,'local_os_boot_disk':False,
            'guest_control_channel':False,'memory_mib':self.memory})
        with (self.folder/'stdout.log').open('wb') as out,(self.folder/'stderr.log').open('wb') as err:
            self.process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)
        with WindowsProcess(self.process.pid) as process:
            if not process.alive() or process.executable!=self.qemu: raise RuntimeError('Owned PXE VM did not start')
            self.binding={'pid':self.process.pid,'created':process.created,'executable':str(process.executable),'uuid':self.uuid}
        save(self.folder/'ownership.json',self.binding)

def run_initrd(base,public):
    spec=importlib.util.spec_from_file_location('pxe_cpio',ROOT/'scripts/build-linux-probe.py')
    probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
    trust={'mother_certificate':public['mother']['certificate'],
           'installer_sha256':digest(ROOT/'guest/lan_install.py')}
    additions={'boot-trust.json':(stat.S_IFREG|0o644,encoded(trust),0,0),
               'boot-provision.py':(stat.S_IFREG|0o644,(ROOT/'guest/pxe_bootstrap.py').read_bytes(),0,0)}
    # Linux supports concatenated compressed initramfs archives. Original root
    # contains no garden code; the second archive is the network provisioner.
    return (ROOT/base['ram_root']['path']).read_bytes()+gzip.compress(probe.make_newc(additions),mtime=0)

def prepare(vm,private,public,cfg,assets,package,manifest,initrd):
    if vm.member==5:
        save(vm.folder/'initial-inventory.json',{'member':5,'files':{},'disks':[],'network_boot_only':True});return
    nodes={'':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000)}
    def add(name,data,mode=0o600): nodes[name]=Node(stat.S_IFREG|mode,data,1000,1000)
    if vm.member==4: add('owned-pxe-data',(vm.uuid+'\n').encode())
    else:
        name=NAMES[vm.member-1]
        add('lab-address',f'192.0.2.{vm.member}\n'.encode())
        add('identity.key',private/(name+'.key'));add('identity.pem',public[name]['certificate'].encode())
        add('lan-config.json',encoded(cfg));add('peer/lan_agent.py',ROOT/'guest/lan_agent.py')
        add('peer/local_lfm.py',ROOT/'guest/local_lfm.py')
        add('model.gguf',assets['model.gguf'],0o400);add('dependencies/libgomp.so.1',assets['libgomp.so.1'],0o400)
        import tarfile
        with tarfile.open(assets['llama.tar.gz']) as archive:
            for item in archive:
                path=Path(item.name)
                if item.name.startswith('/') or '..' in path.parts or item.size>32*1024**2: raise ValueError('Unsafe pinned inference archive')
                target='llama/'+item.name
                if item.isfile(): add(target,archive.extractfile(item).read(),item.mode&0o755)
                elif item.issym() and '/' not in item.linkname: nodes[target]=Node(stat.S_IFLNK|0o777,item.linkname.encode(),1000,1000)
                elif not item.isdir(): raise ValueError('Unexpected pinned archive member')
        entry='pxe_agent.py' if vm.member==1 else 'lan_agent.py'
        add('lab/start.sh',('#!/bin/sh\nexec /usr/bin/python3 -I /workspace/peer/'+entry+'\n').encode(),0o500)
        if vm.member==1:
            add('peer/pxe_agent.py',ROOT/'guest/pxe_agent.py');add('pxe_server.py',ROOT/'guest/pxe_server.py')
            add('lab/manifest.json',encoded(manifest));add('lab/lan_install.py',ROOT/'guest/lan_install.py')
            add('lab/assets/agent.tar.gz',package);add('lab/assets/llama.tar.gz',assets['llama.tar.gz'],0o400)
            add('pxe/boot.ipxe',boot_script());add('pxe/vmlinuz',ROOT/vm.base['vmlinuz']['path']);add('pxe/initrd.gz',initrd)
    for name in list(nodes):
        for parent in Path(name).parents:
            if parent.as_posix()!='.': nodes.setdefault(parent.as_posix(),Node(stat.S_IFDIR|0o700,uid=1000,gid=1000))
    build_ext2(vm.disk,nodes,size_mib=512,label='GARDEN_PXE_DATA')
    save(vm.folder/'initial-inventory.json',{'member':vm.member,
        'files':{name:{'mode':node.mode,'uid':node.uid,'bytes':node.size} for name,node in nodes.items()},'disk_sha256':digest(vm.disk)})

def validated_base():
    path=ROOT/'runtime/linux-pxe-base-v3/build-manifest.json';base=json.loads(path.read_text())
    for key in ('root','iso','rom','vmlinuz','ram_root','package_lock'):
        if digest(ROOT/base[key]['path'])!=base[key]['sha256']: raise ValueError('PXE build changed: '+key)
    for item in base['profiles'].values():
        if digest(ROOT/item['path'])!=item['sha256']: raise ValueError('PXE boot profile changed; build a new version')
    return base

def run(case='happy'):
    if case not in CASES: raise ValueError('Unsupported fixed lab case')
    if os.name!='nt' or not whpx_status()['available']: raise RuntimeError('Windows WHPX required; settings are not changed')
    parent=ROOT/'runtime/pxe-enrollment-runs';parent.mkdir(parents=True,exist_ok=True)
    with exclusive(parent):
        for path in parent.iterdir():
            if path.is_dir() and (path/'owner.json').exists() and not (path/'recovery.json').exists():
                prior=json.loads((path/'report.json').read_text()) if (path/'report.json').exists() else None
                if prior is None or prior.get('cleanup_failures'): raise RuntimeError('Interrupted PXE run needs explicit recovery: '+path.name)
        return _run(case)

def _run(case):
    base=validated_base();memory=check_memory_budget(3*512+768+128);qemu=find_qemu()
    folder=ROOT/'runtime/pxe-enrollment-runs'/str(uuid4());folder.mkdir()
    private=folder/'private';private.mkdir()
    with WindowsProcess(os.getpid()) as owner:
        save(folder/'owner.json',{'pid':os.getpid(),'created':owner.created,'executable':str(owner.executable)})
    journal=Journal(folder,folder.name);switch=Switch();machines=[];cleanup=[];start=time.monotonic()
    expected=case in ('bad-bootstrap','wrong-grant','unapproved-mac')
    report={'schema':'agenticvm.pxe.native.v1','passed':False,'run_id':folder.name,'case':case,
        'source_sha256':{name:digest(ROOT/'guest'/name) for name in SOURCES},
        'host_source_sha256':digest(Path(__file__)),'base_manifest_sha256':digest(ROOT/'runtime/linux-pxe-base-v3/build-manifest.json'),
        'ssh_used':False,'zero_preparation_replication_achieved':False,'initial_boot_authenticated':False,
        'precondition':'iPXE-capable firmware, network boot selected, and trusted private PXE LAN',
        'physical_4gb_host_tested':False,'physical_hosts_tested':1}
    try:
        public={name:certificate(private,name,f'192.0.2.{i}') for i,name in enumerate(NAMES[:3],1)}
        assets=asset_inputs();package=tar_agent();initrd=run_initrd(base,public)
        manifest={'schema':'agenticvm.lan-assets.v1','files':{name:{'bytes':path.stat().st_size,'sha256':digest(path)} for name,path in assets.items()}}
        manifest['files']['agent.tar.gz']={'bytes':len(package),'sha256':hashlib.sha256(package).hexdigest()}
        request_id=str(uuid4());grant=secrets.token_urlsafe(32)
        for i,name in enumerate(NAMES,1):
            cfg={'identity':name,'garden':folder.name,'mother_certificate':public['mother']['certificate'],'peers':public,'test_case':case}
            if i==1: cfg.update(request_id=request_id,grant=grant,manifest_sha256=hashlib.sha256(encoded(manifest)).hexdigest())
            vm=PXEVM(folder/name,i,switch,base,qemu,768 if i==4 else (128 if i==5 else 512));machines.append(vm)
            prepare(vm,private,public,cfg,assets,package,manifest,initrd)
        report['target_initrd_bytes']=len(initrd);report['target_initrd_sha256']=hashlib.sha256(initrd).hexdigest()
        journal.add('prepared',target_uuid=machines[3].uuid,ssh=False,local_target_os=False,memory=memory)
        # Start the boot server before powering on PXE clients. Firmware's
        # finite DHCP attempt otherwise expires while the models initialize.
        for vm in machines[:3]: vm.start()
        server_deadline=time.monotonic()+240
        while time.monotonic()<server_deadline:
            if any(vm.process.poll() is not None for vm in machines[:3]): raise RuntimeError('Garden seed exited before PXE readiness')
            path=machines[0].folder/'boot.log'
            if path.exists():
                data=path.read_text(errors='replace')
                failure=completed_guest_report(data)
                if failure and not failure.get('passed'): raise RuntimeError('Mother boot failed: '+str(failure))
                if 'PXE_BOOT_SERVICE_READY' in data: break
            time.sleep(1)
        else: raise TimeoutError('PXE server readiness deadline exceeded')
        journal.add('boot_service_ready_before_target_power_on')
        for vm in machines[3:]: vm.start()
        journal.add('all_vms_started',ownership=[vm.binding for vm in machines])
        print('Five owned VMs started: network boot case '+case+'. No SSH, physical LAN, or Internet.',flush=True)
        deadline=time.monotonic()+660;guest=None;denied=None;opened=None
        while time.monotonic()<deadline:
            if switch.errors: raise RuntimeError('Private virtual switch failed: '+str(switch.errors))
            for vm in machines:
                if vm.process.poll() is not None: raise RuntimeError(NAMES[vm.member-1]+' exited; inspect stderr.log')
            path=machines[0].folder/'boot.log'
            if path.exists(): guest=completed_guest_report(path.read_text(errors='replace'))
            path=machines[3].folder/'boot.log'
            if path.exists():
                data=path.read_text(errors='replace')
                for line in reversed(data.split('\n')[:-1]):
                    if line.startswith('PXE_TARGET_REPORT '): denied=json.loads(line.removeprefix('PXE_TARGET_REPORT '));break
            if case in ('bad-bootstrap','wrong-grant') and denied is not None: break
            if case=='unapproved-mac':
                # PXE firmware retries DHCP while the mother keeps its enrollment window open.
                path=machines[0].folder/'boot.log'
                if path.exists() and 'PXE_ENROLLMENT_WINDOW_OPEN' in path.read_text(errors='replace'):
                    if opened is None: opened=time.monotonic()
                    if time.monotonic()-opened>=45: break
            if guest is not None: break
            time.sleep(1)
        if expected:
            if guest and guest.get('passed'): raise ValueError('Refused PXE case unexpectedly enrolled')
            if case!='unapproved-mac':
                text={'bad-bootstrap':'integrity verification failed before execution','wrong-grant':'HTTP Error 403'}[case]
                if not denied or denied.get('ok') is not False or text not in denied.get('error',''):
                    raise ValueError('Expected target refusal evidence missing: '+str(denied))
                report['denial_reason']=denied['error']
            elif opened is None: raise ValueError('Mother did not open the bounded test window')
            report.update(passed=True,expected_enrollment_denial=True,prepared_target_automatic_enrollment_verified=False)
        else:
            if not guest or not guest.get('passed'): raise RuntimeError('PXE garden acceptance failed: '+str(guest))
            if guest['garden']!=folder.name or guest['ssh_used']: raise ValueError('Wrong garden or transport receipt')
            save(folder/'guest-report.json',guest)
            proofs=reconcile(guest['statuses'])
            if case=='resume' and not guest['installed']['downloads'][0]['resumed']: raise ValueError('Native model transfer did not resume')
            if 'PXE_AGENT_ABSENT 192.0.2.4' not in (machines[3].folder/'boot.log').read_text(errors='replace'):
                raise ValueError('Agent-free target boot marker missing')
            if switch.stats.get('1->4',0)<len(initrd)+assets['model.gguf'].stat().st_size:
                raise ValueError('Network bytes cannot account for boot and model transfer')
            report.update(passed=True,**proofs,prepared_target_automatic_enrollment_verified=True,
                guest_report_sha256=digest(folder/'guest-report.json'),idle_encrypted_contact_seconds=guest['idle_contact_seconds'],
                duplicate_request_same_agent_process=True,guest_memory_mib=[vm.memory for vm in machines],
                no_guest_control_channels=True,no_target_post_launch_interventions=True,
                no_public_lan_or_internet_connection=True,network_boot_without_local_os=True)
            journal.add('pxe_enrollment_and_model_contact_verified',**proofs)
        time.sleep(4)
    except Exception as error:
        report['error']={'type':type(error).__name__,'message':str(error)};journal.add('validation_failed',error=report['error'])
    finally:
        switch.close()
        for vm in reversed(machines):
            try: vm.stop()
            except Exception as error: cleanup.append({'vm':vm.member,'error':str(error)})
        if not cleanup:
            # Observe mother evidence offline only after every owned VM has stopped.
            if machines:
                for name in ('pxe-dhcp.log','pxe-server.log','pxe-transfers.json','agent.log','lan-report.json'):
                    try: (folder/('mother-'+name)).write_bytes(read_image_file(machines[0].disk,name,maximum=2*1024**2))
                    except FileNotFoundError: pass
            if len(machines)>3:
                target=machines[3]
                if target.disk.exists():
                    for name in ('pxe-result.json','agent.log','enrollment-state.json'):
                        try: (target.folder/name).write_bytes(read_image_file(target.disk,name,maximum=512*1024))
                        except FileNotFoundError: pass
                    if expected:
                        for name in ('model.gguf','peer/lan_agent.py','identity.key'):
                            try: read_image_file(target.disk,name,maximum=256*1024**2)
                            except FileNotFoundError: pass
                            else: cleanup.append({'unexpected_target_activation':name})
            transfers_path=folder/'mother-pxe-transfers.json'
            transfers=json.loads(transfers_path.read_text()) if transfers_path.exists() else []
            report['boot_transfers']=transfers
            if any(row['source']!='192.0.2.4' for row in transfers): cleanup.append({'unapproved_boot_image_recipient':True})
            dhcp=folder/'mother-pxe-dhcp.log'
            log=dhcp.read_text(errors='replace') if dhcp.exists() else ''
            if case=='unapproved-mac':
                if transfers or 'DHCPDISCOVER' not in log or 'DHCPOFFER' in log or 'DHCPACK' in log:
                    cleanup.append({'unapproved_mac_refusal_not_verified':True})
            elif report['passed'] and ('DHCPACK' not in log or '52:54:00:4c:41:04' not in log):
                cleanup.append({'actual_pxe_dhcp_handshake_missing':True})
            for vm in machines:
                if vm.disk.exists(): vm.disk.unlink()
            for path in private.iterdir():
                if path.is_file(): path.unlink()
            private.rmdir()
        report.update(cleanup_failures=cleanup,all_owned_lab_vms_stopped=not cleanup,
            disposable_private_disks_removed=not cleanup,lan_bytes=dict(switch.stats),switch_errors=list(switch.errors),
            elapsed_seconds=round(time.monotonic()-start,3))
        if cleanup: report['passed']=False
        journal.add('lab_cleanup',failures=cleanup);journal.close()
        report['checkpoints']=verify_journal(folder/'checkpoints.jsonl');save(folder/'report.json',report)
    if report['passed']:
        save(ROOT/'docs/validation'/('pxe-'+case+'-'+folder.name+'.json'),{**report,'raw_report':str(folder/'report.json'),'raw_report_sha256':digest(folder/'report.json')})
    print(json.dumps({'passed':report['passed'],'report':str(folder/'report.json'),'error':report.get('error'),
                      'elapsed_seconds':report['elapsed_seconds']},indent=2),flush=True)
    return 0 if report['passed'] else 1
