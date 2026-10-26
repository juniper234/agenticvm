"""Real LFM2.5 on a blank modern-UEFI target plus separate DHCP and cable faults."""
import hashlib,json,secrets,stat,tarfile,time
from pathlib import Path
from . import realism_lab as lab
from .lan_lab import ROOT,LabVM,find_qemu,asset_inputs,tar_agent,certificate,encoded,digest,save,reconcile,completed_guest_report
from .ext2 import Node,build_ext2
from .chain import exclusive
from .resources import check_memory_budget
from .lab_metrics import ResourceTracker

def seed(vm,private,public,cfg,assets,package,manifest,ram,protected_uki=None):
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
            elif not item.isdir(): raise ValueError('Unexpected archive entry')
    entry='garden_realistic.py' if vm.member==1 else 'lan_agent.py'
    files['lab/start.sh']=(('#!/bin/sh\nexport LLAMA_ARG_REPACK=0\nexec /usr/bin/python3 -I /workspace/peer/'+entry+'\n').encode(),0o500)
    if vm.member==1:
        files.update({'peer/garden_realistic.py':(ROOT/'guest/garden_realistic.py',0o600),
            'peer/pxe_agent.py':(ROOT/'guest/pxe_agent.py',0o600),
            'pxe_server.py':(ROOT/('guest/secure_boot_http.py' if protected_uki else 'guest/realism_boot_server.py'),0o600),
            'independent_boot_server.py':(ROOT/'guest/independent_boot_server.py',0o600),
            'lab/manifest.json':(encoded(manifest),0o600),'lab/lan_install.py':(ROOT/'guest/lan_install.py',0o600),
            'lab/assets/agent.tar.gz':(package,0o400),'lab/assets/llama.tar.gz':(assets['llama.tar.gz'],0o400),
            'pxe/boot.ipxe':(b'#!ipxe\nchain http://192.0.2.1:8080/garden.efi\n' if protected_uki else lab.boot_script(),0o600),'pxe/vmlinuz':(ROOT/vm.base['vmlinuz']['path'],0o600),
            'pxe/ipxe.efi':(ROOT/'tools/realism/ipxe.efi',0o600),
            'pxe/initrd.gz':(ram,0o600)})
        if protected_uki: files['pxe/garden.efi']=(protected_uki,0o600)
    nodes={'':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000)}
    for path,(data,mode) in files.items(): nodes[path]=Node(stat.S_IFREG|mode,data,1000,1000)
    for path,data in links.items(): nodes[path]=Node(stat.S_IFLNK|0o777,data,1000,1000)
    for path in list(nodes):
        for parent in Path(path).parents:
            if parent.as_posix()!='.': nodes.setdefault(parent.as_posix(),Node(stat.S_IFDIR|0o700,uid=1000,gid=1000))
    build_ext2(vm.disk,nodes,size_mib=512,label='REALISM_GARDEN_SEED')

def enroll(profile='uefi-e1000',*,resume=True,cable_fault=True,contact_seconds=120,secure=False):
    if profile not in ('uefi-stock-rng','uefi-e1000','uefi-e1000e','uefi-virtio','bios-default'): raise ValueError('Positive compatibility profile required')
    if type(contact_seconds) is not int or not 60<=contact_seconds<=3600: raise ValueError('Contact window must be 60..3600 seconds')
    base=lab.preflight();memory=check_memory_budget(3*512+768+256);lab.PARENT.mkdir(parents=True,exist_ok=True)
    with exclusive(lab.PARENT):
        folder,journal,report=lab.begin_run('secure-lfm-fault-enrollment' if secure else 'lfm-fault-enrollment','uefi-secure-uki' if secure else profile)
        # Additional exact payload/runtime hashes, independent of the older lab.
        extra=[Path(__file__),ROOT/'src/agenticvm/lab_metrics.py',ROOT/'guest/garden_realistic.py',ROOT/'guest/lan_install.py',ROOT/'guest/lan_agent.py',
               ROOT/'guest/pxe_agent.py',ROOT/'guest/pxe_bootstrap.py',ROOT/'guest/local_lfm.py']
        if secure: extra += [ROOT/'src/agenticvm/secure_network.py',ROOT/'src/agenticvm/uki.py',ROOT/'guest/secure_boot_http.py']
        report['additional_source_sha256']={str(p.relative_to(ROOT)):digest(p) for p in extra}
        report.update(contact_requested_seconds=contact_seconds,model_download_interruption_requested=resume,cable_interruption_requested=cable_fault,
            host_memory=memory,guest_allocation_mib=2560,model_runtime_environment={'LLAMA_ARG_REPACK':'0'})
        private=folder/'private';private.mkdir();switch=lab.FaultSwitch();machines=[];before=None;begin=time.monotonic();metrics=ResourceTracker()
        try:
            if secure:
                from .secure_network import SecureTarget,protected_initrd
                from .uki import build,pefile,pe_authenticode_hash
                target=SecureTarget(folder/'target',4,switch,base,find_qemu(),768)
            else: target=lab.TargetVM(folder/'target',4,switch,base,find_qemu(),768)
            machines.append(target);lab.blank_disk(target);before=digest(target.disk)
            public={name:certificate(private,name,f'192.0.2.{i}') for i,name in enumerate(('mother','offshoot-1','offshoot-2'),1)}
            assets=asset_inputs();package=tar_agent();ram=protected_initrd(base,public=public) if secure else lab.initrd(base,probe=False,public=public)
            uki_path=None
            if secure:
                uki_path=folder/'garden-enrollment.efi'
                report['protected_boot_uki']=build(ROOT/'tools/uki-stub/linuxx64.efi.stub',(ROOT/base['vmlinuz']['path']).read_bytes(),ram,uki_path)
                report['preprovisioned_firmware_trust']=True
                ipxe_hash=pe_authenticode_hash(pefile.PE(str(ROOT/'tools/realism/ipxe.efi'))).hex()
            manifest={'schema':'agenticvm.lan-assets.v1','files':{name:{'bytes':p.stat().st_size,'sha256':digest(p)} for name,p in assets.items()}}
            manifest['files']['agent.tar.gz']={'bytes':len(package),'sha256':hashlib.sha256(package).hexdigest()}
            request=folder.name;grant=secrets.token_urlsafe(32);seeds=[]
            for i,name in enumerate(('mother','offshoot-1','offshoot-2'),1):
                cfg={'identity':name,'garden':folder.name,'mother_certificate':public['mother']['certificate'],
                    'peers':public,'test_case':'resume' if resume else 'happy','contact_seconds':contact_seconds,'cable_fault':cable_fault}
                cfg['secure_boot']=secure
                if i==1: cfg.update(request_id=request,grant=grant,manifest_sha256=hashlib.sha256(encoded(manifest)).hexdigest())
                vm=LabVM(folder/name,i,switch,base,find_qemu(),512);machines.append(vm);seeds.append(vm)
                seed(vm,private,public,cfg,assets,package,manifest,ram,uki_path)
            dhcp=lab.DHCPVM(folder/'dhcp',5,switch,base,find_qemu(),256);machines.append(dhcp);dhcp.start()
            lab.wait_marker(dhcp,'REALISM_DHCP_APPLIANCE_READY',60,switch)
            for vm in seeds: vm.start()
            lab.wait_marker(seeds[0],'REALISM_GARDEN_BOOT_SERVICE_READY',240,switch)
            target.start([report['protected_boot_uki']['authenticode_sha256'],ipxe_hash] if secure else profile)
            journal.add('target_powered_on',ownership=target.binding,profile=report['profile'])
            print('Actual LFM enrollment: '+report['profile']+'; separate DHCP, interrupted model download and cable recovery.',flush=True)
            deadline=time.monotonic()+contact_seconds+480;guest=None;cut=None;restored=False
            while time.monotonic()<deadline:
                if switch.errors: raise RuntimeError(str(switch.errors))
                if any(vm.process.poll() is not None for vm in machines): raise RuntimeError('An owned test VM exited')
                metrics.sample(machines)
                text=(seeds[0].folder/'boot.log').read_text(errors='replace')
                if cable_fault and cut is None and 'REALISM_CONTACT_FAULT_READY' in text:
                    switch.set_blocked(4,True);cut=time.monotonic();journal.add('target_cable_interrupted')
                    print('Target cable interrupted for 10 seconds after ten model completions.',flush=True)
                if cut is not None and not restored and time.monotonic()-cut>=10:
                    switch.set_blocked(4,False);restored=True;journal.add('target_cable_restored')
                    print('Target cable restored; checking automatic encrypted reconnection without model task replay.',flush=True)
                guest=completed_guest_report(text)
                if guest is not None: break
                time.sleep(.5)
            if not guest or not guest.get('passed'): raise RuntimeError('Realistic garden failed: '+str(guest))
            proof=reconcile(guest['statuses'])
            if guest['garden']!=folder.name or guest['ssh_used']: raise ValueError('Wrong garden or unexpected SSH')
            if cable_fault and (not restored or not guest['recovered_after_network_failure'] or not switch.drops):
                raise ValueError('Real cable outage/recovery evidence absent')
            log=(target.folder/'boot.log').read_text(errors='replace')
            if 'REALISM_LINUX_DHCP_BOUND 192.0.2.4 server=192.0.2.5' not in log: raise ValueError('Independent Linux DHCP evidence absent')
            renewals=log.count('event=renew')
            if not renewals: raise ValueError('Linux DHCP client did not renew its real lease during sustained contact')
            if 'REALISM_LFM_REPACK_DISABLED' not in log: raise ValueError('Target model process did not inherit the low-memory setting')
            save(folder/'guest-report.json',guest)
            report.update(passed=True,**proof,guest_report_sha256=digest(folder/'guest-report.json'),
                separate_dhcp_vm=True,linux_dhcp_lease_observed=True,secure_boot_enabled=secure,
                initial_boot_authenticated=secure,
                linux_dhcp_renewals_observed=renewals,
                target_model_repacking_disabled_verified=True,
                contact_seconds=guest['contact_seconds'],network_failures_observed=guest['network_failures_observed'],
                recovered_after_network_failure=guest['recovered_after_network_failure'],
                target_identity_and_process_preserved=True,model_tasks_replayed=False,
                interrupted_model_download_resumed=any(x['name']=='model.gguf' and x['resumed'] for x in guest['target_receipt']['installed']['downloads']))
            if secure and ('REALISM_SECURE_BOOT_STATE 1' not in log or not guest['initial_boot_authenticated']):
                raise ValueError('Protected Linux/model enrollment did not prove enforced Secure Boot')
            journal.add('model_and_recovery_verified',**proof);time.sleep(4)
        except Exception as error:
            report.update(passed=False,error={'type':type(error).__name__,'message':str(error)});journal.add('failed',error=report['error'])
        finally:
            report['resource_metrics']=metrics.report()
            if any(digest(ROOT/p)!=sha for p,sha in report['additional_source_sha256'].items()):
                report.update(passed=False,additional_source_changed_during_run=True)
            code=lab.finish(folder,machines,switch,journal,report,before,begin,private)
        return code
