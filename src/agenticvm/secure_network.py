"""Authenticated network boot proof: firmware allowlists all kernel/initrd bytes.

This is a preprovisioned firmware trust experiment, not a factory-default claim
or an actual-model enrollment case. The independent LFM cases remain separate.
"""
import gzip,hashlib,importlib.util,json,stat,struct,subprocess,sys,time
from pathlib import Path
from . import realism_lab as lab
from .lan_lab import ROOT,LabVM,find_qemu,digest,save
from .chain import exclusive
from .resources import check_memory_budget
from .uki import build,pefile,pe_authenticode_hash

def protected_initrd(base,public=None):
    spec=importlib.util.spec_from_file_location('protected_cpio',ROOT/'scripts/build-linux-probe.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    init=(ROOT/'guest/realism-init.sh').read_bytes().replace(b'\r\n',b'\n')
    anchor=b'modprobe af_packet || exit 1\n'
    verify=b'''modprobe efivarfs || exit 1
mkdir -p /sys/firmware/efi/efivars
mount -t efivarfs efivarfs /sys/firmware/efi/efivars || exit 1
state=$(/bin/busybox dd if=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c bs=1 skip=4 count=1 2>/dev/null | /bin/busybox od -An -tu1 | /bin/busybox tr -d ' ')
[ "$state" = 1 ] || exit 1
echo "REALISM_SECURE_BOOT_STATE $state"
'''
    if init.count(anchor)!=1: raise ValueError('Protected init insertion point changed')
    entries={'init':(stat.S_IFREG|0o755,init.replace(anchor,anchor+verify),0,0)}
    manifest=json.loads((ROOT/'tools/secure-kernel/manifest.json').read_text())
    for name,sha in manifest['files'].items():
        path=ROOT/'tools/secure-kernel'/name
        if digest(path)!=sha: raise ValueError('EFI variable module changed')
        entries['usr/lib/'+name]=(stat.S_IFREG|0o644,path.read_bytes(),0,0)
        for parent in Path('usr/lib/'+name).parents:
            if parent.as_posix()!='.': entries.setdefault(parent.as_posix(),(stat.S_IFDIR|0o755,b'',0,0))
    return lab.initrd(base,probe=public is None,public=public)+gzip.compress(module.make_newc(entries),mtime=0)

def firmware_vars(folder,hashes):
    cert=ROOT/'tools/python/firmware-v1/virt/firmware/certs/RedHatSecureBootPKKEKkey1.pem'
    owner='a67dc5c0-8409-42d8-b0ef-af34aa5a083c'
    code='import sys,runpy;sys.path.insert(0,"tools/python/firmware-v1");runpy.run_module("virt.firmware.vars",run_name="__main__")'
    argv=[sys.executable,'-I','-B','-W','ignore','-c',code,'--input',str(ROOT/'tools/ovmf-debian/OVMF_VARS_4M.fd'),
        '--set-pk',owner,str(cert),'--add-kek',owner,str(cert),'--sb','--no-microsoft',
        '--output',str(folder/'nvram.fd'),'--output-json',str(folder/'preprovisioned-vars.json')]
    for value in hashes: argv+=['--add-db-hash',owner,value]
    result=subprocess.run(argv,cwd=ROOT,capture_output=True,text=True,timeout=30)
    if result.returncode: raise RuntimeError('Test firmware trust preparation failed: '+result.stderr[-1000:])
    return {'preprovisioned':True,'allowed_authenticode_sha256':hashes,
        'initial_nvram_sha256':digest(folder/'nvram.fd'),'public_platform_certificate_sha256':digest(cert),
        'private_signing_keys_generated_or_used':False}

class SecureTarget(lab.TargetVM):
    def start(self,hashes):
        trust=firmware_vars(self.folder,hashes)
        self.launch([str(self.qemu),'-L',str(lab.FIRMWARE),'-name','Garden-Protected-Boot-'+self.uuid,'-uuid',self.uuid,
            '-machine','q35,smm=on','-accel','tcg,tb-size=64','-cpu','max','-m','768','-display','none','-monitor','none','-no-reboot',
            '-global','mch.extended-tseg-mbytes=16',
            '-global','driver=cfi.pflash01,property=secure,value=on',
            '-drive','if=pflash,format=raw,readonly=on,file='+str(ROOT/'tools/ovmf-debian/OVMF_CODE_4M.secboot.fd'),
            '-drive','if=pflash,format=raw,file='+str(self.folder/'nvram.fd'),
            '-drive','file='+str(self.disk)+',format=raw','-serial','file:'+str(self.folder/'boot.log'),
            '-object','rng-builtin,id=entropy','-device','virtio-rng-pci,rng=entropy',
            '-netdev',f'socket,id=lan,connect=127.0.0.1:{self.port}',
            '-device','virtio-net-pci,netdev=lan,romfile=,bootindex=1'],
            {'secure_boot_enabled':True,'firmware_trust':trust,'target_commands_or_shares':False,
             'boot_order_override':True,'factory_default_claimed':False,'tcg_required_for_smm_control':True,
             'smm_reserved_memory_mib':16,'qemu_default_smm_reserved_memory_mib':64,'tcg_translation_cache_mib':64})

def run(tampered=False):
    base=lab.preflight();check_memory_budget(1280);lab.PARENT.mkdir(parents=True,exist_ok=True)
    with exclusive(lab.PARENT):
        folder,journal,report=lab.begin_run('secure-network-boot','uefi-secure-uki')
        extra=[Path(__file__),ROOT/'src/agenticvm/uki.py',ROOT/'guest/secure_boot_http.py']
        report['additional_source_sha256']={str(p.relative_to(ROOT)):digest(p) for p in extra}
        report.update(tampered=tampered,network_enrollment_test=False,actual_model_completions=0,
            preprovisioned_firmware_trust=True,encrypted_boot_transport=False)
        switch=lab.FaultSwitch();machines=[];before=None;begin=time.monotonic()
        try:
            target=SecureTarget(folder/'target',4,switch,base,find_qemu(),768);machines.append(target);lab.blank_disk(target);before=digest(target.disk)
            stub=ROOT/'tools/uki-stub/linuxx64.efi.stub';stub_manifest=json.loads((stub.parent/'manifest.json').read_text())
            if digest(stub)!=stub_manifest['stub_sha256']: raise ValueError('UKI stub changed')
            original=folder/'original-garden.efi';uki=build(stub,(ROOT/base['vmlinuz']['path']).read_bytes(),protected_initrd(base),original)
            ipxe_hash=pe_authenticode_hash(pefile.PE(str(ROOT/'tools/realism/ipxe.efi'))).hex()
            served=original
            if tampered:
                data=bytearray(original.read_bytes());pe=pefile.PE(data=bytes(data))
                section=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.initrd')
                data[section.PointerToRawData+1024]^=1;served=folder/'modified-garden.efi';served.write_bytes(data)
                if pe_authenticode_hash(pefile.PE(data=bytes(data))).hex()==uki['authenticode_sha256']: raise ValueError('Payload tampering did not change the authenticated digest')
            report.update(uki=uki,served_image_sha256=digest(served),ipxe_authenticode_sha256=ipxe_hash)
            mother=LabVM(folder/'mother',1,switch,base,find_qemu(),256);machines.append(mother)
            lab.image(mother.disk,{'lab-address':(b'192.0.2.1\n',0o600),'lan-config.json':(b'{}',0o600),
                'pxe_server.py':(ROOT/'guest/secure_boot_http.py',0o600),
                'independent_boot_server.py':(ROOT/'guest/independent_boot_server.py',0o600),
                'lab/start.sh':(b'#!/bin/sh\nwhile [ ! -f /workspace/pxe-ready ]; do sleep .2; done\necho SECURE_HTTP_READY\nwhile :; do sleep 30; done\n',0o500),
                'pxe/boot.ipxe':(b'#!ipxe\nchain http://192.0.2.1:8080/garden.efi\n',0o600),'pxe/garden.efi':(served,0o600)})
            mother.start();lab.wait_marker(mother,'SECURE_HTTP_READY',60,switch)
            dhcp=lab.DHCPVM(folder/'dhcp',5,switch,base,find_qemu(),256);machines.append(dhcp);dhcp.start()
            lab.wait_marker(dhcp,'REALISM_DHCP_APPLIANCE_READY',60,switch)
            target.start([uki['authenticode_sha256'],ipxe_hash]);journal.add('secure_target_powered_on',tampered=tampered)
            print('Protected UEFI network boot: '+('modified image must be rejected' if tampered else 'allowlisted kernel and RAM root must execute'),flush=True)
            deadline=time.monotonic()+240;text=''
            while time.monotonic()<deadline:
                if switch.errors: raise RuntimeError(str(switch.errors))
                if target.process.poll() is not None: raise RuntimeError('Protected target exited')
                path=target.folder/'boot.log';text=path.read_text(errors='replace') if path.exists() else ''
                denied=any(value in text.lower() for value in ('security violation','permission denied','access denied'))
                if tampered and denied:
                    if 'REALISM_SECURE_BOOT_STATE' in text or 'REALISM_NETWORK_BOOT_EXECUTED' in text: raise ValueError('Modified protected environment executed')
                    report.update(passed=True,modified_uki_rejected_before_linux=True);break
                if not tampered and 'REALISM_NETWORK_BOOT_EXECUTED' in text:
                    if 'REALISM_SECURE_BOOT_STATE 1' not in text: raise ValueError('Linux did not observe enforced Secure Boot')
                    report.update(passed=True,initial_boot_authenticated=True,complete_kernel_and_initrd_allowlisted=True,
                        linux_observed_secure_boot_one=True);break
                time.sleep(.5)
            else: raise TimeoutError('Protected network boot did not produce the required positive observation')
            time.sleep(4)
        except Exception as error:
            report.update(passed=False,error={'type':type(error).__name__,'message':str(error)});journal.add('failed',error=report['error'])
        finally:
            changed=any(digest(ROOT/p)!=sha for p,sha in report['additional_source_sha256'].items())
            report['additional_source_changed_during_run']=changed
            if changed: report.update(passed=False,error={'type':'SourceChanged','message':'Protected boot sources changed during this run; receipt excluded'})
            code=lab.finish(folder,machines,switch,journal,report,before,begin)
        return code
