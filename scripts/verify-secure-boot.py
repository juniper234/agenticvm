"""Boot-enforcement control only; not a claim of secure garden enrollment."""
import json,os,shutil,subprocess,sys,time,warnings
from pathlib import Path
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tools/python/firmware-v1')]
warnings.filterwarnings('ignore',category=UserWarning)
from agenticvm.lan_lab import save,digest
from agenticvm.qemu import WindowsProcess,find_qemu
from agenticvm.independent_lab import FIRMWARE
from agenticvm.uki import pe_authenticode_hash
import pefile

def firmware_vars(destination,allowed_hash):
    cert=ROOT/'tools/python/firmware-v1/virt/firmware/certs/RedHatSecureBootPKKEKkey1.pem'
    owner='a67dc5c0-8409-42d8-b0ef-af34aa5a083c'
    command=[sys.executable,'-I','-B','-W','ignore','-c',
        'import sys,runpy;sys.path.insert(0,"tools/python/firmware-v1");runpy.run_module("virt.firmware.vars",run_name="__main__")',
        '--input',str(FIRMWARE/'edk2-i386-vars.fd'),'--set-pk',owner,str(cert),
        '--add-kek',owner,str(cert),'--add-db-hash',owner,allowed_hash,'--sb','--no-microsoft','--output',str(destination)]
    result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=30)
    if result.returncode: raise RuntimeError('Cannot prepare test-only firmware trust: '+result.stderr[-1000:])

def case(folder,efi,allow_hash,tampered=False):
    folder.mkdir();boot=folder/'boot/EFI/BOOT';boot.mkdir(parents=True)
    (boot/'BOOTX64.EFI').write_bytes(efi);firmware_vars(folder/'nvram.fd',allow_hash)
    ident=str(uuid4());argv=[str(find_qemu()),'-L',str(FIRMWARE),'-name','Garden-SB-Control-'+ident,'-uuid',ident,
        '-machine','q35,smm=on','-accel','tcg,tb-size=64','-m','256','-display','none','-monitor','none','-nic','none','-no-reboot',
        '-global','driver=cfi.pflash01,property=secure,value=on',
        '-drive','if=pflash,format=raw,readonly=on,file='+str(ROOT/'tools/realism/edk2-x86_64-secure-code.fd'),
        '-drive','if=pflash,format=raw,file='+str(folder/'nvram.fd'),
        '-drive','if=virtio,format=raw,readonly=on,file=fat:ro:'+str(folder/'boot'),'-serial','file:'+str(folder/'boot.log')]
    save(folder/'launch.json',{'argv':argv,'prepared_boot_control':True,'network_enrollment_test':False,
        'trust_preprovisioned':True,'allowed_authenticode_sha256':allow_hash,'tampered':tampered,
        'tcg_explicitly_selected_for_smm_control':True})
    child=None;state=None;result={'passed':False,'tampered':tampered}
    try:
        with (folder/'stderr.log').open('wb') as err,(folder/'stdout.log').open('wb') as out:
            child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
        with WindowsProcess(child.pid) as p:
            if not p.alive() or p.executable!=find_qemu(): raise RuntimeError('Secure Boot control did not start')
            state={'pid':child.pid,'created':p.created,'executable':str(p.executable)}
        save(folder/'ownership.json',state);deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            text=(folder/'boot.log').read_text(errors='replace') if (folder/'boot.log').exists() else ''
            if tampered and ('Access Denied' in text or 'Security Violation' in text): break
            if not tampered and 'GARDEN_SECURE_BOOT_PROBE_EXECUTED SecureBoot=1' in text: break
            if child.poll() is not None: raise RuntimeError('Secure Boot VM exited: '+(folder/'stderr.log').read_text(errors='replace')[-1000:])
            time.sleep(.5)
        else: raise TimeoutError('Secure Boot control did not reach the expected firmware observation')
        if tampered and 'GARDEN_SECURE_BOOT_PROBE_EXECUTED' in text: raise ValueError('Tampered application executed')
        result.update(passed=True,firmware_rejected_modified_image=tampered,
            secure_boot_one_observed_by_allowed_application=not tampered,boot_log_sha256=digest(folder/'boot.log'))
    except Exception as error: result['error']=type(error).__name__+': '+str(error)
    finally:
        if child and child.poll() is None:
            with WindowsProcess(child.pid,terminate=True) as p:
                if not state or p.created!=state['created'] or str(p.executable)!=state['executable']:
                    raise RuntimeError('Secure Boot control ownership mismatch; retained for recovery')
                p.terminate();p.wait(10)
            child.wait(10)
        result['owned_vm_stopped']=not child or child.poll() is not None
        # Retain readonly test payload and serial evidence; remove writable NVRAM.
        (folder/'nvram.fd').unlink(missing_ok=True)
        save(folder/'report.json',result)
    return result

def main():
    output=ROOT/'runtime/secureboot-runs'/str(uuid4());output.mkdir(parents=True)
    with WindowsProcess(os.getpid()) as p: save(output/'owner.json',{'pid':os.getpid(),'created':p.created,'executable':str(p.executable)})
    result={'schema':'agenticvm.secure-boot-controls.v1','passed':False,
        'network_enrollment_test':False,'physical_hardware_tested':False,'preprovisioned_trust':True,
        'trust_method':'UEFI db allowlist of an exact PE Authenticode SHA256; test platform PK/KEK public cert',
        'code_signing_or_host_keys_used':False,'cases':[]}
    start=time.monotonic()
    try:
        zig=ROOT/'tools/zig/zig-x86_64-windows-0.15.2/zig.exe';efi=output/'probe.efi'
        result['source_sha256']=digest(ROOT/'guest/secureboot_probe.zig')
        built=subprocess.run([str(zig),'build-exe',str(ROOT/'guest/secureboot_probe.zig'),'-target','x86_64-uefi','-O','ReleaseSmall','-femit-bin='+str(efi)],
            cwd=ROOT,capture_output=True,text=True,timeout=60)
        if built.returncode: raise RuntimeError(built.stderr[-2000:])
        pe=pefile.PE(str(efi));allowed=pe_authenticode_hash(pe).hex();data=efi.read_bytes()
        result['allowed_image']={'sha256':digest(efi),'authenticode_sha256':allowed,'bytes':len(data)}
        result['cases'].append(case(output/'allowed',data,allowed))
        if not result['cases'][0]['passed']: raise RuntimeError(str(result['cases'][0]))
        # Change an allocated data section, retaining a structurally valid PE.
        modified=bytearray(data);offset=pe.sections[0].PointerToRawData+16;modified[offset]^=1
        if pe_authenticode_hash(pefile.PE(data=bytes(modified))).hex()==allowed: raise ValueError('Tampering did not alter executable digest')
        result['cases'].append(case(output/'modified',bytes(modified),allowed,True))
        result['passed']=all(row['passed'] and row['owned_vm_stopped'] for row in result['cases'])
    except Exception as error: result['error']=type(error).__name__+': '+str(error)
    result['elapsed_seconds']=round(time.monotonic()-start,3)
    save(output/'report.json',result);path=ROOT/'docs/validation'/('secure-boot-controls-'+output.name+'.json');save(path,result)
    print(json.dumps({'passed':result['passed'],'report':str(path),'error':result.get('error')},indent=2),flush=True)
    return 0 if result['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
