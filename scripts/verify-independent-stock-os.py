"""Stock Alpine OS control: normal boot, no enrollment despite available PXE service."""
import importlib.util,json,os,socket,subprocess,sys,time
from pathlib import Path
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.independent_lab import (LearningSwitch,IndependentVM,default_target_argv,blank_disk,image,initrd,script,firmware_manifest)
from agenticvm.independent_recovery import require_clean_history
from agenticvm.lan_lab import LabVM,save,digest
from agenticvm.pxe_lab import validated_base
from agenticvm.ext2 import read_image_file
from agenticvm.chain import exclusive
from agenticvm.qemu import WindowsProcess,find_qemu
from agenticvm.framebuffer_observer import capture

class ObservedStockVM(IndependentVM):
    def start(self,iso):
        listener=socket.socket();listener.bind(('127.0.0.1',0));self.vnc_port=listener.getsockname()[1];listener.close()
        argv=default_target_argv(self,iso)+['-vnc',f'127.0.0.1:{self.vnc_port-5900}']
        save(self.folder/'launch.json',{'argv':argv,'uuid':self.uuid,'boot_order_override':False,
            'firmware_or_rom_override':False,'target_mac_override':False,'garden_files_on_target':False,
            'stock_os_iso':str(iso),'loopback_framebuffer_observation_only':True})
        with (self.folder/'stdout.log').open('wb') as out,(self.folder/'stderr.log').open('wb') as err:
            self.process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)
        with WindowsProcess(self.process.pid) as p:
            if not p.alive() or p.executable!=self.qemu: raise RuntimeError('Owned stock OS VM failed to start')
            self.binding={'pid':self.process.pid,'created':p.created,'executable':str(p.executable),'uuid':self.uuid}
        save(self.folder/'ownership.json',self.binding)

def main():
    require_clean_history();base=validated_base();firmware=firmware_manifest()
    spec=importlib.util.spec_from_file_location('stock_alpine',ROOT/'scripts/build-linux-probe.py')
    probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe);iso,provenance=probe.verified_iso()
    parent=ROOT/'runtime/independent-vm-runs';parent.mkdir(parents=True,exist_ok=True)
    with exclusive(parent):
        folder=parent/str(uuid4());folder.mkdir();switch=LearningSwitch();machines=[];begin=time.monotonic();cleanup=[]
        with WindowsProcess(os.getpid()) as p: save(folder/'owner.json',{'pid':os.getpid(),'created':p.created,'executable':str(p.executable)})
        report={'schema':'agenticvm.independent-stock-os.v1','case':'stock-alpine-os-control','passed':False,
            'run_id':folder.name,'stock_firmware':firmware,'stock_os':provenance,'recruitment_achieved':False,
            'source_sha256':digest(Path(__file__)),'framebuffer_review_required':True,
            'stock_keymaps_manifest_sha256':digest(ROOT/'tools/qemu-stock-firmware/20260811/stock-keymaps.json')}
        try:
            target=ObservedStockVM(folder/'independent-target',4,switch,base,find_qemu(),768);machines.append(target);blank_disk(target);before=digest(target.disk)
            mother=LabVM(folder/'mother',1,switch,base,find_qemu(),256);machines.append(mother)
            image(mother.disk,{'lab-address':(b'192.0.2.1\n',0o600),'lan-config.json':(b'{}',0o600),
                'pxe-open':(b'one owned lab client\n',0o600),'pxe_server.py':(ROOT/'guest/independent_boot_server.py',0o600),
                'lab/start.sh':(b'#!/bin/sh\nwhile [ ! -f /workspace/pxe-ready ]; do sleep 0.2; done\necho INDEPENDENT_SERVER_READY\nwhile :; do sleep 30; done\n',0o500),
                'pxe/boot.ipxe':(script(),0o600),'pxe/vmlinuz':(ROOT/base['vmlinuz']['path'],0o600),'pxe/initrd.gz':(initrd(base),0o600)})
            mother.start();deadline=time.monotonic()+60
            while time.monotonic()<deadline:
                path=mother.folder/'boot.log'
                if path.exists() and 'INDEPENDENT_SERVER_READY' in path.read_text(errors='replace'): break
                if mother.process.poll() is not None: raise RuntimeError('Private boot server exited')
                time.sleep(.2)
            else: raise TimeoutError('Private boot server not ready')
            target.start(iso);print('Stock Alpine ISO booting with default boot order; no keys or commands will be sent.',flush=True)
            deadline=time.monotonic()+45
            while time.monotonic()<deadline:
                if target.process.poll() is not None or mother.process.poll() is not None: raise RuntimeError('Owned stock OS VM exited')
                if switch.errors: raise RuntimeError(str(switch.errors))
                time.sleep(.5)
            snapshot=folder/'stock-os-screen.png';report['framebuffer_observer']=capture(target.vnc_port,snapshot)
            report['framebuffer']={'path':str(snapshot),'sha256':digest(snapshot)}
        except Exception as error: report['error']={'type':type(error).__name__,'message':str(error)}
        finally:
            # The mother's init syncs every three seconds. Preserve diagnostics
            # on an early startup failure before stopping its owned process.
            time.sleep(4)
            switch.close()
            for vm in reversed(machines):
                try: vm.stop()
                except Exception as error: cleanup.append(str(error))
            if not cleanup:
                for name in ('pxe-transfers.json','pxe-dhcp.log','learned-leases.json','pxe-server.log'):
                    try: (folder/name).write_bytes(read_image_file(mother.disk,name,maximum=1024**2))
                    except FileNotFoundError: pass
                    except ValueError as error: cleanup.append('Diagnostic read failed: '+name+': '+str(error))
                path=folder/'pxe-transfers.json';transfers=json.loads(path.read_text()) if path.exists() else []
                report['boot_transfers']=transfers;report['dhcp_client_events']=list(switch.dhcp)
                report['blank_disk_unchanged']=digest(target.disk)==before
                firmware_log=(target.folder/'firmware.log').read_text(errors='replace')
                report['firmware_booted_optical_media']='Booting from DVD/CD' in firmware_log
                report['passed']=not report.get('error') and not transfers and report['blank_disk_unchanged'] and report['firmware_booted_optical_media']
                if not cleanup:
                    for vm in machines:
                        if vm.disk.exists(): vm.disk.unlink()
            report.update(cleanup_failures=cleanup,all_owned_vms_stopped=not cleanup,disposable_disks_removed=not cleanup,
                elapsed_seconds=round(time.monotonic()-begin,3))
            if cleanup: report['passed']=False
            save(folder/'report.json',report);save(ROOT/'docs/validation'/('independent-stock-os-'+folder.name+'.json'),report)
        print(json.dumps({'passed':report['passed'],'report':str(folder/'report.json'),'framebuffer':report.get('framebuffer'),'error':report.get('error')},indent=2),flush=True)
        return 0 if report['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
