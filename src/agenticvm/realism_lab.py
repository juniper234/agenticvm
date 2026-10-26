"""Finite enrollment compatibility/fault lab. Never attaches a physical NIC."""
from __future__ import annotations
import gzip,hashlib,importlib.util,json,os,shutil,socket,stat,struct,subprocess,threading,time
from pathlib import Path
from uuid import uuid4
from .lan_lab import ROOT,Switch,FrameDecoder,LabVM,mac,digest,save,encoded,completed_guest_report
from .independent_lab import FIRMWARE,firmware_manifest,blank_disk,image,seed_image
from .pxe_lab import validated_base
from .qemu import WindowsProcess,find_qemu
from .resources import check_memory_budget,whpx_status,memory_status
from .chain import exclusive
from .peers import Journal,verify_journal
from .ext2 import read_image_file
from .framebuffer_observer import capture

PARENT=ROOT/'runtime/realism-runs'
PROFILES=('bios-default','uefi-default','uefi-stock-rng','uefi-e1000','uefi-e1000e','uefi-virtio','uefi-http','uefi-tcg','network-boot-disabled','linux-os-control')
NAMES=('mother','offshoot-1','offshoot-2','target','dhcp')

class FaultSwitch(Switch):
    """At most five owned ports, learned client MAC, bounded DHCP and outage evidence."""
    def __init__(self):
        super().__init__();self.addresses={n:mac(n) for n in (1,2,3,5)}
        self.blocked=set();self.events=[];self.dhcp=[];self.drops=0;self.begin=time.monotonic()
    def set_blocked(self,member,blocked):
        if member!=4: raise ValueError('Only the disposable target cable may be interrupted')
        with self.lock:
            if blocked: self.blocked.add(member)
            else: self.blocked.discard(member)
            self.events.append({'target_blocked':blocked,'monotonic':time.monotonic(),'drops':self.drops})
    def listen(self,member):
        if member not in (1,2,3,4,5): raise ValueError('Owned five-port topology only')
        return super().listen(member)
    def _serve(self,member,listener):
        from .independent_lab import dhcp_event
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
                try: raw=conn.recv(65536)
                except socket.timeout: continue
                if not raw: return
                for frame in decoder.feed(raw):
                    source=frame[6:12]
                    with self.lock:
                        if member not in self.addresses:
                            if member!=4 or source[0]&1 or source in self.addresses.values(): raise ValueError('Invalid learned client')
                            self.addresses[member]=source
                        if self.addresses[member]!=source: raise ValueError('Hardware identity changed on owned port')
                        event=dhcp_event(frame)
                        if event and len(self.dhcp)<256:
                            self.dhcp.append({**event,'elapsed_seconds':round(time.monotonic()-self.begin,3)})
                        dest=next((n for n,a in self.addresses.items() if a==frame[:6]),None)
                        targets=[]
                        for n,pair in self.ports.items():
                            if n==member or (dest is not None and dest!=n): continue
                            if member in self.blocked or n in self.blocked: self.drops+=1;continue
                            targets.append(pair);key=f'{member}->{n}';self.stats[key]=self.stats.get(key,0)+len(frame)
                    packet=struct.pack('!I',len(frame))+frame
                    for peer,guard in targets:
                        with guard: peer.sendall(packet)
        except OSError as error:
            if not self.stop.is_set(): self.errors.append(str(error))
        except Exception as error: self.errors.append(type(error).__name__+': '+str(error))
        finally:
            with self.lock: self.ports.pop(member,None)
            if conn: conn.close()

def initrd(base,*,infrastructure=False,probe=True,public=None):
    spec=importlib.util.spec_from_file_location('realism_cpio',ROOT/'scripts/build-linux-probe.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    def file(path,mode=0o644): return stat.S_IFREG|mode,(ROOT/path).read_bytes().replace(b'\r\n',b'\n'),0,0
    entries={'init':file('guest/realism-init.sh',0o755),'dhcp-hook.sh':file('guest/realism-dhcp-hook.sh',0o755)}
    if infrastructure:
        # A network appliance does not need Python, OpenSSL, package metadata or
        # inference tools. Reuse only signed-package files from the pinned base.
        source=module.unpack_newc(gzip.decompress((ROOT/base['ram_root']['path']).read_bytes()))
        entries={}
        for name,(mode,data) in source.items():
            if stat.S_ISDIR(mode) or stat.S_ISLNK(mode) or name in ('usr/bin/busybox','usr/sbin/dnsmasq','etc/passwd','etc/group','etc/nsswitch.conf') or name.startswith(('usr/lib/x86_64-linux-gnu/','usr/lib/modules/')):
                entries[name]=(mode,data,0,0)
        spec=importlib.util.spec_from_file_location('realism_dhcp_config',ROOT/'guest/realism_dhcp.py')
        config_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(config_module)
        shell='''#!/bin/busybox sh
BB=/bin/busybox
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
$BB mount -t devtmpfs devtmpfs /dev || exit 1
exec </dev/console >/dev/console 2>&1
$BB mount -t proc proc /proc || exit 1
$BB mount -t sysfs sysfs /sys || exit 1
$BB mkdir -p /run
$BB modprobe e1000 || exit 1
$BB ip link set lo up
$BB ip link set eth0 up || exit 1
$BB ip addr add 192.0.2.5/24 dev eth0 || exit 1
/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/dhcp.conf &
child=$!
$BB sleep 1
kill -0 "$child" || exit 1
echo REALISM_DHCP_APPLIANCE_READY
while kill -0 "$child"; do $BB sleep 2; done
exit 1
'''
        entries.update({'init':(stat.S_IFREG|0o755,shell.encode(),0,0),
            'dev/console':(stat.S_IFCHR|0o600,b'',5,1),
            'dhcp.conf':(stat.S_IFREG|0o600,config_module.config().encode(),0,0),
            'bootfiles/ipxe.efi':(stat.S_IFREG|0o644,(ROOT/'tools/realism/ipxe.efi').read_bytes(),0,0),
            'bootfiles/autoexec.ipxe':(stat.S_IFREG|0o644,b'#!ipxe\ndhcp\nchain http://192.0.2.1:8080/boot.ipxe\n',0,0),
            'bootfiles':(stat.S_IFDIR|0o755,b'',0,0)})
        return gzip.compress(module.make_newc(entries),mtime=0)
    elif probe: entries['probe-only']=(stat.S_IFREG|0o600,b'boot only\n',0,0)
    else:
        entries['boot-trust.json']=(stat.S_IFREG|0o644,encoded({'mother_certificate':public['mother']['certificate'],
            'installer_sha256':digest(ROOT/'guest/lan_install.py')}),0,0)
        entries['boot-provision.py']=file('guest/pxe_bootstrap.py')
    network=json.loads((ROOT/'tools/kernel-network/manifest.json').read_text())
    for name,sha in network['files'].items():
        path=ROOT/'tools/kernel-network'/name
        if digest(path)!=sha: raise ValueError('Extra kernel module changed')
        entries['usr/lib/'+name]=(stat.S_IFREG|0o644,path.read_bytes(),0,0)
        for parent in Path('usr/lib/'+name).parents:
            if parent.as_posix()!='.': entries.setdefault(parent.as_posix(),(stat.S_IFDIR|0o755,b'',0,0))
    # Parents precede children in cpio; the kernel does not synthesize directories.
    entries=dict(sorted(entries.items(),key=lambda row:(row[0].count('/'),row[0])))
    return (ROOT/base['ram_root']['path']).read_bytes()+gzip.compress(module.make_newc(entries),mtime=0)

def boot_script():
    return b'#!ipxe\nkernel http://192.0.2.1:8080/vmlinuz initrd=initrd.gz console=ttyS0,115200n8 rdinit=/init panic=1\ninitrd --name initrd.gz http://192.0.2.1:8080/initrd.gz\nboot\n'

class OwnedVM(LabVM):
    def launch(self,argv,metadata):
        save(self.folder/'launch.json',{'argv':argv,'uuid':self.uuid,**metadata})
        with (self.folder/'stdout.log').open('wb') as out,(self.folder/'stderr.log').open('wb') as err:
            self.process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)
        with WindowsProcess(self.process.pid) as p:
            if not p.alive() or p.executable!=self.qemu: raise RuntimeError('Owned VM failed to start')
            self.binding={'pid':self.process.pid,'created':p.created,'executable':str(p.executable),'uuid':self.uuid}
        save(self.folder/'ownership.json',self.binding)

class DHCPVM(OwnedVM):
    def prepare(self):
        ram=self.folder/'infrastructure-initrd.gz'
        with ram.open('xb') as stream: stream.write(initrd(self.base,infrastructure=True))
        self.prepared_sha256=digest(ram)
        save(self.folder/'prepared-image.json',{'sha256':self.prepared_sha256,'bytes':ram.stat().st_size})
    def start(self):
        ram=self.folder/'infrastructure-initrd.gz'
        if not ram.exists(): self.prepare()
        if digest(ram)!=getattr(self,'prepared_sha256',None): raise ValueError('Prepared DHCP image changed')
        self.launch([str(self.qemu),'-L',str(FIRMWARE),'-name','Garden-DHCP-'+self.uuid,'-uuid',self.uuid,
            '-machine','q35','-accel','whpx','-m','256','-nodefaults','-display','none','-monitor','none','-no-reboot',
            '-kernel',str(ROOT/self.base['vmlinuz']['path']),'-initrd',str(ram),
            '-append','console=ttyS0,115200n8 rdinit=/init panic=1','-serial','file:'+str(self.folder/'boot.log'),
            '-netdev',f'socket,id=lan,connect=127.0.0.1:{self.port}',
            '-device','e1000,netdev=lan,romfile=,mac='+mac(5).hex(':')],{'prepared_infrastructure':True})

def target_argv(vm,profile):
    if profile not in PROFILES: raise ValueError('Unknown compatibility profile')
    argv=[str(vm.qemu),'-L',str(FIRMWARE),'-name','Garden-Realism-'+vm.uuid,'-uuid',vm.uuid,
        '-accel','whpx','-m','768','-display','none','-monitor','none','-no-reboot',
        '-serial','file:'+str(vm.folder/'boot.log'),'-debugcon','file:'+str(vm.folder/'firmware.log'),
        '-global','isa-debugcon.iobase=0x402','-drive','file='+str(vm.disk).replace(',',',,')+',format=raw']
    if profile.startswith('uefi'):
        stock=profile in ('uefi-default','uefi-stock-rng')
        code=(FIRMWARE/'edk2-x86_64-code.fd') if stock else ROOT/'tools/ovmf-debian/OVMF_CODE_4M.fd'
        nic='virtio-net-pci' if profile in ('uefi-virtio','uefi-http') else ('e1000e' if profile=='uefi-e1000e' else 'e1000')
        options=''
        if not stock:
            rom='' if nic=='virtio-net-pci' else str(FIRMWARE/('efi-e1000e.rom' if nic=='e1000e' else 'efi-e1000.rom'))
            options=',romfile='+rom+',bootindex=1'
        argv+=['-machine','q35','-drive','if=pflash,format=raw,readonly=on,file='+str(code),
            '-drive','if=pflash,format=raw,file='+str(vm.folder/'nvram.fd'),
            '-netdev',f'socket,id=lan,connect=127.0.0.1:{vm.port}',
            '-device',nic+',netdev=lan'+options]
        if not stock:
            argv+=['-fw_cfg','name=opt/org.tianocore/IPv4Support,string=yes',
                '-fw_cfg','name=opt/org.tianocore/IPv4PXESupport,string=yes',
                '-fw_cfg','name=opt/org.tianocore/VirtioNetSupport,string=yes']
        if profile!='uefi-default': argv+=['-object','rng-builtin,id=entropy','-device','virtio-rng-pci,rng=entropy']
    else:
        if profile=='network-boot-disabled':
            # Boot order alone does not disable SeaBIOS's option-ROM fallback.
            # Keep the adapter/cable but explicitly remove its executable ROM.
            argv+=['-netdev',f'socket,id=lan,connect=127.0.0.1:{vm.port}',
                '-device','e1000,netdev=lan,romfile=','-boot','order=c,strict=on']
        else: argv+=['-nic',f'socket,connect=127.0.0.1:{vm.port}']
    if profile=='uefi-tcg': argv[argv.index('-accel')+1]='tcg'
    if profile=='linux-os-control':
        argv+=['-kernel',str(ROOT/vm.base['vmlinuz']['path']),'-initrd',str(vm.folder/'os-initrd.gz'),
            '-append','console=ttyS0,115200n8 rdinit=/init panic=1']
    return argv

class TargetVM(OwnedVM):
    def __init__(self,*args,**kw):
        super().__init__(*args,**kw);self.disk=self.folder/'blank.raw'
    def start(self,profile):
        if profile.startswith('uefi'):
            vars=(FIRMWARE/'edk2-i386-vars.fd') if profile in ('uefi-default','uefi-stock-rng') else ROOT/'tools/ovmf-debian/OVMF_VARS_4M.fd'
            if profile=='uefi-http':
                code='import sys,runpy;sys.path.insert(0,"tools/python/firmware-v1");runpy.run_module("virt.firmware.vars",run_name="__main__")'
                result=subprocess.run([str(ROOT/'tools/python-runtime/3.13.16/python.exe'),'-I','-B','-W','ignore','-c',code,
                    '--input',str(vars),'--set-boot-uri','http://192.0.2.1:8080/ipxe.efi','--output',str(self.folder/'nvram.fd')],
                    cwd=ROOT,capture_output=True,text=True,timeout=30)
                if result.returncode: raise RuntimeError('UEFI HTTP boot preparation failed: '+result.stderr[-1000:])
            else: shutil.copyfile(vars,self.folder/'nvram.fd')
        if profile=='linux-os-control':
            spec=importlib.util.spec_from_file_location('basic_os_cpio',ROOT/'scripts/build-linux-probe.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            override={'init':(stat.S_IFREG|0o755,(ROOT/'guest/basic-linux-init.sh').read_bytes().replace(b'\r\n',b'\n'),0,0)}
            (self.folder/'os-initrd.gz').write_bytes(initrd(self.base)+gzip.compress(module.make_newc(override),mtime=0))
        prepared=profile.startswith('uefi') and profile not in ('uefi-default','uefi-stock-rng')
        self.launch(target_argv(self,profile),{'profile':profile,'fresh_blank_disk':True,
            'firmware_explicitly_selected':profile.startswith('uefi'),'secure_boot_enabled':False,
            'boot_order_override':profile in ('network-boot-disabled','linux-os-control') or prepared,
            'network_firmware_preparation':prepared,'hardware_rng_supplied':profile.startswith('uefi') and profile!='uefi-default',
            'network_boot_rom_disabled':profile=='network-boot-disabled',
            'initial_os_fixture_prepared':profile=='linux-os-control','boot_uri_preconfigured':profile=='uefi-http',
            'target_commands_or_shares':False})

def wait_marker(vm,marker,seconds,switch):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if vm.process and vm.process.poll() is not None:
            raise RuntimeError(vm.folder.name+' exited: '+(vm.folder/'stderr.log').read_text(errors='replace')[-1200:])
        if switch.errors: raise RuntimeError(str(switch.errors))
        path=vm.folder/'boot.log'
        if path.exists() and marker in path.read_text(errors='replace'): return
        if vm.folder.name=='target' and path.exists() and 'Shell> ' in path.read_text(errors='replace'):
            raise RuntimeError('UEFI entered its shell without a usable network boot entry')
        time.sleep(.3)
    raise TimeoutError(vm.folder.name+' did not reach '+marker)

def finish(folder,machines,switch,journal,report,before,begin,private=None):
    failures=[];switch.close()
    for vm in reversed(machines):
        try: vm.stop()
        except Exception as error: failures.append(str(error))
    if not failures:
        target=folder/'target/blank.raw'
        if target.exists():
            report['blank_disk_unchanged']=digest(target)==before
            if not report['blank_disk_unchanged']: report['passed']=False
        mother=folder/'mother/workspace.ext2'
        if mother.exists():
            for name in ('pxe-transfers.json','pxe-server.log','lan-report.json'):
                try: (folder/('mother-'+name)).write_bytes(read_image_file(mother,name,maximum=2*1024**2))
                except Exception as error: report.setdefault('diagnostic_collection_errors',[]).append(str(error))
        for vm in machines:
            for name in ('workspace.ext2','blank.raw','infrastructure-initrd.gz','nvram.fd','os-initrd.gz'):
                path=vm.folder/name
                if path.exists(): path.unlink()
        if private:
            allowed={name+suffix for name in ('mother','offshoot-1','offshoot-2') for suffix in ('.key','.pem')}
            if any(p.name not in allowed or not p.is_file() or p.is_symlink() for p in private.iterdir()):
                failures.append('Unexpected private file retained')
            else:
                for p in private.iterdir(): p.unlink()
                private.rmdir()
    report.update(cleanup_failures=failures,all_owned_vms_stopped=not failures,
        disposable_disks_keys_removed=not failures,elapsed_seconds=round(time.monotonic()-begin,3),
        dhcp_client_events=switch.dhcp,learned_client_mac=switch.addresses.get(4,b'').hex(':'),
        cable_events=switch.events,dropped_frames=switch.drops,lan_bytes=dict(switch.stats))
    if failures: report['passed']=False
    journal.add('cleanup',failures=failures);journal.close();report['checkpoints']=verify_journal(folder/'checkpoints.jsonl')
    report['source_changed_during_run']=report['source_sha256']!=sources()
    if report['source_changed_during_run']: report['passed']=False
    save(folder/'report.json',report)
    save(ROOT/'docs/validation'/('realism-'+folder.name+'.json'),report)
    print(json.dumps({'passed':report['passed'],'report':str(folder/'report.json'),'error':report.get('error')},indent=2),flush=True)
    return 0 if report['passed'] else 1

def sources():
    return {str(p.relative_to(ROOT)):digest(p) for pattern in ('src/agenticvm/realism*.py','guest/realism*','guest/basic-linux-init.sh','scripts/*realism*.py') for p in ROOT.glob(pattern) if p.is_file()}

def preflight():
    from .realism_recovery import require_clean_history
    require_clean_history()
    if os.name!='nt' or not whpx_status()['available']: raise RuntimeError('Existing Windows WHPX required')
    firmware_manifest()
    tools=json.loads((ROOT/'tools/realism/manifest.json').read_text())
    for name,sha in tools['files'].items():
        if digest(ROOT/'tools/realism'/name)!=sha: raise ValueError('Realism tool changed: '+name)
    ovmf=json.loads((ROOT/'tools/ovmf-debian/manifest.json').read_text())
    for name,sha in ovmf['files'].items():
        if digest(ROOT/'tools/ovmf-debian'/name)!=sha: raise ValueError('Debian OVMF changed: '+name)
    return validated_base()

def begin_run(case,profile):
    folder=PARENT/str(uuid4());folder.mkdir()
    with WindowsProcess(os.getpid()) as p: save(folder/'owner.json',{'pid':os.getpid(),'created':p.created,'executable':str(p.executable)})
    journal=Journal(folder,folder.name)
    report={'schema':'agenticvm.realism-run.v1','passed':False,'run_id':folder.name,'case':case,'profile':profile,
        'physical_hardware_tested':False,'physical_4gb_host_tested':False,'initial_boot_authenticated':False,
        'target_storage_persistent':False,'physical_network_attached':False,'host_memory':memory_status(),
        'source_sha256':sources()}
    return folder,journal,report

def probe(profile='uefi-e1000',delay=0):
    base=preflight();check_memory_budget(1280);PARENT.mkdir(parents=True,exist_ok=True)
    with exclusive(PARENT):
        folder,journal,report=begin_run('boot-probe',profile);switch=FaultSwitch();machines=[];before=None;begin=time.monotonic()
        try:
            target=TargetVM(folder/'target',4,switch,base,find_qemu(),768);machines.append(target);blank_disk(target);before=digest(target.disk)
            mother=LabVM(folder/'mother',1,switch,base,find_qemu(),256);machines.append(mother)
            image(mother.disk,{'lab-address':(b'192.0.2.1\n',0o600),'lan-config.json':(b'{}',0o600),
                'pxe-open':(b'one owned client\n',0o600),'pxe_server.py':(ROOT/'guest/realism_boot_server.py',0o600),
                'independent_boot_server.py':(ROOT/'guest/independent_boot_server.py',0o600),
                'lab/start.sh':(b'#!/bin/sh\nwhile [ ! -f /workspace/pxe-ready ]; do sleep .2; done\necho REALISM_HTTP_READY\nwhile :; do sleep 30; done\n',0o500),
                'pxe/boot.ipxe':(boot_script(),0o600),'pxe/vmlinuz':(ROOT/base['vmlinuz']['path'],0o600),
                'pxe/ipxe.efi':(ROOT/'tools/realism/ipxe.efi',0o600),
                'pxe/initrd.gz':(initrd(base),0o600)})
            mother.start();wait_marker(mother,'REALISM_HTTP_READY',60,switch)
            dhcp=DHCPVM(folder/'dhcp',5,switch,base,find_qemu(),256);machines.append(dhcp)
            # Preparation is not part of the requested service-start delay.
            dhcp.prepare();target_started=None
            if delay:
                target.start(profile);target_started=time.monotonic();journal.add('target_on_before_dhcp',delay_seconds=delay)
                time.sleep(delay)
                dhcp.start()
            else: dhcp.start()
            wait_marker(dhcp,'REALISM_DHCP_APPLIANCE_READY',60,switch)
            report['dhcp_ready_after_target_seconds']=round(time.monotonic()-target_started,3) if target_started else None
            report['dhcp_image_prepared_before_target_power_on']=True
            if not target.process: target.start(profile)
            journal.add('target_started',profile=profile,ownership=target.binding)
            print('Native boot probe: '+profile+'; separate DHCP VM'+(' delayed '+str(delay)+'s' if delay else ''),flush=True)
            if profile in ('network-boot-disabled','uefi-default','linux-os-control'):
                if profile=='linux-os-control': wait_marker(target,'BASIC_LINUX_DHCP_READY_NO_AGENT',60,switch)
                deadline=time.monotonic()+35
                while time.monotonic()<deadline:
                    if switch.errors: raise RuntimeError(str(switch.errors))
                    if any(vm.process.poll() is not None for vm in machines): raise RuntimeError('Negative-control VM exited during observation')
                    time.sleep(.5)
                text=(target.folder/'boot.log').read_text(errors='replace') if (target.folder/'boot.log').exists() else ''
                if profile=='uefi-default' and 'Shell> ' not in text: raise ValueError('Default UEFI control did not reach its observed firmware state')
                if profile=='network-boot-disabled':
                    firmware=(target.folder/'firmware.log').read_text(errors='replace')
                    if 'Booting from Hard Disk' not in firmware: raise ValueError('BIOS control did not attempt its configured disk boot')
                if 'REALISM_NETWORK_BOOT_EXECUTED' in text: raise ValueError('Negative control unexpectedly booted a garden payload')
                if profile!='linux-os-control' and switch.dhcp: raise ValueError('Network-disabled control unexpectedly requested DHCP')
                if profile=='linux-os-control' and not switch.dhcp: raise ValueError('OS control did not prove real DHCP connectivity')
                report.update(passed=True,expected_no_enrollment_observed=True,
                    factory_default_network_enrollment_supported=False,
                    negative_control_remained_live_during_observation=True,
                    independently_booting_dhcp_enabled_linux_control=profile=='linux-os-control')
            else:
                wait_marker(target,'REALISM_NETWORK_BOOT_EXECUTED',140,switch)
                text=(target.folder/'boot.log').read_text(errors='replace')
                if 'REALISM_LINUX_DHCP_BOUND 192.0.2.4 server=192.0.2.5' not in text:
                    raise ValueError('Linux did not independently obtain its lease from the separate appliance')
                report.update(passed=True,network_linux_booted=True,linux_dhcp_lease_observed=True,
                    separate_dhcp_vm=True,dhcp_start_delay_seconds=delay,secure_boot_enabled=False)
            time.sleep(4)
        except Exception as error:
            report.update(passed=False,error={'type':type(error).__name__,'message':str(error)});journal.add('failed',error=report['error'])
        finally: code=finish(folder,machines,switch,journal,report,before,begin)
        return code
