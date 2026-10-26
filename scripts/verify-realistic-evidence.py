"""Read back native evidence and exact process cleanup; does not launch any VM."""
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path
from uuid import UUID
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from agenticvm.lan_lab import save,digest,reconcile
from agenticvm.qemu import find_qemu,WindowsProcess
from agenticvm.peers import verify_journal
from agenticvm.realism_recovery import NAMES,FILES

def read(path): return json.loads(path.read_text())
def within(path):
    p=Path(path).resolve()
    if not p.is_relative_to(ROOT): raise ValueError('Evidence points outside this workspace')
    return p
def stopped(ownership):
    state=read(ownership)
    with WindowsProcess(state['pid']) as p:
        if p.alive() and p.created==state['created']: raise ValueError('An exact owned test process remains alive')
def clean(folder):
    if (folder/'private').exists(): raise ValueError('Private test keys remain')
    for name in NAMES:
        for filename in FILES:
            if (folder/name/filename).exists(): raise ValueError('Writable disposable test input remains')
        ownership=folder/name/'ownership.json'
        if ownership.exists(): stopped(ownership)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--suite',required=True)
    a=parser.parse_args();path=within(a.suite);suite=read(path)
    if not suite['passed'] or suite['native_scenarios_passed']!=12: raise ValueError('Full native suite has not passed')
    tests=suite['host_tests']
    if tests['run']<310 or any(tests[k] for k in ('failures','errors','skipped')): raise ValueError('Host tests incomplete')
    if digest(within(tests['log']))!=tests['log_sha256']: raise ValueError('Host test log changed')
    for name,sha in suite['source_sha256'].items():
        if digest(ROOT/name)!=sha: raise ValueError('Tested source changed: '+name)
    spec=importlib.util.spec_from_file_location('realistic_suite_verifier',ROOT/'scripts/verify-garden-enrollment.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    zeros=hashlib.sha256()
    for _ in range(512): zeros.update(bytes(1024**2))
    zero_sha=zeros.hexdigest();models=[];controls=[];coverage=set()
    for item in suite['cases']:
        receipt_path=within(item['path'])
        if digest(receipt_path)!=item['sha256']: raise ValueError('Native receipt changed')
        r=module.validate(receipt_path);folder=receipt_path.parent;clean(folder)
        key=(r['case'],r['profile'],r.get('tampered'))
        if key in coverage: raise ValueError('A scenario was counted more than once')
        coverage.add(key)
        inventory=read(folder/'target/initial-inventory.json')
        if inventory['sha256']!=zero_sha or inventory['files'] or inventory['parent_vm'] is not None or inventory['source_snapshot'] is not None:
            raise ValueError('Target did not begin with an independently created all-zero disk')
        launch=read(folder/'target/launch.json');argv=launch['argv']
        if r['profile']!='linux-os-control':
            for forbidden in ('-kernel','-initrd','-append','-qmp','-virtfs','-cdrom'):
                if forbidden in argv: raise ValueError('A target used a forbidden guest bootstrap/control channel')
        if '-nic' in argv:
            backend=argv[argv.index('-nic')+1]
        else: backend=argv[argv.index('-netdev')+1]
        if not backend.startswith('socket,') or 'connect=127.0.0.1:' not in backend: raise ValueError('Target has a non-private carrier')
        if r['profile']=='uefi-stock-rng':
            if launch['boot_order_override'] or launch['network_firmware_preparation'] or 'bootindex=' in str(argv) or 'romfile=' in str(argv):
                raise ValueError('Stock UEFI plus entropy profile was silently prepared for garden boot')
        if r['profile'] in ('uefi-default','network-boot-disabled','linux-os-control'):
            if not r['expected_no_enrollment_observed'] or not r['negative_control_remained_live_during_observation']:
                raise ValueError('Negative control was not a live system observation')
        if r['profile']=='network-boot-disabled' and not launch['network_boot_rom_disabled']:
            raise ValueError('The negative boot control did not disable its executable NIC ROM')
        if r['case'] in ('lfm-fault-enrollment','secure-lfm-fault-enrollment'):
            guest=read(folder/'guest-report.json');proof=reconcile(guest['statuses'])
            target=guest['statuses']['sprout-4']
            if guest['target_receipt']['installed']['process']['pid']!=target['pid']: raise ValueError('Model agent process identity changed')
            if not r['target_model_repacking_disabled_verified'] or not r['linux_dhcp_renewals_observed']: raise ValueError('Low-memory/runtime lease evidence absent')
            for status in guest['statuses'].values():
                model=status['model']
                if not (model['execution_location']=='Linux guest' and model['weights_verified_inside_vm'] and model['server_alive'] and model['ready']):
                    raise ValueError('Actual guest model evidence incomplete')
                if model['cpu_threads']!=1 or model['context_tokens']!=1024 or model['gpu']: raise ValueError('Model resource profile changed')
                if status['dns'].strip() or status['interfaces']!=['eth0','lo']: raise ValueError('Unexpected guest network configuration')
                if any(row.split()[1]=='00000000' for row in status['routes'].splitlines()[1:] if row.strip()): raise ValueError('Guest has an Internet default route')
            if not r['dropped_frames'] or not r['recovered_after_network_failure'] or r['model_tasks_replayed']:
                raise ValueError('Network recovery proof missing')
            if r['case']=='secure-lfm-fault-enrollment':
                uki=folder/'garden-enrollment.efi'
                if digest(uki)!=r['protected_boot_uki']['sha256']: raise ValueError('Protected actual-model image changed')
                if not (r['initial_boot_authenticated'] and r['secure_boot_enabled'] and launch['secure_boot_enabled']): raise ValueError('Protected model boot was not enforced')
                if r['protected_boot_uki']['authenticode_sha256'] not in launch['firmware_trust']['allowed_authenticode_sha256']:
                    raise ValueError('Firmware trust did not cover the complete actual-model bootstrap')
                if 'mch.extended-tseg-mbytes=16' not in argv or 'q35,smm=on' not in argv: raise ValueError('Secure SMM profile changed')
                if 'tcg,tb-size=64' not in argv: raise ValueError('Secure test translation-cache budget changed')
            models.append({'profile':r['profile'],**proof,'contact_seconds':r['contact_seconds'],
                'dhcp_renewals':r['linux_dhcp_renewals_observed'],'resource_metrics':r['resource_metrics']})
        if r['case']=='secure-network-boot':
            log=(folder/'target/boot.log').read_text(errors='replace')
            if r['tampered']:
                if not r['modified_uki_rejected_before_linux'] or 'REALISM_SECURE_BOOT_STATE' in log or not any(x in log.lower() for x in ('access denied','security violation','permission denied')):
                    raise ValueError('Modified whole-image rejection not observed')
                if r['served_image_sha256']==r['uki']['sha256']: raise ValueError('Negative boot image was not actually modified')
            elif not (r['initial_boot_authenticated'] and r['linux_observed_secure_boot_one'] and 'REALISM_SECURE_BOOT_STATE 1' in log):
                raise ValueError('Protected Linux boot not observed')
            controls.append({'tampered':r['tampered'],'run_id':r['run_id'],'passed':True})
    if len(models)!=3 or len(controls)!=1 or not controls[0]['tampered']: raise ValueError('Protected/unprotected scenario coverage incomplete')
    expected={('boot-probe',p,None) for p in ('uefi-default','network-boot-disabled','linux-os-control','bios-default','uefi-e1000e')}
    expected.update({('lfm-fault-enrollment','uefi-stock-rng',None),('lfm-fault-enrollment','uefi-virtio',None),
        ('secure-lfm-fault-enrollment','uefi-secure-uki',None),('secure-network-boot','uefi-secure-uki',True)})
    if coverage!=expected: raise ValueError('Firmware/OS/model coverage is incomplete')
    if sum(x['actual_model_completions'] for x in models)!=30: raise ValueError('Thirty model completions not reconciled')
    sb_path=within(suite['secure_boot_controls']['path']);sb=read(sb_path)
    if digest(sb_path)!=suite['secure_boot_controls']['sha256'] or not sb['passed']: raise ValueError('Secure Boot control receipt changed')
    sb_id=sb_path.stem.removeprefix('secure-boot-controls-');UUID(sb_id)
    for name in ('allowed','modified'):
        f=ROOT/'runtime/secureboot-runs'/sb_id/name
        stopped(f/'ownership.json')
        if (f/'nvram.fd').exists(): raise ValueError('Secure Boot control NVRAM remains')
    crash_path=within(suite['controller_crash']['path']);crash=read(crash_path)
    if digest(crash_path)!=suite['controller_crash']['sha256'] or not crash['passed'] or crash['tasks_replayed']: raise ValueError('Crash receipt changed')
    f=ROOT/'runtime/realism-runs'/crash['run_id'];clean(f)
    if read(f/'recovery.json')!=crash['recovery'] or not crash['second_recovery_idempotent']: raise ValueError('Underlying recovery receipt changed')
    historical=0
    for f in (ROOT/'runtime/realism-runs').iterdir():
        if f.is_dir() and (f/'owner.json').exists(): clean(f);historical+=1
    tools=read(ROOT/'tools/build-tools-lock.json')['sources']
    qemu=next(x for x in tools['qemu']['files'] if x['path']=='qemu-system-x86_64.exe')
    if digest(find_qemu())!=qemu['sha256']: raise ValueError('Verified QEMU executable changed')
    if digest(ROOT/'tools/zig/zig-x86_64-windows-0.15.2/zig.exe')!=tools['zig']['exe_sha256']: raise ValueError('Verified Zig executable changed')
    manifests={str(p.relative_to(ROOT)):digest(p) for p in (
        ROOT/'tools/build-tools-lock.json',ROOT/'tools/realism/manifest.json',ROOT/'tools/realism/firmware-python-lock.json',
        ROOT/'tools/python/firmware-v1/verified-files.json',ROOT/'tools/ovmf-debian/manifest.json',
        ROOT/'tools/kernel-network/manifest.json',ROOT/'tools/secure-kernel/manifest.json',ROOT/'tools/uki-stub/manifest.json')}
    for directory in ('tools/realism','tools/ovmf-debian','tools/kernel-network','tools/secure-kernel'):
        r=read(ROOT/directory/'manifest.json')
        for name,sha in r['files'].items():
            if digest(ROOT/directory/name)!=sha: raise ValueError('Pinned test helper changed')
    python=read(ROOT/'tools/python/firmware-v1/verified-files.json')
    for name,sha in python['files'].items():
        if digest(ROOT/'tools/python/firmware-v1'/name)!=sha: raise ValueError('Pinned firmware Python helper changed')
    old=ROOT/'dist/Garden-Sprout-LFM-v1/Sprout.exe'
    oldsha=digest(old)
    if oldsha!='dd359f7c8a1539e180fdc5df177052ef320dd14d57780d30883b52843ade8bf6': raise ValueError('Earlier one-file alternative changed')
    result={'schema':'agenticvm.realistic-validation.v1','passed':True,'host_tests':tests,
        'native_scenarios_passed':12,'actual_model_completions':30,'completed_model_exchanges':15,
        'actual_model_runs':models,'authenticated_network_boot_controls':controls,
        'suite':{'path':str(path),'sha256':digest(path)},'input_manifests_sha256':manifests,
        'all_historical_owned_realism_runs_cleaned':historical,'all_owned_test_vms_stopped':True,
        'all_target_blank_disks_unchanged':True,'old_one_file_lfm_sha256':oldsha,
        'physical_hardware_tested':False,'physical_4gb_host_tested':False,'overnight_soak_tested':False,
        'limits':['Physical acceptance requires spare hardware and an isolated Ethernet network.',
            'Protected boot uses explicitly preprovisioned image hashes; it is not factory-default enrollment.',
            'Unprotected default-boot profiles still trust the isolated boot LAN.',
            'The one-client admission window is not TPM device attestation.',
            'Target agent is RAM-only; cold-reboot identity persistence is not implemented.',
            'Controller crash is ownership-safe abort, not automatic mother-service continuation.',
            'No arbitrary running-OS recruitment, recursive spreading, physical LAN attachment or Internet path.']}
    output=ROOT/'docs/validation/realistic-validation-final.json';save(output,result)
    print(json.dumps({'passed':True,'report':str(output),'native_cases':12,'model_completions':30},indent=2))

if __name__=='__main__': main()
