"""Add final public evidence, preserving the native-tested executable/runtime."""
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source,'sha256').hexdigest()


def main():
    bundle = ROOT/'dist/Agent-Live-v1'
    native = json.loads((ROOT/'docs/validation/live-native-portable-report.json').read_text())
    recovery = json.loads((ROOT/'docs/validation/live-recovery-report.json').read_text())
    if not native['passed'] or not recovery['passed'] or sha(bundle/'Agent-Live.exe') != native['native_executable_sha256']:
        raise ValueError('Actual native and recovery proof required before finalization')
    manifest = json.loads((bundle/'live-manifest.json').read_text())
    for item in manifest['files']:
        if sha(bundle/item['path']) != item['sha256']:
            raise ValueError('Payload changed after native validation: '+item['path'])
    audit_path = ROOT/'docs/validation/test-scope-audit.json'
    audit = json.loads(audit_path.read_text(encoding='utf-8'))
    if not audit['passed'] or audit['host_tests']['count'] != 242:
        raise ValueError('Current passing host audit required')
    for item in audit['host_tests']['files']:
        if sha(ROOT/item['path']) != item['sha256']:
            raise ValueError('Host test source changed since its recorded execution')
    # Refresh integration references after their runs finish, without claiming
    # that the already-passed host suite was executed a second time here.
    present = {item['path'] for item in audit['live_vm_evidence']}
    for name,scope in (
        ('live-native-portable-report.json','native portable launcher and live Linux VMs'),
        ('live-recovery-report.json','actual live controller fault and owned VM recovery')):
        path = ROOT/'docs/validation'/name
        relative = path.relative_to(ROOT).as_posix()
        if relative not in present:
            audit['live_vm_evidence'].append({'path':relative,'scope':scope,
                'limitation':'One physical host; no physical multi-host or physical 4 GB validation.',
                'sha256':sha(path),'separate_physical_hosts_tested':False})
    audit['all_validation_json_files'] = [p.name for p in sorted((ROOT/'docs/validation').glob('*.json'))]
    audit['integration_evidence_refreshed_after_native_validation'] = True
    audit_path.write_text(json.dumps(audit,indent=2)+'\n',encoding='utf-8')
    selected = {item['path']:item for item in manifest['files']}
    evidence = ('test-scope-audit.json','live-native-portable-report.json','live-recovery-report.json')
    for name in evidence:
        source = ROOT/'docs/validation'/name
        relative = 'docs/validation/'+name
        target = bundle/relative
        shutil.copy2(source,target)
        selected[relative] = {'path':relative,'bytes':target.stat().st_size,'sha256':sha(target)}
    final_files = [selected[name] for name in sorted(selected)]
    original = {item['path']:item for item in manifest['files']}
    runtime_unchanged = all(item == original[item['path']] for item in final_files if not item['path'].startswith('docs/'))
    if not runtime_unchanged:
        raise ValueError('Finalization attempted to change the tested runtime')
    manifest.update(files=final_files,file_count=len(final_files),
                    runtime_unchanged_since_native_validation=True,
                    native_validation_report_sha256=sha(ROOT/'docs/validation/live-native-portable-report.json'))
    (bundle/'live-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    output = ROOT/'dist/Agent-Live-v1-release.zip'
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for item in final_files:
            name = item['path']
            if name.startswith('runtime/live-agent-runs/') or name.endswith(('.key','.sqlite')):
                raise ValueError('Private user state selected')
            if sha(bundle/name) != item['sha256']:
                raise ValueError('Selected final payload changed')
            archive.write(bundle/name,bundle.name+'/'+name)
        archive.write(bundle/'live-manifest.json',bundle.name+'/live-manifest.json')
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError('Final ZIP CRC failed')
    report = {'passed':True,'archive':str(output.relative_to(ROOT)),'bytes':output.stat().st_size,
              'sha256':sha(output),'static_files':len(final_files)+1,'crc_verified':True,
              'runtime_unchanged_since_native_validation':True,'documentation_only_finalization':True,
              'native_executable_sha256':sha(bundle/'Agent-Live.exe'),'private_runtime_state_in_archive':False}
    output.with_suffix('.archive.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
