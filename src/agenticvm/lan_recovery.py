"""Abort an interrupted owned LAN lab. Never replay installation/model work."""
import json
from pathlib import Path
from uuid import UUID
from .chain import exclusive
from .lan_lab import ROOT,NAMES,save
from .qemu import WindowsProcess,find_qemu

def plain(path):
    path=path.absolute()
    if any(item.is_symlink() or getattr(item,'is_junction',lambda:False)() for item in (path,*path.parents)):
        raise ValueError('Redirected recovery paths are refused')
    return path

def recover(run_id,*,delegated=False):
    if str(UUID(run_id))!=run_id: raise ValueError('Canonical lab run UUID required')
    parent=plain(ROOT/('runtime/delegated-enrollment-runs' if delegated else 'runtime/lan-enrollment-runs'));folder=plain(parent/run_id)
    with exclusive(parent):
        owner=json.loads((folder/'owner.json').read_text())
        with WindowsProcess(owner['pid']) as process:
            if process.alive() and process.created==owner['created']:
                raise RuntimeError('The lab controller is still running; recovery refused')
        if (folder/'recovery.json').exists():
            prior=json.loads((folder/'recovery.json').read_text())
            if not prior['passed']: raise RuntimeError('Previous recovery needs manual review')
            return {**prior,'duplicate':True}
        result={'passed':False,'run_id':run_id,'duplicate':False,'tasks_replayed':False,'resources':[],'failures':[]}
        qemu=find_qemu()
        for name in NAMES:
            directory=plain(folder/name);ownership=directory/'ownership.json'
            if not ownership.exists(): continue
            state=json.loads(ownership.read_text())
            try:
                with WindowsProcess(state['pid'],terminate=True) as process:
                    if process.alive():
                        if process.created!=state['created'] or process.executable!=qemu or str(process.executable)!=state['executable']:
                            raise RuntimeError('Owned VM identity mismatch')
                        process.terminate()
                        process.wait(10)
                    if process.alive(): raise RuntimeError('Owned VM did not stop')
                result['resources'].append({'vm':name,'uuid':state['uuid'],'stopped':True})
            except Exception as error: result['failures'].append({'vm':name,'error':str(error)})
        if not result['failures']:
            for name in NAMES:
                disk=plain(folder/name/'workspace.ext2')
                if disk.is_file(): disk.unlink()
            private=plain(folder/'private')
            allowed={stem+suffix for stem in NAMES[:3] for suffix in ('.pem','.key')}
            allowed|={'enroll_key','enroll_key.pub','ssh_host_key','ssh_host_key.pub'}
            if private.exists():
                files=list(private.iterdir())
                if any(path.name not in allowed or not path.is_file() or path.is_symlink() for path in files):
                    result['failures'].append({'private':'Unexpected provisioning files retained'})
                else:
                    for path in files: path.unlink()
                    private.rmdir()
        result['passed']=not result['failures']
        result['disposable_disks_and_private_identities_removed']=result['passed']
        save(folder/'recovery.json',result)
        return result
