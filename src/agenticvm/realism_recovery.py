"""Exact owned-process abort for the separate realism lab; no enrollment replay."""
import json
from uuid import UUID
from .lan_lab import ROOT,save
from .lan_recovery import plain
from .chain import exclusive
from .qemu import WindowsProcess,find_qemu

NAMES=('mother','offshoot-1','offshoot-2','target','dhcp')
FILES=('workspace.ext2','blank.raw','infrastructure-initrd.gz','nvram.fd','os-initrd.gz')

def require_clean_history():
    parent=ROOT/'runtime/realism-runs'
    if not parent.exists(): return
    for folder in parent.iterdir():
        if not folder.is_dir() or not (folder/'owner.json').exists(): continue
        for name in ('report.json','recovery.json'):
            path=folder/name
            if path.exists():
                item=json.loads(path.read_text())
                if item.get('all_owned_vms_stopped',False) and not item.get('cleanup_failures',[]): break
        else: raise RuntimeError('Interrupted realism run requires recovery: '+folder.name)

def recover(ident):
    if str(UUID(ident))!=ident: raise ValueError('Canonical realism UUID required')
    parent=plain(ROOT/'runtime/realism-runs');folder=plain(parent/ident)
    with exclusive(parent):
        owner=json.loads((folder/'owner.json').read_text())
        with WindowsProcess(owner['pid']) as p:
            if p.alive() and p.created==owner['created']: raise RuntimeError('Controller is still running')
        prior=folder/'recovery.json'
        if prior.exists():
            result=json.loads(prior.read_text())
            if not result['passed']: raise RuntimeError('Previous recovery needs review')
            return {**result,'duplicate':True}
        result={'passed':False,'run_id':ident,'tasks_replayed':False,'resources':[],'cleanup_failures':[]}
        for name in NAMES:
            ownership=plain(folder/name/'ownership.json')
            if not ownership.exists(): continue
            state=json.loads(ownership.read_text())
            try:
                with WindowsProcess(state['pid'],terminate=True) as p:
                    if p.alive():
                        if p.created!=state['created'] or p.executable!=find_qemu() or str(p.executable)!=state['executable']:
                            raise ValueError('Owned process identity changed')
                        p.terminate();p.wait(10)
                    if p.alive(): raise RuntimeError('Owned VM did not stop')
                result['resources'].append({'vm':name,'stopped':True})
            except Exception as error: result['cleanup_failures'].append(str(error))
        if not result['cleanup_failures']:
            for name in NAMES:
                for filename in FILES:
                    path=plain(folder/name/filename)
                    if path.exists(): path.unlink()
            private=plain(folder/'private')
            if private.exists():
                allowed={name+suffix for name in NAMES[:3] for suffix in ('.key','.pem')}
                if any(p.name not in allowed or not p.is_file() or p.is_symlink() for p in private.iterdir()):
                    result['cleanup_failures'].append('Unexpected private file retained')
                else:
                    for p in private.iterdir(): p.unlink()
                    private.rmdir()
        result.update(passed=not result['cleanup_failures'],all_owned_vms_stopped=not result['cleanup_failures'])
        save(prior,result);return result
