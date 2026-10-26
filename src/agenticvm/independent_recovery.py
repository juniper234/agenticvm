"""Abort only an interrupted independent-VM experiment; never replay actions."""
import json
from uuid import UUID
from .lan_lab import ROOT,save
from .lan_recovery import plain
from .chain import exclusive
from .qemu import WindowsProcess,find_qemu

NAMES=('mother','offshoot-1','offshoot-2','independent-target')

def require_clean_history():
    parent=ROOT/'runtime/independent-vm-runs'
    if not parent.exists(): return
    for folder in parent.iterdir():
        if not folder.is_dir() or not (folder/'owner.json').exists(): continue
        if (folder/'recovery.json').exists():
            if json.loads((folder/'recovery.json').read_text())['passed']: continue
        if (folder/'report.json').exists():
            prior=json.loads((folder/'report.json').read_text())
            if prior.get('all_owned_vms_stopped') and not prior.get('cleanup_failures'): continue
        raise RuntimeError('Prior independent VM run requires explicit ownership recovery: '+folder.name)

def recover(ident):
    if str(UUID(ident))!=ident: raise ValueError('Canonical independent run UUID required')
    parent=plain(ROOT/'runtime/independent-vm-runs');folder=plain(parent/ident)
    with exclusive(parent):
        owner=json.loads((folder/'owner.json').read_text())
        with WindowsProcess(owner['pid']) as p:
            if p.alive() and p.created==owner['created']: raise RuntimeError('Controller is still running')
        if (folder/'recovery.json').exists():
            prior=json.loads((folder/'recovery.json').read_text())
            if not prior['passed']: raise RuntimeError('Previous recovery requires review')
            return {**prior,'duplicate':True}
        result={'passed':False,'run_id':ident,'tasks_replayed':False,'resources':[],'failures':[]}
        qemu=find_qemu()
        for name in NAMES:
            path=plain(folder/name/'ownership.json')
            if not path.exists(): continue
            state=json.loads(path.read_text())
            try:
                with WindowsProcess(state['pid'],terminate=True) as p:
                    if p.alive():
                        if p.created!=state['created'] or p.executable!=qemu or str(p.executable)!=state['executable']:
                            raise RuntimeError('Owned process identity changed')
                        p.terminate();p.wait(10)
                    if p.alive(): raise RuntimeError('Owned VM did not stop')
                result['resources'].append({'vm':name,'uuid':state['uuid'],'stopped':True})
            except Exception as error: result['failures'].append({'vm':name,'error':str(error)})
        if not result['failures']:
            for name in NAMES:
                for filename in ('workspace.ext2','blank.raw'):
                    path=plain(folder/name/filename)
                    if path.exists(): path.unlink()
            private=plain(folder/'private')
            allowed={name+suffix for name in NAMES[:3] for suffix in ('.key','.pem')}
            if private.exists():
                paths=list(private.iterdir())
                if any(p.name not in allowed or not p.is_file() or p.is_symlink() for p in paths):
                    result['failures'].append({'private':'Unexpected files retained'})
                else:
                    for path in paths: path.unlink()
                    private.rmdir()
        result['passed']=not result['failures'];save(folder/'recovery.json',result);return result
