"""Abort only a crashed PXE experiment's owned VMs; never replay enrollment."""
import json
from uuid import UUID
from .chain import exclusive
from .lan_lab import ROOT,NAMES,save
from .lan_recovery import plain
from .qemu import WindowsProcess,find_qemu
from .ext2 import read_image_file

def recover(run_id):
    if str(UUID(run_id))!=run_id: raise ValueError('Canonical PXE run UUID required')
    parent=plain(ROOT/'runtime/pxe-enrollment-runs');folder=plain(parent/run_id)
    with exclusive(parent):
        owner=json.loads((folder/'owner.json').read_text())
        with WindowsProcess(owner['pid']) as process:
            if process.alive() and process.created==owner['created']: raise RuntimeError('PXE controller is still running')
        if (folder/'recovery.json').exists():
            prior=json.loads((folder/'recovery.json').read_text())
            if not prior['passed']: raise RuntimeError('Prior PXE recovery requires review')
            return {**prior,'duplicate':True}
        result={'passed':False,'run_id':run_id,'tasks_replayed':False,'resources':[],'failures':[]}
        qemu=find_qemu()
        for name in NAMES:
            ownership=plain(folder/name/'ownership.json')
            if not ownership.exists(): continue
            state=json.loads(ownership.read_text())
            try:
                with WindowsProcess(state['pid'],terminate=True) as process:
                    if process.alive():
                        if process.created!=state['created'] or process.executable!=qemu or str(process.executable)!=state['executable']:
                            raise RuntimeError('Owned PXE VM identity mismatch')
                        process.terminate();process.wait(10)
                    if process.alive(): raise RuntimeError('Owned PXE VM did not stop')
                result['resources'].append({'vm':name,'stopped':True,'uuid':state['uuid']})
            except Exception as error: result['failures'].append({'vm':name,'error':str(error)})
        if not result['failures']:
            mother=plain(folder/'mother/workspace.ext2')
            if mother.exists():
                for name in ('pxe-server.log','pxe-dhcp.log','pxe-transfers.json','lan-report.json'):
                    try: (folder/('recovered-mother-'+name)).write_bytes(read_image_file(mother,name,maximum=2*1024**2))
                    except FileNotFoundError: pass
            for name in NAMES:
                disk=plain(folder/name/'workspace.ext2')
                if disk.is_file(): disk.unlink()
            private=plain(folder/'private');allowed={name+suffix for name in NAMES[:3] for suffix in ('.key','.pem')}
            if private.exists():
                paths=list(private.iterdir())
                if any(path.name not in allowed or not path.is_file() or path.is_symlink() for path in paths):
                    result['failures'].append({'private':'Unexpected private fixture files retained'})
                else:
                    for path in paths: path.unlink()
                    private.rmdir()
        result['passed']=not result['failures'];result['disposable_disks_and_private_identities_removed']=result['passed']
        save(folder/'recovery.json',result);return result
