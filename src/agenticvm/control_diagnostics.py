"""Read-only capabilities, resource health and bounded owned-log access."""
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import time

from .control_store import checked,fail
from .resources import memory_status,whpx_status

PROFILES={'desktop':'linux','android':'android','windows':'windows','custom':'custom'}
LOGS={'linux':{'boot':'boot.log','backend':'stderr.log'},
    'android':{'emulator':'emulator.log','adb':'adb.log'},
    'windows':{'boot':'console.log','backend':'stderr.log','supervisor':'supervisor.log','reboots':'reboot-events.jsonl'},
    'custom':{'backend':'stderr.log'}}


def state(controller):
    return controller.store.load(required=False) or {}


def generation(controller):
    saved=state(controller)
    if not saved.get('registered'):
        return None
    identity={key:saved.get(key) for key in ('uuid','pid','process_created','launcher','processes')}
    return hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()[:32]


def unwrap(response):
    if not response.get('ok'):
        error=response.get('error',{})
        fail(error.get('message','Guest operation failed.'),error.get('code','guest_error'))
    return response['result']


def observe(controller):
    result=unwrap(controller.status())
    result['generation']=generation(controller) if result.get('registered') else None
    result['vm']=PROFILES[controller.profile]
    return result


def capabilities(controller):
    vm=PROFILES[controller.profile]
    if vm == 'custom':
        return {'vm':vm,'os_id':controller.os_id,'profile':'custom','screen':True,'keyboard':True,'pointer_move':True,
            'commands':False,'files':False,'jobs':False,'checkpoints':False,'sync':False,'sessions':False,
            'touch':False,'unicode_text_bytes':0,'ascii_text_characters':128,'network_required_for_control':False,
            'logs':['backend'],'wait_conditions':['desktop','stopped'],'generation':generation(controller)}
    return {'vm':vm,'profile':controller.profile,'uuid':state(controller).get('uuid'),
        'generation':generation(controller),'screen':True,'commands':True,'files':True,
        'keyboard':True,'pointer_move':vm!='android','touch':vm=='android',
        'unicode_text_bytes':4096,'max_file_bytes':1048576,
        'command_shell':'powershell' if vm=='windows' else 'sh',
        'workspace':'C:/workspace/' if vm=='windows' else '/workspace/',
        'logs':list(LOGS[vm]),'network_required_for_control':False,
        'wait_conditions':['guest','desktop','stopped'],'jobs':False,'checkpoints':False,
        'sync':False,'sessions':False}


def health(controller):
    memory=memory_status()
    disk=shutil.disk_usage(controller.workspace if controller.workspace.exists() else controller.root)
    saved=state(controller)
    vm=PROFILES[controller.profile]
    requested=saved['memory_mib'] if 'memory_mib' in saved else {'linux':768,'android':2560,'windows':2048,'custom':768}[vm]
    minimum_disk=8*1024**3 if vm=='android' else 18*1024**3 if vm=='windows' and not saved.get('disk') else 512*1024**2
    reasons=[]
    budget=requested+(512 if vm=='android' else 0) # Emulator overhead used by AndroidBackend.start.
    if memory['available_physical_mib']<budget+512 or memory['available_commit_mib']<budget+384:
        reasons.append({'code':'insufficient_host_memory','message':'Free physical and committed memory is below this profile requirement.'})
    if disk.free<minimum_disk:
        reasons.append({'code':'insufficient_disk','message':'Free disk is below this profile start requirement.'})
    accelerator=whpx_status()
    if not accelerator.get('available'):
        reasons.append({'code':'accelerator_unavailable','message':'WHPX is unavailable.'})
    try:
        guest=observe(controller)
    except Exception as error:
        guest={'status':'unknown','error':{'code':getattr(error,'code','status_error'),'message':redact(str(error))}}
        reasons.append({'code':'status_unknown','message':'Guest ownership/status must be resolved before launch.'})
    return {'vm':vm,'memory':memory,'disk':{'free_bytes':disk.free,'total_bytes':disk.total,
        'required_free_bytes':minimum_disk},'accelerator':accelerator,'requested_memory_mib':requested,
        'required_available_physical_mib':budget+512,'required_available_commit_mib':budget+384,
        'can_start':not reasons,'start_blocks':reasons,'guest':guest,'observed_at':time.time()}


def redact(value):
    value=re.sub(r'(?im)((?:token|password|api[_-]?key|secret)\s*[:=]\s*)[^\r\n]*',r'\1[redacted]',value)
    return re.sub(r'\bsk-[A-Za-z0-9_-]{8,}', '[redacted]',value)


def logs(controller, kind, cursor=0, limit=16384):
    vm=PROFILES[controller.profile]
    if kind not in LOGS[vm] or type(cursor) is not int or cursor<0 or type(limit) is not int or not 1<=limit<=65536:
        fail('Choose a known log type and a bounded byte cursor.','invalid_log')
    saved=state(controller)
    if not saved:
        return {'kind':kind,'text':'','cursor':0,'eof':True,'missing':True,'generation':None}
    folder=controller.workspace/'vms'/('AgenticVM-'+saved['uuid'])
    path=checked(folder/LOGS[vm][kind],controller.workspace)
    if not path.exists():
        return {'kind':kind,'text':'','cursor':0,'eof':True,'missing':True,'generation':generation(controller)}
    if not path.is_file():
        fail('The owned log is not a regular file.','invalid_log')
    size=path.stat().st_size
    rotated=cursor>size
    if rotated:
        cursor=0
    with path.open('rb') as stream:
        continuation=False
        if cursor:
            stream.seek(cursor-1)
            continuation=stream.read(1)!=b'\n'
        stream.seek(cursor)
        data=stream.read(limit)
    if continuation:
        end=data.find(b'\n')
        consumed=end+1 if end>=0 else len(data)
        output='[log continuation omitted]\n'
    else:
        end=data.rfind(b'\n')
        consumed=end+1 if end>=0 else len(data)
        output=redact(data[:consumed].decode('utf-8','replace')) if end>=0 else '[partial or oversized log line omitted]\n' if data else ''
    # The raw byte channel is deliberately not returned: it would bypass redaction.
    return {'kind':kind,'text':output,'cursor':cursor+consumed,
        'eof':cursor+consumed>=size,'bytes_read':consumed,'rotated':rotated,'generation':generation(controller)}


def probe(controller, condition):
    if condition not in {'guest','desktop','stopped'}:
        fail('Choose guest, desktop or stopped readiness.','invalid_condition')
    current=observe(controller)
    ready=(not current.get('registered') or current.get('status') in {'exited','stopped'}) if condition=='stopped' else current.get('guest_ready') is True
    if condition=='desktop':
        ready=(current.get('screen_ready') is True) if controller.profile == 'custom' else ready and current.get('desktop_ready',current.get('guest',{}).get('display')==':0') is True
    return {'condition':condition,'satisfied':bool(ready),'state':current}
