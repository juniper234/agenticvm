"""Verified local LFM assets and source-only construction of guest data disks."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path,PurePosixPath
import stat
import tarfile

from .ext2 import Node,build_ext2

MODEL_NAME = 'LFM2.5-350M-Q4_K_M'
MODEL_SHA = '7e6f72643caafc9a68256686638c4d7916f2cec76d1df478d4c3ddcd95a6aed4'


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def assets(root):
    folder = root/'models/lfm2.5-350m'
    lock = json.loads((folder/'model-lock.json').read_text())
    expected = {'model.gguf':MODEL_SHA,
        'llama-b11711-bin-ubuntu-x64.tar.gz':'05e4fb108c568a8717ef146e86edaee753dabe1f2713c33ea7cb380c74d63cc7',
        'libgomp.so.1':'6456b504ac347bd50c419667440b691f6966ad8aff5309d2f06c977fe2f9debe',
        'agenticvm-linux-peer.iso':'efe13ac8ebb4647d8d96d638b1eb72b08a4165a7954103cdc714f1165b2765bc'}
    if lock.get('schema')!='agenticvm.garden-lfm.v1' or set(lock.get('files',{}))!=set(expected):
        raise ValueError('Unexpected garden model inventory')
    for name,sha in expected.items():
        path = folder/name
        if any(p.is_symlink() or getattr(p,'is_junction',lambda:False)() for p in (path,*path.parents)):
            raise ValueError('Redirected model assets are refused')
        if lock['files'][name]['sha256']!=sha or path.stat().st_size!=lock['files'][name]['bytes'] or digest(path)!=sha:
            raise ValueError('Pinned garden model asset changed: '+name)
    return folder,lock


def prepare_disk(vm,source,folder):
    nodes = {'':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000),
             'peer':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000),
             'model.gguf':Node(stat.S_IFREG|0o444,folder/'model.gguf',1000,1000),
             'dependencies/libgomp.so.1':Node(stat.S_IFREG|0o444,folder/'libgomp.so.1',1000,1000)}
    nodes.update({'peer/'+name:Node(stat.S_IFREG|0o600,path,1000,1000) for name,path in source.items()})
    with tarfile.open(folder/'llama-b11711-bin-ubuntu-x64.tar.gz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or len(path.parts)!=2 and not member.isdir() or path.parts[0]!='llama-b11711' or member.size>32*1024**2:
                raise ValueError('Unexpected pinned inference release member')
            name = 'llama/'+str(path)
            if member.isfile():
                nodes[name] = Node(stat.S_IFREG|(member.mode&0o755),archive.extractfile(member).read(),1000,1000)
            elif member.issym():
                if '/' in member.linkname or member.linkname in ('.','..'):
                    raise ValueError('Unexpected inference library symlink')
                nodes[name] = Node(stat.S_IFLNK|0o777,member.linkname.encode(),1000,1000)
            elif not member.isdir():
                raise ValueError('Unsupported inference release entry')
    disk = vm.workspace/'data/default.ext2'
    disk.parent.mkdir(parents=True)
    build_ext2(disk,nodes,size_mib=512,label='AGENTICVM_DATA')


def verify_conversation(snapshots):
    """Reconcile actual generated outputs, received messages and reply inputs."""
    hashes = lambda value:hashlib.sha256(value.encode()).hexdigest()
    generated,received,calls = {},{},{}
    source_bound = True
    for member,status in snapshots.items():
        for call in status['model']['calls']:
            if (call['call_id'] in calls or type(call['completion_tokens']) is not int or call['completion_tokens']<1 or
                    json.loads(call['raw_content'])!={'text':call['text']} or
                    call['text_sha256']!=hashes(call['text']) or call['prompt_sha256']!=hashes(call['prompt'])):
                raise ValueError('Model output evidence does not match its actual completion')
            calls[call['call_id']] = call
        for peer,edge in status['links'].items():
            for message in edge['application']['generated']:
                if message['id'] in generated or message['from']!='sprout-'+member or message['to']!='sprout-'+peer:
                    raise ValueError('Duplicate or misrouted generated message')
                generated[message['id']] = message
            for message in edge['application']['received']:
                if message['id'] in received or message['to']!='sprout-'+member or message['from']!='sprout-'+peer:
                    raise ValueError('Duplicate or misrouted received message')
                received[message['id']] = message
    if len(generated)!=12 or generated!=received or set(generated)!=set(calls):
        raise ValueError('The twelve actual model messages do not reconcile across the three VMs')
    for key,message in generated.items():
        call = calls[key]
        if (call['text']!=message['text'] or call['completion_tokens']!=message['model']['completion_tokens'] or
                message['model']['weights_sha256']!=MODEL_SHA or message['model']['call_id']!=key):
            raise ValueError('A message was not the recorded LFM completion')
        if message['kind']=='reply':
            source = generated.get(message['reply_to'])
            if (not source or source['kind']!='hello' or source['from']!=message['to'] or source['to']!=message['from'] or
                    call['source_message_id']!=source['id'] or json.dumps(source['text'],sort_keys=True,separators=(',',':'),ensure_ascii=True) not in call['prompt']):
                source_bound = False
    if not source_bound:
        raise ValueError('Model replies were not generated from the received greeting')
    return {'twelve_real_model_completions_delivered':True,
            'model_completion_text_and_token_evidence_matches_delivered_messages':True,
            'six_model_replies_include_actual_received_greeting_in_prompt':True,
            'no_canned_model_response_fallback':True}
