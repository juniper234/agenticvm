"""Build Pong using two offline 512 MiB model VMs and a direct TLS serial pair."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request
from uuid import UUID, uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.ext2 import Node, build_ext2
from agenticvm.peers import Runner, VM, verify_journal, recover_run
from agenticvm.qemu import prepare_pair_directory
from agenticvm.state import StateStore

MODEL=ROOT/'runtime/local-model-test'
GUEST=ROOT/'guest'
QJS_SHA='0bfc02511a9f549c28b53880d988fc7cd5d361e90c5e8afdfcd7dc6774ceace5'
QJS_URL='https://github.com/quickjs-ng/quickjs/releases/download/v0.17.0/qjs-linux-x86_64'


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def prepare_disk(vm,extra_guest=()):
    qjs=MODEL/'downloads/qjs-linux-x86_64'
    if not qjs.exists():
        with urllib.request.urlopen(QJS_URL,timeout=60) as source:
            content=source.read(2562505)
        if len(content)!=2562504 or hashlib.sha256(content).hexdigest()!=QJS_SHA:
            raise ValueError('QuickJS release verification failed')
        qjs.write_bytes(content)
    if digest(qjs)!=QJS_SHA:raise ValueError('Cached QuickJS changed')
    preparation=json.loads((MODEL/'preparation.json').read_text())
    weights=MODEL/'downloads/LFM2.5-350M-Q4_K_M.gguf'
    archive=MODEL/'downloads/llama-b11711-bin-ubuntu-x64.tar.gz'
    for path in (weights,archive):
        if digest(path)!=preparation['sources'][path.name]['sha256']:
            raise ValueError('Pinned inference artifact changed')
    nodes={'':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000),
           'peer':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000),
           'model.gguf':Node(stat.S_IFREG|0o444,weights,1000,1000),
           'qjs':Node(stat.S_IFREG|0o555,qjs,1000,1000),
           'dependencies/libgomp.so.1':Node(stat.S_IFREG|0o444,MODEL/'dependencies/libgomp.so.1',1000,1000)}
    for path in (GUEST/'pong').iterdir():
        if path.is_file():nodes['templates/'+path.name]=Node(stat.S_IFREG|0o444,path,1000,1000)
    protocol=GUEST/'peer_protocol.py' if (GUEST/'peer_protocol.py').exists() else ROOT/'src/agenticvm/peer_protocol.py'
    for name,source in [('pong_agent.py',GUEST/'pong_agent.py'),('peer_agent.py',GUEST/'peer_agent.py'),
                        ('peer_protocol.py',protocol),('pong_synthesis.py',GUEST/'pong_synthesis.py')]:
        nodes['peer/'+name]=Node(stat.S_IFREG|0o444,source,1000,1000)
    for name in extra_guest:
        if name!='replica_agent.py':raise ValueError('Unsupported additional guest capability')
        nodes['peer/'+name]=Node(stat.S_IFREG|0o444,GUEST/name,1000,1000)
    with tarfile.open(archive) as source:
        for member in source:
            path=PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts:raise ValueError('Unsafe archive path')
            if member.isfile():
                nodes['llama/'+str(path)]=Node(stat.S_IFREG|(member.mode&0o755),source.extractfile(member).read(),1000,1000)
            elif member.issym():
                if '/' in member.linkname:raise ValueError('Unexpected link')
                nodes['llama/'+str(path)]=Node(stat.S_IFLNK|0o777,member.linkname.encode(),1000,1000)
            elif not member.isdir():raise ValueError('Unexpected member')
    target=vm.workspace/'data/default.ext2'
    target.parent.mkdir(parents=True)
    build_ext2(target,nodes,size_mib=512,label='AGENTICVM_DATA')


def erase_generated_guest_key(vm):
    """Exact disposable key path only; keep model files and artifacts intact."""
    code="from pathlib import Path; import json; p=Path('/workspace/peer/key.pem'); assert not p.is_symlink() and p.parent.resolve()==Path('/workspace/peer'); p.unlink(missing_ok=True); print(json.dumps({'private_key_removed':not p.exists()}))"
    result=json.loads(vm.run('/usr/bin/python3','-I','-c',code))
    if result.get('private_key_removed') is not True:
        raise RuntimeError('Guest key removal was not verified')
    vm.run('/bin/sync')
    return result


def main():
    global MODEL,GUEST
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recover',help='Stop an interrupted owned run and remove its disposable keys; never replay tasks')
    parser.add_argument('--run-id',help='Canonical UUID assigned by the local chain launcher')
    parser.add_argument('--agent-directory',type=Path,help='Verified torrent agent package, supplied by the chain launcher')
    args=parser.parse_args()
    if args.agent_directory:
        MODEL=args.agent_directory.resolve()
        GUEST=MODEL/'guest'
        # VM.install supplies the trusted host transport implementation. A
        # downloaded agent must use precisely the same transport contract.
        for packaged,host in ((GUEST/'peer_agent.py',ROOT/'guest/peer_agent.py'),
                              (GUEST/'peer_protocol.py',ROOT/'src/agenticvm/peer_protocol.py')):
            if digest(packaged)!=digest(host):raise ValueError('Agent/host transport version mismatch')
    if args.recover:
        if str(UUID(args.recover))!=args.recover:raise ValueError('Use a canonical run UUID')
        directory=ROOT/'runtime/pong-agent-runs'/args.recover
        verify_journal(directory/'checkpoints.jsonl')
        first=json.loads((directory/'checkpoints.jsonl').read_text().splitlines()[0])
        if first.get('purpose')!='two local-model agents build Pong':raise ValueError('Not a Pong-agent run')
        result=recover_run(directory)
        if result['passed']:
            subprocess.run([sys.executable,'-I',str(ROOT/'scripts/cleanup-pong-keys.py'),'--run',args.recover,'--after-recovery'],check=True,cwd=ROOT)
            result['guest_key_cleanup']=json.loads((directory/'key-cleanup.json').read_text())
            result['passed']=result['passed'] and result['guest_key_cleanup']['passed']
        (directory/'pong-recovery.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result))
        return 0 if result['passed'] else 1
    run_id=args.run_id or str(uuid4())
    if str(UUID(run_id))!=run_id:raise ValueError('Use a canonical run UUID')
    folder=ROOT/'runtime/pong-agent-runs'/run_id
    folder.mkdir(parents=True,mode=0o700)
    runner=Runner(folder,run_id,512,1)
    runner.journal.add('run_started',purpose='two local-model agents build Pong',guest_memory_mib=512)
    report={'run_id':run_id,'passed':False,'memory_mib_per_vm':512,'model':'LFM2.5-350M-Q4_K_M',
            'agent_directory':str(MODEL),
            'host_is_message_relay':False,'supplied_canvas_scaffold':True,'model_assisted_arithmetic':True,
            'deterministic_synthesis_fallback_available':True,
            'physical_4gb_host_tested':False,'quickjs':{'url':QJS_URL,'sha256':QJS_SHA}}
    print(json.dumps({'event':'run_started','directory':str(folder)}),flush=True)
    def cancelled():
        if (folder/'cancel.request').exists():raise KeyboardInterrupt('Chain launcher requested cancellation')
    try:
        cancelled()
        runner.provision()
        runner.pair_id=str(uuid4())
        prepare_pair_directory(runner.pair_id)
        left,right=VM(runner,'guest-a-serial'),VM(runner,'guest-b-serial')
        for vm,role,identity,peer in ((left,'listen','guest-a','guest-b'),(right,'connect','guest-b','guest-a')):
            cancelled()
            prepare_disk(vm)
            vm.start('--persistent','--image',MODEL/'boot/agenticvm-linux-peer.iso','--pair',runner.pair_id,
                     '--peer-role',role,'--peer-link','serial')
            vm.install(identity,peer)
            preflight=vm.run('/workspace/qjs','--std','-e','print(typeof std.loadScript)')
            if preflight.strip()!='function':raise RuntimeError('Guest JavaScript harness preflight failed')
            # Reference primitives validate the supplied harness in isolation;
            # they are never written into the worker's game artifacts.
            reference='globalThis.PongMath={advance:(p,v,t)=>p+v*t,bounce:v=>-v,clamp:(v,l,h)=>Math.max(l,Math.min(h,v))};'
            check='\n'.join((GUEST/'pong/check.js').read_text(encoding='utf-8').splitlines()[3:])
            actual=json.loads(vm.run('/workspace/qjs','--std','-e',reference+"std.loadScript('/workspace/templates/engine.js');"+check))
            if not actual['passed']:raise RuntimeError('Supplied guest game harness failed its preflight')
            runner.journal.add('harness_preflight',vm=vm.name,checks=actual['checks'],passed=True,reference_not_delivered=True)
            runner.journal.add('workspace_prepared',vm=vm.name,role='orchestrator' if vm==left else 'worker',
                               model_on_disk=True,no_network_adapter=True)
        def start(vm,role,pin):
            job=vm.cli('exec','--async','--timeout-ms','0','--','/usr/bin/python3','-I','/workspace/peer/pong_agent.py',
                       '--role',role,'--run-id',run_id,'--pin',pin)['job_id']
            vm.jobs.append(job)
            return job
        worker=start(right,'worker',runner.identities['guest-a']['sha256'])
        orchestrator=start(left,'orchestrator',runner.identities['guest-b']['sha256'])
        runner.journal.add('agents_started',worker_job=worker,orchestrator_job=orchestrator,
                           host_sends_no_further_build_instructions=True)
        print(json.dumps({'event':'agents_started','directory':str(folder)}),flush=True)
        started=time.monotonic()
        pending={(left,orchestrator),(right,worker)}
        # Monitoring polls contain no build instructions, artifacts or messages.
        while pending and time.monotonic()-started<1000:
            time.sleep(10)
            cancelled()
            print(json.dumps({'event':'agents_running','elapsed_seconds':round(time.monotonic()-started),
                              'pending':sorted(vm.name for vm,job in pending)}),flush=True)
            for vm,job in list(pending):
                snapshot=vm.cli('poll',job)
                if snapshot['state']=='exited':
                    (folder/(vm.name+'-job.json')).write_text(json.dumps(snapshot,indent=2)+'\n')
                    pending.remove((vm,job))
                    print(json.dumps({'event':'agent_exited','vm':vm.name,'exit_code':snapshot['exit_code']}),flush=True)
        if pending:raise TimeoutError('Bounded two-agent run exceeded 1000 seconds')
        for vm in (left,right):
            destination=folder/'evidence'/vm.name
            destination.mkdir(parents=True)
            for name in ('summary.json','evidence.jsonl','model.log'):
                vm.download('peer/'+name,destination/name)
        orch=json.loads((folder/'evidence'/left.name/'summary.json').read_text())
        work=json.loads((folder/'evidence'/right.name/'summary.json').read_text())
        report.update(orchestrator=orch,worker=work)
        if not orch['passed'] or not work['passed']:
            raise RuntimeError('One or both guest agents failed; inspect preserved evidence')
        if orch['hashes']!=work['hashes']:raise ValueError('Accepted artifacts differ between guests')
        game=folder/'game'
        game.mkdir()
        for name,expected in work['hashes'].items():
            if name not in ('index.html','engine.js','view.js','logic.js','config.js'):
                raise ValueError('Unexpected game artifact')
            right.download('pong/'+name,game/name)
            if digest(game/name)!=expected:raise ValueError('Exported game checksum mismatch')
        left_events=[json.loads(line) for line in (folder/'evidence'/left.name/'evidence.jsonl').read_text().splitlines()]
        right_events=[json.loads(line) for line in (folder/'evidence'/right.name/'evidence.jsonl').read_text().splitlines()]
        sent={row['message_id']:row['body_sha256'] for row in left_events if row['event']=='sent'}
        received={row['message_id']:row['body_sha256'] for row in right_events if row['event']=='received'}
        if sent!=received or len(sent)<2:raise ValueError('Task transcript reconciliation failed')
        report.update(passed=True,game_directory=str(game),verified_task_messages=len(sent),
                      formula_origins=work.get('formula_origins'),
                      elapsed_agent_seconds=round(time.monotonic()-started,3))
        runner.journal.add('game_accepted',hashes=work['hashes'],checks=orch['checks']['checks'])
    except (Exception,KeyboardInterrupt) as error:
        report['failure']={'class':type(error).__name__,'message':str(error)[:1500]}
        runner.journal.add('run_failed',error=report['failure'])
        runner.diagnose()
    finally:
        guest_key_failures=[]
        report['guest_key_cleanup']={}
        for vm in runner.machines:
            if not (vm.workspace/'data/default.ext2').exists():continue
            state=StateStore(vm.workspace).load(required=False)
            if state and state.get('registered'):
                try:
                    report['guest_key_cleanup'][vm.name]=erase_generated_guest_key(vm)
                    runner.journal.add('guest_private_key_removed',vm=vm.name)
                except Exception as error:
                    guest_key_failures.append({'vm':vm.name,'error_class':type(error).__name__,'needs_offline_key_cleanup':True})
        report['cleanup_failures']=guest_key_failures+runner.cleanup()
        report['passed']=report['passed'] and not report['cleanup_failures']
        runner.journal.add('run_completed',passed=report['passed'])
        runner.journal.close()
        report['checkpoints']=verify_journal(folder/'checkpoints.jsonl')
        (folder/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':report['passed'],'report':str(folder/'report.json'),'failure':report.get('failure')}),flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
