"""Two local-model agents build and review a scaffolded Pong game over mTLS.

All actions and paths are fixed. Model-generated arithmetic expressions use a
small lexical allowlist and execute only in a deadline-bounded guest JS engine.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0,str(Path(__file__).resolve().parent))
from peer_agent import FDTransport, Evidence
from peer_protocol import BIOStream, PeerSession, PeerTLSConfig
from pong_synthesis import synthesize

BASE=Path('/workspace')
FILES=('index.html','engine.js','view.js','logic.js','config.js')
PARTS={
 'advance':('position,velocity,dt','Compute the new position: multiply velocity by dt, then add position. Use only position, velocity, dt and arithmetic.'),
 'bounce':('velocity','Reverse the sign of velocity while preserving its magnitude. Use only velocity and unary minus.'),
 'clamp':('value,low,high','Clamp value between low and high inclusively. Use Math.max and Math.min with value, low, high.'),
}
ALLOWED=set('position velocity dt value low high Math max min abs'.split())


def expression(value):
    if not isinstance(value,str) or not 1<=len(value)<=180:
        raise ValueError('Expression length limit')
    if re.sub(r'[a-zA-Z_][a-zA-Z_0-9]*|\d+(?:\.\d+)?|[\s()+*/.,\-]','',value):
        raise ValueError('Only arithmetic expressions and Math.min/max/abs are allowed')
    if any(word not in ALLOWED for word in re.findall(r'[a-zA-Z_][a-zA-Z_0-9]*',value)):
        raise ValueError('Unexpected identifier in arithmetic expression')
    return value


def sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


class Model:
    def __init__(self,log):
        self.log=log
        self.process=None
        self.calls=0
        self.peak_rss_kib=0
        self.done=threading.Event()

    def start(self):
        command=['/workspace/llama/llama-b11711/llama-server','-m','/workspace/model.gguf','-c','1024',
                 '-t','1','-tb','1','-b','64','-ub','64','-np','1','-ngl','0','--host','127.0.0.1',
                 '--port','8080','--jinja','--no-webui','--no-warmup','--fit','off','--threads-http','1']
        self.output=(BASE/'peer/model.log').open('wb')
        self.process=subprocess.Popen(command,stdout=self.output,stderr=subprocess.STDOUT,
            env={**os.environ,'LD_LIBRARY_PATH':'/workspace/dependencies:/workspace/llama/llama-b11711','OMP_NUM_THREADS':'1'})
        def monitor():
            while not self.done.wait(.2):
                try:
                    for line in Path(f'/proc/{self.process.pid}/status').read_text().splitlines():
                        if line.startswith('VmHWM:'):
                            self.peak_rss_kib=max(self.peak_rss_kib,int(line.split()[1]))
                except OSError:
                    pass
        self.monitor=threading.Thread(target=monitor,daemon=True)
        self.monitor.start()
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            if self.process.poll() is not None:
                raise RuntimeError('Local inference server exited')
            try:
                with urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=1) as response:
                    if response.status==200:
                        self.log({'event':'model_ready','pid':self.process.pid})
                        return
            except OSError:
                time.sleep(.2)
        raise TimeoutError('Local inference startup deadline')

    def ask(self,purpose,prompt,schema,tokens=96):
        if self.calls>=18:
            raise RuntimeError('Model call budget exhausted')
        self.calls+=1
        request={'model':'local','messages':[{'role':'system','content':'Follow the provided field names and exact instructions. Return JSON only.'},
                 {'role':'user','content':prompt}], 'temperature':.1,'top_k':50,'repeat_penalty':1.05,
                 'seed':42,'max_tokens':tokens,'cache_prompt':False,
                 'response_format':{'type':'json_schema','json_schema':{'name':'result','strict':True,'schema':schema}}}
        start=time.monotonic()
        req=urllib.request.Request('http://127.0.0.1:8080/v1/chat/completions',data=json.dumps(request).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=120) as response:
            result=json.load(response)
        content=result['choices'][0]['message']['content']
        self.log({'event':'model_result','purpose':purpose,'prompt':prompt,'content':content,
                  'seconds':round(time.monotonic()-start,3),'timings':result.get('timings')})
        return json.loads(content)

    def close(self):
        self.done.set()
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
                try:self.process.wait(5)
                except subprocess.TimeoutExpired:
                    self.process.kill();self.process.wait(5)
            self.output.close()


def schema(properties):
    return {'type':'object','properties':properties,'required':list(properties),'additionalProperties':False}


def logic_source(formulas):
    if set(formulas)!=set(PARTS):
        raise ValueError('Incomplete worker arithmetic')
    pieces=[]
    for name,(args,_) in PARTS.items():
        pieces.append(f'{name}:function({args}){{return ({expression(formulas[name])});}}')
    return 'globalThis.PongMath={'+','.join(pieces)+'};\n'


def validate_game(config,formulas):
    folder=BASE/'pong'
    folder.mkdir(exist_ok=True)
    (folder/'logic.js').write_text(logic_source(formulas))
    (folder/'config.js').write_text('globalThis.PongConfig='+json.dumps(config,sort_keys=True)+';\n')
    for name in ('index.html','engine.js','view.js'):
        (folder/name).write_bytes((BASE/'templates'/name).read_bytes())
    return check_game()


def check_game():
    try:
        result=subprocess.run(['/workspace/qjs','--std','--module','/workspace/templates/check.js'],
                              capture_output=True,text=True,timeout=5)
        if result.returncode:
            return {'passed':False,'checks':0,'results':[], 'error':(result.stderr or result.stdout)[-1200:]}
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired,ValueError) as error:
        return {'passed':False,'checks':0,'results':[],'error':type(error).__name__}


def artifacts():
    return {name:(BASE/'pong'/name).read_text() for name in FILES}


def receive_artifacts(files):
    if not isinstance(files,dict) or set(files)!=set(FILES) or sum(len(v.encode()) for v in files.values() if isinstance(v,str))>14000:
        raise ValueError('Unexpected artifact inventory or size')
    folder=BASE/'pong'
    folder.mkdir(exist_ok=True)
    for name,text in files.items():
        if not isinstance(text,str):raise ValueError('Artifact must be text')
        if name in ('index.html','engine.js','view.js') and text!=(BASE/'templates'/name).read_text():
            raise ValueError('Worker modified trusted scaffold')
        (folder/name).write_text(text)


def rpc(session,body,log):
    sent=session.send('request',body,timeout=10)
    log({'event':'task_sent','message_id':sent['id'],'body':body})
    result=session.receive(timeout=600)
    if result['kind']!='response' or result['reply_to']!=sent['id']:
        raise ValueError('Wrong build response correlation')
    log({'event':'task_result','message_id':result['id'],'reply_to':sent['id'],
         'body':{k:v for k,v in result['body'].items() if k!='artifacts'}})
    return result['body']


def orchestrate(session,model,log):
    plan=model.ask('plan','Create a small single-player 2D Pong game against a computer. Choose palette blue, mint, or amber and pace easy or normal. Return palette and pace.',
                   schema({'palette':{'type':'string','enum':['blue','mint','amber']},'pace':{'type':'string','enum':['easy','normal']}}))
    if plan.get('palette') not in ('blue','mint','amber') or plan.get('pace') not in ('easy','normal'):
        raise ValueError('Invalid model plan')
    request={'op':'build_pong','spec':{'goal':'Build a small playable 2D Pong game','palette':plan['palette'],'pace':plan['pace'],
             'target':5,'controls':['keyboard','mouse','touch'],'scaffold_provided':True},'round':1,'issues':[]}
    for attempt in range(1,5):
        result=rpc(session,request,log)
        if not result.get('artifacts'):
            checks={'passed':False,'results':[],'error':result.get('error','Worker produced no artifacts')}
        else:
            if result['artifacts'].get('logic.js')!=logic_source(result.get('formulas',{})):
                raise ValueError('Worker arithmetic artifact does not match validated expressions')
            if result['artifacts'].get('config.js')!='globalThis.PongConfig='+json.dumps(plan,sort_keys=True)+';\n':
                raise ValueError('Worker configuration differs from orchestrator plan')
            receive_artifacts(result['artifacts'])
            checks=check_game()
        log({'event':'independent_review','round':attempt,'checks':checks})
        expected='approve' if checks['passed'] else 'repair'
        proposed=model.ask('review',f'The independent executable tests passed={str(checks["passed"]).lower()}. Choose action "approve" only if true; otherwise choose "repair".',
                           schema({'action':{'type':'string','enum':['approve','repair']}}),32)
        action=proposed.get('action')
        if action!=expected:
            log({'event':'policy_override','proposed':action,'required':expected})
        if checks['passed']:
            hashes={name:sha(text) for name,text in artifacts().items()}
            response=rpc(session,{'op':'accept','hashes':hashes},log)
            if response.get('accepted') is not True or response.get('hashes')!=hashes:
                raise ValueError('Worker acceptance acknowledgement mismatch')
            return {'passed':True,'rounds':attempt,'checks':checks,'hashes':hashes,'plan':plan,
                    'worker_physics':result.get('formulas'),'formula_origins':result.get('formula_origins')}
        issues=[row for row in checks.get('results',[]) if not row['passed']]
        request={'op':'repair_pong','spec':request['spec'],'round':attempt+1,'issues':issues,
                 'error':checks.get('error'), 'failed_parts':result.get('failed_parts',[])}
    raise RuntimeError('Four build/review rounds exhausted')


def work(session,model,log):
    formulas={}
    origins={}
    for _ in range(5):
        incoming=session.receive(timeout=600)
        if incoming['kind']!='request':raise ValueError('Worker expects requests')
        body=incoming['body']
        log({'event':'task_received','message_id':incoming['id'],'body':body})
        if body.get('op')=='accept':
            actual={name:sha(text) for name,text in artifacts().items()}
            if actual!=body.get('hashes'):raise ValueError('Accepted artifact hashes differ')
            session.send('response',{'accepted':True,'hashes':actual},reply_to=incoming['id'])
            return {'passed':True,'hashes':actual,'formulas':formulas,'formula_origins':origins}
        if body.get('op') not in ('build_pong','repair_pong') or body.get('round') not in (1,2,3,4):
            raise ValueError('Unknown build capability or round')
        config={'palette':body['spec']['palette'],'pace':body['spec']['pace']}
        failed={row['name'] for row in body.get('issues',[]) if row.get('name') in PARTS}
        names=list(PARTS) if not formulas or not failed else sorted(failed)
        failed_parts=[]
        for name in names:
            if body['round']>=3:
                repair=synthesize(name)
                formulas[name]=expression(repair['expression'])
                origins[name]=repair['origin']
                log({'event':'deterministic_repair','part':name,**repair})
                continue
            _,description=PARTS[name]
            feedback=''
            if body.get('issues'):
                feedback=' Previous test failures: '+json.dumps(body['issues'])[:450]
            try:
                answer=model.ask('implement_'+name,description+' Return one JSON field expression containing only the JavaScript expression, without return, semicolon, or function declaration.'+feedback,
                     schema({'expression':{'type':'string','maxLength':180}}),64)
                formulas[name]=expression(answer['expression'])
                origins[name]='local_language_model'
            except (ValueError,KeyError) as error:
                failed_parts.append(name)
                log({'event':'generation_rejected','part':name,'error':str(error)[:300]})
        response={'formulas':formulas,'formula_origins':origins,'failed_parts':failed_parts}
        try:
            if failed_parts:raise ValueError('Regenerate invalid parts: '+','.join(failed_parts))
            checks=validate_game(config,formulas)
            response.update(checks=checks,artifacts=artifacts())
            log({'event':'candidate_written','round':body['round'],'checks':checks,
                 'hashes':{name:sha(text) for name,text in response['artifacts'].items()}})
        except ValueError as error:
            response['error']=str(error)
        session.send('response',response,reply_to=incoming['id'],timeout=10)
    raise RuntimeError('Worker request budget exhausted')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--role',choices=('orchestrator','worker'),required=True)
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--pin',required=True)
    args=parser.parse_args()
    if os.getuid()!=1000:raise ValueError('Run only as guest UID 1000')
    identity,peer=('guest-a','guest-b') if args.role=='orchestrator' else ('guest-b','guest-a')
    evidence=Evidence('/workspace/peer/evidence.jsonl',args.run_id,identity,peer)
    model=Model(evidence)
    stream=None
    report={'passed':False,'role':args.role,'run_id':args.run_id,'model':'LFM2.5-350M-Q4_K_M',
            'scaffold_provided':True,'uid':os.getuid(),'network_interfaces':sorted(p.name for p in Path('/sys/class/net').iterdir())}
    start=time.monotonic()
    try:
        if report['network_interfaces']!=['lo']:raise ValueError('Agents must have no network adapter')
        model.start()
        configuration=PeerTLSConfig('/workspace/peer/identity.pem','/workspace/peer/key.pem','/workspace/peer/ca.pem',args.pin,peer)
        if args.role=='orchestrator':time.sleep(1)
        stream=BIOStream(FDTransport('/dev/virtio-ports/org.agenticvm.peer'),configuration,
                         server_side=args.role=='worker',timeout=45)
        session=PeerSession(stream,args.run_id,identity,peer,evidence)
        report['tls']=stream.info
        result=orchestrate(session,model,evidence) if args.role=='orchestrator' else work(session,model,evidence)
        report.update(result)
    except Exception as error:
        report['error']={'class':type(error).__name__,'message':str(error)[:1500]}
        evidence({'event':'agent_failed','error':report['error']})
    finally:
        if stream:stream.close()
        model.close()
        report.update(model_calls=model.calls,model_peak_rss_kib=model.peak_rss_kib,elapsed_seconds=round(time.monotonic()-start,3))
        (BASE/'peer/summary.json').write_text(json.dumps(report,indent=2)+'\n')
        evidence({'event':'agent_finished','passed':report['passed'],'model_calls':model.calls})
        evidence.close()
    print(json.dumps({'passed':report['passed'],'role':args.role,'error':report.get('error')}))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
