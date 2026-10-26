"""Finite, explicitly authorized four-member LAN enrollment/inference lab.

The model writes greetings only. Enrollment is a fixed mother policy for one
named SSH target. No scanning, exploit, shell tool or inherited installer key
is given to offshoots or the recruited agent.
"""
from __future__ import annotations
import base64,hashlib,hmac,http.client,http.server,json,os,sqlite3,ssl,subprocess,sys,threading,time
from pathlib import Path
from uuid import UUID,uuid5
sys.path.insert(0,str(Path(__file__).resolve().parent))
from local_lfm import LocalLFM,MODEL_NAME,MODEL_SHA

BASE=Path('/workspace')
MEMBERS=('mother','offshoot-1','offshoot-2','sprout-4')
ADDRESSES=dict(zip(MEMBERS,('192.0.2.1','192.0.2.2','192.0.2.3','192.0.2.4')))

def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def sha(data): return hashlib.sha256(data).hexdigest()
def save(path,value):
    tmp=path.with_suffix('.tmp')
    with tmp.open('wb') as stream: stream.write(encoded(value)+b'\n');stream.flush();os.fsync(stream.fileno())
    tmp.replace(path)
def pin(pem): return sha(ssl.PEM_cert_to_DER_cert(pem))

def context(cert,*,own=False):
    ctx=ssl.create_default_context(cadata=cert)
    ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
    if own: ctx.load_cert_chain(BASE/'identity.pem',BASE/'identity.key')
    return ctx

def request(address,port,path,ctx,*,body=None,expected=None,timeout=150):
    conn=http.client.HTTPSConnection(address,port,context=ctx,timeout=timeout)
    try:
        conn.connect()
        if conn.sock.version()!='TLSv1.3' or (expected and sha(conn.sock.getpeercert(binary_form=True))!=expected):
            raise ValueError('Pinned TLS endpoint mismatch')
        tls={'version':conn.sock.version(),'cipher':conn.sock.cipher()[0]}
        conn.request('POST' if body is not None else 'GET',path,body=encoded(body) if body is not None else None,
                     headers={'Content-Type':'application/json','Connection':'close'})
        response=conn.getresponse();raw=response.read(256*1024+1)
        if len(raw)>256*1024 or response.status!=200:
            raise ValueError('Garden request rejected: '+str(response.status)+': '+raw.decode(errors='replace')[:400])
        return json.loads(raw),tls
    finally: conn.close()

class SecureServer(http.server.ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=True
    def get_request(self):
        raw,address=self.socket.accept();raw.settimeout(150)
        try: return self.node.server_context(self.control).wrap_socket(raw,server_side=True),address
        except BaseException: raw.close();raise

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def output(self,value,status=200):
        data=encoded(value);self.send_response(status);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_GET(self): self.handle_request(None)
    def do_POST(self):
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 1<=length<=16384: raise ValueError('Bounded JSON body required')
            value=json.loads(self.rfile.read(length));self.handle_request(value)
        except Exception as error: self.output({'error':type(error).__name__},400)
    def handle_request(self,body):
        node=self.server.node
        try:
            if self.server.control:
                if self.path != '/bundle' and getattr(node, 'install_token', None):
                    if self.headers.get('Authorization') != 'Bearer ' + node.install_token:
                        return self.output({'error': 'ValueError: Wrong provisioning token'}, 403)
                if self.path.startswith('/assets/') and body is None:
                    return node.serve_asset(self)
                if self.path=='/manifest' and body is None:
                    raw=(BASE/'lab/manifest.json').read_bytes()
                    self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw);return
                if self.path=='/bundle' and body is None: return self.output(node.bundle())
                if self.path=='/admission' and body is not None: return self.output(node.admit(self.client_address[0],body))
                if self.path=='/enroll' and body is not None: return self.output(node.register(self.client_address[0],body))
                raise ValueError('Unknown provisioning endpoint')
            actor=node.authenticate(self.connection)
            if self.path=='/hello' and body is not None: result=node.receive(actor,body)
            elif self.path=='/heartbeat' and body is not None:
                if body!={'from':actor,'garden':node.config['garden']}: raise ValueError('Wrong heartbeat')
                with node.lock: node.heartbeats[actor]=node.heartbeats.get(actor,0)+1
                result={'ok':True,'from':node.identity,'sequence':node.heartbeats[actor]}
            elif self.path=='/status' and body is None: result=node.snapshot()
            else: raise ValueError('Unknown application endpoint')
            self.output(result)
        except (BrokenPipeError,ConnectionResetError): pass
        except Exception as error: self.output({'error':type(error).__name__+': '+str(error)},403)

class Node:
    def __init__(self,config):
        self.config=config;self.identity=config['identity']
        if self.identity not in MEMBERS: raise ValueError('Unapproved lab member')
        UUID(config['garden'])
        self.lock=threading.RLock();self.model_lock=threading.Lock();self.stop=threading.Event()
        self.model=LocalLFM();self.error=None;self.ready=False;self.heartbeats={};self.sent_heartbeats={}
        self.cut_once=False
        self.known=config.get('peers',{});self.enrollment=None;self.servers=[]
        self.db=sqlite3.connect(BASE/'lan-messages.sqlite',check_same_thread=False)
        self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS calls(id TEXT PRIMARY KEY,kind TEXT,peer TEXT,source TEXT,state TEXT,proof TEXT);
          CREATE TABLE IF NOT EXISTS inbox(id TEXT PRIMARY KEY,actor TEXT,payload TEXT,reply TEXT);
          CREATE TABLE IF NOT EXISTS delivered(id TEXT PRIMARY KEY,peer TEXT,hello TEXT,reply TEXT);''')
        if self.db.execute("SELECT 1 FROM calls WHERE state='generating'").fetchone():
            raise ValueError('Interrupted generation requires reconciliation; not replayed')
        if self.identity=='mother':
            self.registry_path=BASE/'registry.json'
            if self.registry_path.exists(): self.known=json.loads(self.registry_path.read_text())
            else: save(self.registry_path,self.known)
        self.public={'identity':self.identity,'address':ADDRESSES[self.identity],
                     'certificate':(BASE/'identity.pem').read_text()}
        self.public['sha256']=pin(self.public['certificate'])
    def bundle(self):
        with self.lock: return {'garden':self.config['garden'],'members':dict(self.known)}
    def server_context(self,control):
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(BASE/'identity.pem',BASE/'identity.key')
        if not control:
            with self.lock: certs='\n'.join(row['certificate'] for row in self.known.values())
            ctx.load_verify_locations(cadata=certs);ctx.verify_mode=ssl.CERT_REQUIRED
        return ctx
    def authenticate(self,connection):
        if connection.version()!='TLSv1.3': raise ValueError('TLS 1.3 required')
        fingerprint=sha(connection.getpeercert(binary_form=True))
        with self.lock: matches=[name for name,row in self.known.items() if row['sha256']==fingerprint]
        if len(matches)!=1 or matches[0]==self.identity: raise ValueError('Unknown application identity')
        actor=matches[0]
        if ('URI','urn:agenticvm:lan:'+actor) not in connection.getpeercert().get('subjectAltName',()):
            raise ValueError('Certificate identity mismatch')
        return actor
    def start_server(self,port,control=False):
        server=SecureServer((ADDRESSES[self.identity],port),Handler)
        server.node=self;server.control=control;self.servers.append(server)
        threading.Thread(target=server.serve_forever,daemon=True).start()
    def register(self,address,body):
        expected={'request_id','identity','certificate','grant'}
        if set(body)!=expected or body['identity']!='sprout-4' or address!='192.0.2.4' or body['request_id']!=self.config['request_id']:
            raise ValueError('Unapproved target enrollment')
        if not isinstance(body['grant'],str) or not hmac.compare_digest(body['grant'],self.config['grant']):
            raise ValueError('Wrong enrollment grant')
        if len(body['certificate'])>8192: raise ValueError('Oversized certificate')
        public={'identity':'sprout-4','address':'192.0.2.4','certificate':body['certificate'],'sha256':pin(body['certificate'])}
        with self.lock:
            old=self.known.get('sprout-4')
            if old and old!=public: raise ValueError('Enrollment grant already consumed by another identity')
            if not old:
                if self.enrollment is None or time.monotonic()>self.enrollment: raise ValueError('Enrollment window is not open')
                self.known['sprout-4']=public;save(self.registry_path,self.known)
            return {'ok':True,'duplicate':bool(old),'bundle':self.bundle()}
    def admit(self,address,body):
        if (set(body)!={'request_id','identity','grant'} or address!='192.0.2.4' or body['identity']!='sprout-4' or
            body['request_id']!=self.config['request_id'] or not isinstance(body['grant'],str) or
            not hmac.compare_digest(body['grant'],self.config['grant'])):
            raise ValueError('Enrollment admission scope mismatch')
        if self.enrollment is None or time.monotonic()>self.enrollment:
            raise ValueError('Enrollment window is not open')
        return {'ok':True,'admitted':True}
    def serve_asset(self,handler):
        name=handler.path.removeprefix('/assets/')
        manifest=json.loads((BASE/'lab/manifest.json').read_text())
        if name not in manifest['files']: raise ValueError('Unapproved asset')
        path=({'model.gguf':BASE/'model.gguf','libgomp.so.1':BASE/'dependencies/libgomp.so.1'}.get(name,BASE/'lab/assets'/name))
        size=manifest['files'][name]['bytes'];start=0
        value=handler.headers.get('Range')
        if value:
            if not value.startswith('bytes=') or not value.endswith('-'): raise ValueError('Unsupported byte range')
            start=int(value[6:-1])
            if not 0<start<size: raise ValueError('Invalid byte offset')
        handler.send_response(206 if start else 200)
        handler.send_header('Content-Length',str(size-start))
        if start: handler.send_header('Content-Range',f'bytes {start}-{size-1}/{size}')
        handler.end_headers()
        with path.open('rb') as stream:
            stream.seek(start)
            transferred=0
            while chunk:=stream.read(256*1024):
                handler.wfile.write(chunk);transferred+=len(chunk)
                if self.config.get('test_case')=='resume' and name=='model.gguf' and not start and not self.cut_once and transferred>=2*1024**2:
                    self.cut_once=True
                    import socket
                    handler.connection.shutdown(socket.SHUT_RDWR);handler.connection.close();return
    def update_bundle(self):
        if self.identity=='mother': return
        config=self.config
        result,_=request('192.0.2.1',8443,'/bundle',context(config['mother_certificate']),expected=pin(config['mother_certificate']),timeout=10)
        if result['garden']!=config['garden'] or not set(result['members'])<=set(MEMBERS): raise ValueError('Wrong garden bundle')
        for name,row in result['members'].items():
            if row['identity']!=name or row['address']!=ADDRESSES[name] or pin(row['certificate'])!=row['sha256']:
                raise ValueError('Invalid member pin bundle')
        with self.lock: self.known=result['members']
    def rpc(self,peer,path,body=None,timeout=150):
        with self.lock: public=self.known[peer]
        return request(public['address'],9443,path,context(public['certificate'],own=True),body=body,
                       expected=public['sha256'],timeout=timeout)
    def generated(self,message_id,peer,kind,source=None):
        with self.model_lock:
            with self.lock:
                old=self.db.execute('SELECT * FROM calls WHERE id=?',(message_id,)).fetchone()
                if old:
                    if old['peer']!=peer or old['kind']!=kind or old['source']!=source: raise ValueError('Changed generation request')
                    if old['state']!='ready': raise ValueError('Uncertain generation is not replayed')
                    return json.loads(old['proof'])
                prompt=(f'You are {self.identity}. Greet agent {peer}. Write fewer than eight words. Return JSON field text.' if source is None else
                        f'You are {self.identity}. Agent {peer} sent '+json.dumps(json.loads(source)['text'])+'. Reply in fewer than eight words. Return JSON field text.')
                with self.db: self.db.execute('INSERT INTO calls VALUES (?,?,?,?,?,NULL)',(message_id,kind,peer,source,'generating'))
            proof={**self.model.generate(prompt),'call_id':message_id,'prompt':prompt,'source_message_id':json.loads(source)['id'] if source else None}
            with self.lock,self.db: self.db.execute("UPDATE calls SET state='ready',proof=? WHERE id=?",(encoded(proof).decode(),message_id))
            return proof
    def message(self,message_id,peer,kind,source=None):
        proof=self.generated(message_id,peer,kind,encoded(source).decode() if source else None)
        return {'garden':self.config['garden'],'id':message_id,'from':self.identity,'to':peer,'kind':kind,
            'reply_to':source['id'] if source else None,'text':proof['text'],
            'model':{'name':MODEL_NAME,'weights_sha256':MODEL_SHA,'text_sha256':proof['text_sha256'],
                     'completion_tokens':proof['completion_tokens'],'call_id':message_id}}
    def validate_message(self,body,actor,kind):
        if (not isinstance(body,dict) or set(body)!={'garden','id','from','to','kind','reply_to','text','model'} or
            body['garden']!=self.config['garden'] or body['from']!=actor or body['to']!=self.identity or body['kind']!=kind):
            raise ValueError('Unexpected model message')
        UUID(body['id'])
        model=body['model']
        if (not isinstance(body['text'],str) or not 1<=len(body['text'])<=160 or any(ord(c)<32 for c in body['text']) or
            model.get('name')!=MODEL_NAME or model.get('weights_sha256')!=MODEL_SHA or model.get('call_id')!=body['id'] or
            model.get('text_sha256')!=sha(body['text'].encode()) or type(model.get('completion_tokens')) is not int or model['completion_tokens']<1):
            raise ValueError('Invalid completion evidence')
    def receive(self,actor,body):
        self.validate_message(body,actor,'hello')
        if body['reply_to'] is not None: raise ValueError('A greeting cannot refer to a prior message')
        payload=encoded(body).decode()
        with self.lock:
            old=self.db.execute('SELECT * FROM inbox WHERE id=?',(body['id'],)).fetchone()
            if old and (old['payload']!=payload or old['actor']!=actor): raise ValueError('Changed duplicate message')
            if old and old['reply']: return json.loads(old['reply'])
            if not old:
                if self.db.execute('SELECT count(*) FROM inbox').fetchone()[0]>=8: raise ValueError('Introduction quota exhausted')
                with self.db: self.db.execute('INSERT INTO inbox VALUES (?,?,?,NULL)',(body['id'],actor,payload))
        reply=self.message(str(uuid5(UUID(self.config['garden']),'reply/'+body['id'])),actor,'reply',body)
        with self.lock,self.db: self.db.execute('UPDATE inbox SET reply=? WHERE id=?',(encoded(reply).decode(),body['id']))
        return reply
    def exchange(self,peer):
        ident=str(uuid5(UUID(self.config['garden']),'hello/'+self.identity+'/'+peer))
        hello=self.message(ident,peer,'hello')
        reply,tls=self.rpc(peer,'/hello',hello)
        self.validate_message(reply,peer,'reply')
        if reply['reply_to']!=ident: raise ValueError('Reply correlation mismatch')
        with self.lock,self.db:
            self.db.execute('INSERT OR IGNORE INTO delivered VALUES (?,?,?,?)',(ident,peer,encoded(hello).decode(),encoded(reply).decode()))
        return {'peer':peer,'tls':tls,'hello':hello,'reply':reply}
    def snapshot(self):
        with self.lock:
            calls=[dict(row) for row in self.db.execute('SELECT * FROM calls ORDER BY id')]
            for row in calls:
                if row['proof']: row['proof']=json.loads(row['proof'])
            return {'identity':self.identity,'role':'orchestrator' if self.identity=='mother' else 'worker',
                'ready':self.ready,'error':self.error,'model':self.model.snapshot(),'calls':calls,
                'received':[json.loads(row['payload']) for row in self.db.execute('SELECT payload FROM inbox')],
                'delivered':[{'hello':json.loads(row['hello']),'reply':json.loads(row['reply'])} for row in self.db.execute('SELECT * FROM delivered')],
                'heartbeat_received':dict(self.heartbeats),'heartbeat_acknowledged':dict(self.sent_heartbeats),
                'public_identity':self.public,'pid':os.getpid(),'interfaces':sorted(p.name for p in Path('/sys/class/net').iterdir()),
                'routes':Path('/proc/net/route').read_text(),'dns':Path('/etc/resolv.conf').read_text()}
    def background(self):
        while not self.stop.wait(2):
            try:
                self.update_bundle()
                with self.lock: names=[name for name in self.known if name!=self.identity]
                for name in names:
                    try:
                        result,_=self.rpc(name,'/heartbeat',{'from':self.identity,'garden':self.config['garden']},timeout=3)
                        if not result['ok'] or result['from']!=name: raise ValueError('Wrong heartbeat identity')
                        with self.lock: self.sent_heartbeats[name]=self.sent_heartbeats.get(name,0)+1
                    except (OSError,ValueError): pass # Initial boot/enrollment is allowed to be pending.
            except (OSError,ValueError): pass
    def wait_ready(self,peers):
        deadline=time.monotonic()+180
        last='no status response'
        while time.monotonic()<deadline:
            try:
                statuses={name:self.rpc(name,'/status',timeout=5)[0] for name in peers}
                if all(value['ready'] and not value['error'] for value in statuses.values()): return statuses
                last=str({name:(value['ready'],value['error']) for name,value in statuses.items()})
            except ValueError:
                # A status authorization/schema failure is not startup delay.
                # Fail promptly instead of hiding it behind a readiness timeout.
                raise
            except (OSError,KeyError) as error: last=type(error).__name__+': '+str(error)
            time.sleep(1)
        raise TimeoutError('Garden peers did not become model-ready: '+last)
    def mother(self):
        self.wait_ready(('offshoot-1','offshoot-2'))
        baseline=[self.exchange(name) for name in ('offshoot-1','offshoot-2')]
        before=self.rpc('offshoot-1','/status')[0]
        # A negative control can be observed over the same LAN but cannot run
        # this installer: no SSH service is provisioned there.
        import socket
        try:
            with socket.create_connection(('192.0.2.5',2222),2):
                raise ValueError('Negative control unexpectedly exposed an installer entry point')
        except (ConnectionRefusedError,TimeoutError,OSError): negative=True
        cfg={key:self.config[key] for key in ('garden','request_id','grant','manifest_sha256','mother_certificate')}
        cfg.update(identity='sprout-4',mother='https://192.0.2.1:8443')
        if self.config.get('test_case')=='wrong-grant': cfg['grant']='intentionally-invalid-lab-grant'
        installer=(BASE/'lab/lan_install.py').read_text().replace('from __future__ import annotations\n','')
        script='CONFIG='+repr(cfg)+'\n'+installer
        # Strict host pin, fixed owned destination, no forwarding or password.
        command=['/usr/bin/ssh','-F','/dev/null','-T','-p','2222','-i','/workspace/lab/enroll_key',
            '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
            '-o','UserKnownHostsFile=/workspace/lab/known_hosts','-o','GlobalKnownHostsFile=/dev/null',
            '-o','ConnectTimeout=3','-o','PasswordAuthentication=no','-o','ClearAllForwardings=yes',
            'garden@192.0.2.4','/usr/bin/python3 -I -']
        self.enrollment=time.monotonic()+300
        started=time.monotonic()
        completed=subprocess.run(command,input=script,text=True,capture_output=True,timeout=300)
        if completed.returncode: raise RuntimeError('Authorized bootstrap failed: '+completed.stderr[-1200:]+completed.stdout[-1200:])
        installed=json.loads(completed.stdout)
        if installed.get('ok') is not True or installed.get('duplicate'): raise ValueError('Fresh installation was not established')
        self.wait_ready(('sprout-4',))
        joined=self.exchange('sprout-4')
        duplicate=subprocess.run(command,input=script,text=True,capture_output=True,timeout=15)
        if duplicate.returncode: raise ValueError('Duplicate bootstrap check failed')
        repeated=json.loads(duplicate.stdout)
        if repeated.get('duplicate') is not True or repeated['process']!=installed['process']:
            raise ValueError('Duplicate request created another process')
        deadline=time.monotonic()+150
        while time.monotonic()<deadline:
            target=self.rpc('sprout-4','/status')[0]
            if len(target['delivered'])==2: break
            time.sleep(1)
        else: raise TimeoutError('Recruited agent did not communicate with both offshoots')
        begin=time.monotonic();at_start={name:self.rpc(name,'/status')[0] for name in MEMBERS if name!='mother'}
        while time.monotonic()-begin<60: time.sleep(1)
        statuses={name:self.rpc(name,'/status')[0] for name in MEMBERS if name!='mother'}
        statuses['mother']=self.snapshot()
        active={name:dict(value['heartbeat_received']) for name,value in statuses.items()}
        for name,old in at_start.items():
            for peer in MEMBERS:
                if peer!=name and statuses[name]['heartbeat_received'].get(peer,0)<=old['heartbeat_received'].get(peer,0):
                    raise ValueError('Encrypted garden heartbeat did not continue')
        report={'passed':True,'schema':'agenticvm.lan-enrollment.guest.v1','garden':self.config['garden'],
            'enrollment_trigger':'fixed authorized mother policy; model generates messages only',
            'strict_zero_preparation_satisfied':False,'prerequisite':'preauthorized key-only SSH for the named target',
            'baseline':baseline,'new_mother_exchange':joined,'installed':installed,'duplicate':repeated,
            'negative_control_no_entry_point':negative,'idle_contact_seconds':round(time.monotonic()-begin,3),
            'offshoot_1_heartbeat_before_enrollment':before['heartbeat_received'],
            'statuses':statuses,'heartbeat_received':active,'enrollment_and_contact_seconds':round(time.monotonic()-started,3)}
        save(BASE/'lan-report.json',report);os.sync()
    def run(self):
        print('LAN_NODE_START '+self.identity,flush=True)
        if self.identity=='mother': self.start_server(8443,True)
        else:
            if self.identity=='sprout-4':
                result,_=request('192.0.2.1',8443,'/enroll',context(self.config['mother_certificate']),
                    body={'request_id':self.config['request_id'],'identity':self.identity,'certificate':self.public['certificate'],'grant':self.config['grant']},
                    expected=pin(self.config['mother_certificate']),timeout=10)
                if not result['ok']: raise ValueError('Enrollment rejected')
                self.known=result['bundle']['members']
            else: self.update_bundle()
        self.start_server(9443)
        threading.Thread(target=self.background,daemon=True).start()
        self.model.start();self.ready=True
        print('LAN_MODEL_READY '+self.identity,flush=True)
        if self.identity=='mother': self.mother()
        elif self.identity=='sprout-4':
            self.wait_ready(('offshoot-1','offshoot-2'))
            for peer in ('offshoot-1','offshoot-2'): self.exchange(peer)
        while not self.stop.wait(1): self.model.ensure_alive()

def main():
    node=None
    try:
        node=Node(json.loads((BASE/'lan-config.json').read_text()));node.run()
    except Exception as error:
        if node: node.error=type(error).__name__+': '+str(error)
        report={'passed':False,'identity':node.identity if node else None,'error':type(error).__name__+': '+str(error)}
        if node:
            try: report['mother_status']=node.snapshot()
            except Exception: pass
        save(BASE/'lan-report.json',report);os.sync()
        import traceback;traceback.print_exc()
        while True: time.sleep(30)

if __name__=='__main__': main()
