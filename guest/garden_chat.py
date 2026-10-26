"""Durable, bounded introductions and input-dependent replies from real LFM.

Each enrolled pair exchanges two model messages in each direction: an original
greeting and a reply to the other greeting. It then listens with live TLS
heartbeats instead of spending CPU generating endless unsolicited chatter.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from uuid import UUID,uuid5

from local_lfm import LocalLFM,MODEL_NAME,MODEL_SHA,text


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)


def identifier(value):
    if not isinstance(value,str) or str(UUID(value)) != value:
        raise ValueError('Expected a canonical message UUID')
    return value


def prompt_for(identity,peer,source=None):
    if source is None:
        return f'You are {identity}. Greet {peer}, another agent joining your garden. Write fewer than eight words. Return the JSON field text.'
    return (f'You are {identity}. Agent {peer} sent this message: '+canonical(source['text'])+
            '. Write a friendly reply in fewer than eight words. Return the JSON field text.')


class Chat:
    def __init__(self,path,garden,member,*,model=None):
        self.garden,self.member,self.identity = identifier(garden),member,'sprout-'+str(member)
        self.model = model if model is not None else LocalLFM()
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.error = None
        self.db = sqlite3.connect(path,timeout=10,check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS meta(binding TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,peer INTEGER,kind TEXT,source TEXT,state TEXT,proof TEXT);
            CREATE TABLE IF NOT EXISTS incoming(id TEXT PRIMARY KEY,peer INTEGER,payload TEXT);
            CREATE TABLE IF NOT EXISTS outgoing(id TEXT PRIMARY KEY,peer INTEGER,payload TEXT,enqueued INTEGER DEFAULT 0);
        ''')
        binding = canonical({'garden':garden,'member':member})
        old = self.db.execute('SELECT binding FROM meta').fetchone()
        if old and old['binding']!=binding:
            self.db.close()
            raise ValueError('Chat ledger belongs to another garden/member')
        if not old:
            with self.db:
                self.db.execute('INSERT INTO meta VALUES (?)',(binding,))
        if self.db.execute("SELECT 1 FROM tasks WHERE state='generating'").fetchone():
            self.db.close()
            raise ValueError('Interrupted model generation requires an explicit new garden; it is not silently replayed')
        self.thread = threading.Thread(target=self._worker,name='garden-lfm',daemon=True)

    def start(self):
        self.thread.start()

    def _peer(self,peer):
        if type(peer) is not int or peer not in (1,2,3) or peer==self.member:
            raise ValueError('Peer is outside this bounded garden')
        return 'sprout-'+str(peer)

    def enroll(self,peer):
        self._peer(peer)
        task_id = str(uuid5(UUID(self.garden),f'hello/{self.member}/{peer}'))
        with self.lock,self.db:
            self.db.execute('INSERT OR IGNORE INTO tasks VALUES (?,?,?,?,?,NULL)',(task_id,peer,'hello',None,'queued'))

    def accept(self,peer,payload):
        remote = self._peer(peer)
        fields = {'op','garden','from','to','id','kind','reply_to','text','model'}
        if not isinstance(payload,dict) or set(payload)!=fields or payload['op']!='garden-chat' or payload['garden']!=self.garden or payload['from']!=remote or payload['to']!=self.identity or payload['kind'] not in ('hello','reply'):
            raise ValueError('Wrong model-message schema or routing')
        message = identifier(payload['id'])
        content = text(payload['text'])
        if content!=payload['text']:
            raise ValueError('Model message text must match its exact normalized completion')
        proof = payload['model']
        if (not isinstance(proof,dict) or set(proof)!={'name','weights_sha256','call_id','text_sha256','completion_tokens'} or
                proof['name']!=MODEL_NAME or proof['weights_sha256']!=MODEL_SHA or proof['call_id']!=message or
                proof['text_sha256']!=hashlib.sha256(content.encode()).hexdigest() or
                type(proof['completion_tokens']) is not int or proof['completion_tokens']<1):
            raise ValueError('Invalid model-message provenance')
        encoded = canonical(payload)
        with self.lock,self.db:
            previous = self.db.execute('SELECT payload FROM incoming WHERE id=?',(message,)).fetchone()
            if previous:
                if previous['payload']!=encoded:
                    raise ValueError('Model message ID reused with changed content')
                return False
            if self.db.execute('SELECT COUNT(*) FROM incoming').fetchone()[0]>=64:
                raise BufferError('Model introduction inbox quota reached')
            if payload['kind']=='hello':
                if payload['reply_to'] is not None:
                    raise ValueError('An introduction must not claim a parent message')
                task_id = str(uuid5(UUID(self.garden),'reply/'+self.identity+'/'+message))
                self.db.execute('INSERT INTO tasks VALUES (?,?,?,?,?,NULL)',
                    (task_id,peer,'reply',encoded,'queued'))
            else:
                parent = identifier(payload['reply_to'])
                own = self.db.execute('SELECT peer,payload FROM outgoing WHERE id=?',(parent,)).fetchone()
                if not own or own['peer']!=peer or json.loads(own['payload'])['kind']!='hello':
                    raise ValueError('Reply does not correlate to this agent\'s actual greeting')
            self.db.execute('INSERT INTO incoming VALUES (?,?,?)',(message,peer,encoded))
        return True

    def pending(self,peer):
        with self.lock:
            return [json.loads(r['payload']) for r in self.db.execute(
                'SELECT payload FROM outgoing WHERE peer=? AND enqueued=0 ORDER BY rowid',(peer,))]

    def enqueued(self,message):
        with self.lock,self.db:
            if not self.db.execute('SELECT 1 FROM outgoing WHERE id=?',(message,)).fetchone():
                raise ValueError('Unknown model output')
            self.db.execute('UPDATE outgoing SET enqueued=1 WHERE id=?',(message,))

    def _worker(self):
        try:
            self.model.start()
            while not self.stop.is_set():
                with self.lock,self.db:
                    task = self.db.execute("SELECT * FROM tasks WHERE state='queued' ORDER BY rowid LIMIT 1").fetchone()
                    if task:
                        self.db.execute("UPDATE tasks SET state='generating' WHERE id=?",(task['id'],))
                if not task:
                    self.stop.wait(.1)
                    continue
                source = json.loads(task['source']) if task['source'] else None
                prompt = prompt_for(self.identity,self._peer(task['peer']),source)
                result = self.model.generate(prompt)
                generated = text(result['text'])
                payload = {'op':'garden-chat','garden':self.garden,'from':self.identity,'to':self._peer(task['peer']),
                    'id':task['id'],'kind':task['kind'],'reply_to':source['id'] if source else None,'text':generated,
                    'model':{'name':MODEL_NAME,'weights_sha256':MODEL_SHA,'call_id':task['id'],
                             'text_sha256':hashlib.sha256(generated.encode()).hexdigest(),
                             'completion_tokens':result['completion_tokens']}}
                proof = {**result,'call_id':task['id'],'peer':task['peer'],'kind':task['kind'],
                         'source_message_id':source['id'] if source else None,'prompt':prompt}
                with self.lock,self.db:
                    self.db.execute('INSERT INTO outgoing (id,peer,payload) VALUES (?,?,?)',
                                    (task['id'],task['peer'],canonical(payload)))
                    self.db.execute("UPDATE tasks SET state='complete',proof=? WHERE id=?",(canonical(proof),task['id']))
        except Exception as error:
            self.error = {'class':type(error).__name__,'message':str(error)[:2000]}
        finally:
            if self.error:
                self.model.close()

    def peer_snapshot(self,peer):
        with self.lock:
            incoming = [json.loads(r['payload']) for r in self.db.execute('SELECT payload FROM incoming WHERE peer=?',(peer,))]
            outgoing = [json.loads(r['payload']) for r in self.db.execute('SELECT payload FROM outgoing WHERE peer=?',(peer,))]
        return {'received':incoming,'generated':outgoing,'received_count':len(incoming),'generated_count':len(outgoing),
                'received_hello':sum(x['kind']=='hello' for x in incoming),
                'received_reply':sum(x['kind']=='reply' for x in incoming)}

    def snapshot(self):
        with self.lock:
            calls = [json.loads(r['proof']) for r in self.db.execute("SELECT proof FROM tasks WHERE state='complete' ORDER BY rowid")]
            queued = self.db.execute("SELECT COUNT(*) FROM tasks WHERE state!='complete'").fetchone()[0]
        return {'server':self.model.snapshot(),'calls':calls,'completed_calls':len(calls),'pending_calls':queued,'error':self.error}

    def close(self):
        self.stop.set()
        self.model.close()
        if self.thread.is_alive():
            self.thread.join(8)
        if not self.thread.is_alive():
            self.db.close()
