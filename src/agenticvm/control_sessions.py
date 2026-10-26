"""Owned session inventory and expiring operator leases. No host VM discovery."""
import secrets
import hashlib
import json
import time

from .control_store import Metadata,fail,identifier,load_json,save_json
from .control_diagnostics import PROFILES,generation,state


def epoch(controller):
    saved=state(controller)
    identity={key:saved.get(key) for key in ('uuid','pid','process_created','registered','launcher','processes','stopped_at')}
    return hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()


class Sessions:
    def __init__(self, main):
        self.main=main
        self.meta=Metadata(main.workspace/'control')
        self.controllers={'main':main}

    def records(self):
        data=load_json(self.meta.path('sessions.json'),default={})
        if not isinstance(data,dict) or len(data)>16:
            fail('Session registry is invalid.','invalid_state')
        for key,record in data.items():
            identifier(key)
            if key=='main' or not isinstance(record,dict) or set(record)!={'vm','created_at','disposable'} or record['vm'] not in {'linux','android'} or type(record['disposable']) is not bool:
                fail('Session registry is invalid.','invalid_state')
        return data

    def create(self, name, vm, disposable=False):
        name=identifier(name)
        if name=='main' or vm not in {'linux','android'} or type(disposable) is not bool:
            fail('Create a named Linux or Android session. Windows uses its independently prepared main installation.','invalid_session')
        with self.meta.lock():
            records=self.records()
            if name in records or len(records)>=16:
                fail('Session already exists or the 16-session limit was reached.','session_conflict')
            records[name]={'vm':vm,'created_at':time.time(),'disposable':disposable}
            save_json(self.meta.path('sessions.json'),records)
        return {'session':name,**records[name]}

    def resolve(self, name):
        name=identifier(name)
        if name=='main':
            return self.main
        with self.meta.lock():
            record=self.records().get(name)
            if record is None:
                fail('Unknown owned session.','invalid_session')
            if name not in self.controllers:
                from .viewer import ViewerController
                root=self.meta.path('sessions/'+name+'/workspace')
                controller=ViewerController(root,'managed-'+name,application_root=self.main.root)
                controller.select_profile('desktop' if record['vm']=='linux' else record['vm'])
                self.controllers[name]=controller
            return self.controllers[name]

    def inventory(self):
        with self.meta.lock():
            return {'sessions':[{'session':'main','vm':PROFILES[self.main.profile],'disposable':False}]+[
                {'session':name,**record} for name,record in sorted(self.records().items())]}


class Lease:
    def __init__(self,controller):
        self.controller=controller
        # Each profile owns its lease. Switching the main selector never transfers it.
        self.meta=Metadata(controller.workspace/'control'/('profile-'+PROFILES[controller.profile]+('-'+controller.os_id if controller.profile=='custom' else '')))

    def acquire(self,owner,seconds=120,token=None):
        if not isinstance(owner,str) or not 1<=len(owner)<=64 or any(ord(c)<32 for c in owner) or type(seconds) is not int or not 1<=seconds<=300:
            fail('Use an owner label and a lease duration of 1-300 seconds.','invalid_lease')
        with self.meta.lock():
            prior=load_json(self.meta.path('lease.json'),default={})
            current=generation(self.controller)
            live=prior.get('expires_at',0)>time.time() and prior.get('generation')==current and prior.get('epoch')==epoch(self.controller)
            if live and (not isinstance(token,str) or not secrets.compare_digest(token,prior.get('token',''))):
                fail('Another operator holds this VM.','lease_conflict')
            result={'owner':owner,'token':token if live else secrets.token_urlsafe(32),
                'generation':current,'epoch':epoch(self.controller),'expires_at':time.time()+seconds}
            save_json(self.meta.path('lease.json'),result)
            return result

    def require(self,token,expected):
        with self.meta.lock():
            lease=load_json(self.meta.path('lease.json'),default={})
            current=generation(self.controller)
            if expected!=current:
                fail('VM generation changed; observe and acquire a new lease.','generation_changed')
            if (not isinstance(token,str) or not secrets.compare_digest(token,lease.get('token',''))
                    or lease.get('expires_at',0)<=time.time() or lease.get('generation')!=current or lease.get('epoch')!=epoch(self.controller)):
                fail('Acquire a current operator lease before changing this session.','lease_required')

    def release(self,token,expected):
        with self.meta.lock():
            self.require(token,expected)
            save_json(self.meta.path('lease.json'),{})
            return {'released':True}
