"""Explicit two-way file sync with revisions, conflict receipts and CAS writes."""
import os
from uuid import uuid4

from .control_client import safe_path
from .control_guest import Guest,MAX_FILE,sha
from .control_store import Metadata,fail,identifier,load_json,save_json


class Sync:
    def __init__(self,controller,exchange):
        self.controller=controller
        self.guest=Guest(controller)
        self.exchange=exchange
        self.meta=Metadata(controller.workspace/'control'/('profile-'+controller.profile)/'sync')

    def host(self,value):
        path=safe_path(value,self.exchange)
        if not path.exists():
            return path,None
        if not path.is_file() or path.stat().st_size>MAX_FILE:
            fail('Sync requires regular files up to 1 MiB.','file_too_large')
        with path.open('rb') as stream:
            data=stream.read(MAX_FILE+1)
        if len(data)>MAX_FILE:
            fail('Sync file grew beyond 1 MiB.','file_too_large')
        return path,data

    def record(self,name):
        name=identifier(name)
        record=load_json(self.meta.path(name+'.json'))
        if not isinstance(record,dict) or record.get('name')!=name:
            fail('Unknown sync pair.','invalid_sync')
        return record

    def create(self,name,exchange_path,guest_path):
        name=identifier(name)
        self.host(exchange_path)
        guest_path=self.guest.path(guest_path)
        with self.meta.lock():
            path=self.meta.path(name+'.json')
            if path.exists():
                fail('This sync pair already exists.','sync_conflict')
            record={'name':name,'exchange_path':exchange_path,'guest_path':guest_path,
                'revision':0,'host_hash':None,'guest_hash':None,'initialized':False}
            save_json(path,record)
            return record

    def inspect(self,name):
        with self.meta.lock():
            record=self.record(name)
            _,host=self.host(record['exchange_path'])
            guest=self.guest.optional(record['guest_path'])
            h,g=sha(host),sha(guest)
            conflict=h!=g and ((not record['initialized'] and h is not None and g is not None) or
                (record['initialized'] and h!=record['host_hash'] and g!=record['guest_hash']))
            return {**record,'observed_host_hash':h,'observed_guest_hash':g,'conflict':conflict,
                'host_changed':h!=record['host_hash'],'guest_changed':g!=record['guest_hash']}

    def apply(self,name,revision,direction='auto',host_hash=None,guest_hash=None):
        if type(revision) is not int or direction not in {'auto','push','pull','keep-host','keep-guest','keep-both'}:
            fail('Choose a sync direction and exact revision.','invalid_sync')
        with self.meta.lock():
            observed=self.inspect(name)
            if observed['revision']!=revision:
                fail('Sync revision changed. Inspect the pair again.','sync_conflict')
            resolving=direction.startswith('keep-')
            if resolving and (host_hash!=observed['observed_host_hash'] or guest_hash!=observed['observed_guest_hash']):
                fail('Conflict versions changed. Inspect the pair again.','sync_conflict')
            if observed['conflict'] and not resolving:
                return {**observed,'applied':False,'reason':'both_changed'}
            destination,host=self.host(observed['exchange_path'])
            guest=self.guest.optional(observed['guest_path'])
            h,g=sha(host),sha(guest)
            if (h,g)!=(observed['observed_host_hash'],observed['observed_guest_hash']):
                fail('Sync input changed during observation.','sync_conflict')
            if direction=='auto':
                direction='push' if h!=observed['host_hash'] or (not observed['initialized'] and host is not None) else 'pull'
            if direction=='push' and observed['initialized'] and g!=observed['guest_hash'] and h!=g:
                return {**observed,'applied':False,'reason':'guest_changed'}
            if direction=='pull' and observed['initialized'] and h!=observed['host_hash'] and h!=g:
                return {**observed,'applied':False,'reason':'host_changed'}
            preserved=None
            if direction=='keep-both' and host!=guest:
                if host is None or guest is None:
                    fail('Keep-both requires two existing files.','invalid_sync')
                preserved=observed['exchange_path']+'.guest-'+uuid4().hex
                other=safe_path(preserved,self.exchange)
                other.parent.mkdir(parents=True,exist_ok=True)
                with other.open('xb') as stream:
                    stream.write(guest)
                direction='keep-host'
            if direction in {'push','keep-host'}:
                if host is None:
                    fail('The host source is missing; sync never infers deletion.','missing_file')
                self.guest.compare_write(observed['guest_path'],host,g)
                target=host
            else:
                if guest is None:
                    fail('The guest source is missing; sync never infers deletion.','missing_file')
                destination.parent.mkdir(parents=True,exist_ok=True)
                temporary=destination.with_name(destination.name+'.sync-'+uuid4().hex)
                try:
                    with temporary.open('xb') as stream:
                        stream.write(guest); stream.flush(); os.fsync(stream.fileno())
                    if sha(self.host(observed['exchange_path'])[1])!=h:
                        fail('Host file changed during transfer.','sync_conflict')
                    # The service serializes sync clients. In-guest applications
                    # and external host editors remain optimistic competitors.
                    safe_path(observed['exchange_path'],self.exchange)
                    os.replace(temporary,destination)
                finally:
                    temporary.unlink(missing_ok=True)
                target=guest
            record={key:observed[key] for key in ('name','exchange_path','guest_path','revision','host_hash','guest_hash','initialized')}
            record.update(revision=revision+1,host_hash=sha(target),guest_hash=sha(target),initialized=True)
            save_json(self.meta.path(name+'.json'),record)
            return {**record,'applied':True,'preserved_exchange_path':preserved}
