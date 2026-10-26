"""A garden member with dynamically enrolled, independently encrypted peers."""
from __future__ import annotations
import argparse
import json
import os
import resource
from pathlib import Path
import sys
import threading
import time
from uuid import UUID,uuid5

sys.path.insert(0,str(Path(__file__).resolve().parent))
from garden_wire import Multiplexer
from live_agent import initialize
from live_channel import Mailbox,serve
from peer_agent import FDTransport
from peer_protocol import BIOStream,PeerTLSConfig

HOME = Path('/workspace/peer')
MARKER = 'Hello from the garden — 你好'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--member',type=int,choices=(1,2,3),required=True)
    parser.add_argument('--initialize',action='store_true')
    parser.add_argument('--lfm',action='store_true',help='Generate and answer messages with the local LFM model')
    args = parser.parse_args()
    identity = 'sprout-'+str(args.member)
    if args.initialize:
        print(json.dumps(initialize(identity)))
        return 0
    interfaces = sorted(p.name for p in Path('/sys/class/net').iterdir())
    if interfaces != ['lo']:
        raise ValueError('The garden expects offline Linux guests')
    # The stock profile retains RLIMIT_AS=128 MiB; the LFM boot uses 2 GiB
    # virtual address space for model mmap, bounded by 512 MiB physical RAM.
    # glibc's
    # default per-thread arenas can reserve 64 MiB each without using that
    # amount of RAM. Start with MALLOC_ARENA_MAX=1 and small, explicit stacks
    # rather than removing the sandbox's existing address-space bound.
    if os.environ.get('MALLOC_ARENA_MAX') != '1':
        raise ValueError('Garden requires its bounded allocator configuration')
    threading.stack_size(256*1024)
    mux = Multiplexer(FDTransport('/dev/virtio-ports/org.agenticvm.peer'),args.member)
    lock = threading.Lock()
    status = {'identity':identity,'member':args.member,'interfaces':interfaces,'model_inference':args.lfm,
              'private_key_exported':False,'links':{},'errors':[],'running':True,'heartbeat_sequence':0,
              'allocator_arena_max':1,'thread_stack_bytes':256*1024,
              'address_space_limit_bytes':resource.getrlimit(resource.RLIMIT_AS)[0]}
    threads = {}
    stop = threading.Event()
    chat = None
    if args.lfm:
        from garden_chat import Chat
        config = json.loads((HOME/'garden.json').read_text())
        chat = Chat(HOME/'chat.sqlite',config['garden'],args.member)
        chat.start()

    def link(peer,config,garden):
        remote = 'sprout-'+str(peer)
        room = str(uuid5(UUID(garden),'/'.join(map(str,sorted((args.member,peer))))))
        tls = PeerTLSConfig(str(HOME/'live.pem'),str(HOME/'live.key'),str(HOME/(remote+'.pem')),
                            config['sha256'],remote,alpn='agenticvm-garden-lfm/1' if args.lfm else 'agenticvm-garden/1')
        box = Mailbox(HOME/(remote+'.sqlite'),room,identity,remote)
        next_send = time.monotonic()
        last_status = 0
        value = {'connected':False,'connections':0,'received_verified':0,'last_received':None,'state':box.state(),'events':{}}
        with lock:
            status['links'][str(peer)] = value

        def produce(mailbox,now):
            nonlocal next_send,last_status
            for row in mailbox.incoming():
                payload = json.loads(row['payload'])
                if chat:
                    chat.accept(peer,payload)
                else:
                    expected = {'op':'garden-message','garden':garden,'from':remote,'to':identity,
                                'counter':row['seq'],'text':MARKER}
                    if payload != expected:
                        raise ValueError('Garden recipient rejected changed or misrouted application data')
                with lock:
                    value['received_verified'] += 1
                    value['last_received'] = payload
                mailbox.consume(row['seq'])
            mailbox.prune(keep=128)
            if chat:
                for payload in chat.pending(peer):
                    try:
                        mailbox.enqueue(payload,identifier=payload['id'])
                    except BufferError:
                        break
                    chat.enqueued(payload['id'])
                with lock:
                    value['application'] = chat.peer_snapshot(peer)
            elif now >= next_send:
                try:
                    mailbox.enqueue({'op':'garden-message','garden':garden,'from':identity,'to':remote,
                                     'counter':mailbox.state()['sent']+1,'text':MARKER})
                    next_send = now+1
                except BufferError:
                    next_send = now+.25
            if now-last_status >= .25:
                with lock:
                    value['state'] = mailbox.state()
                last_status = now

        def event(name,**fields):
            with lock:
                value['events'][name] = value['events'].get(name,0)+1
                if name == 'connected':
                    value.update(connected=True,tls=fields['tls'],connections=value['connections']+1)
                elif name == 'disconnected':
                    value.update(connected=False,last_disconnect=fields)
                value['state'] = box.state()

        try:
            serve(box,lambda:BIOStream(mux.channel(peer),tls,server_side=args.member<peer,timeout=8),
                  produce=produce,event=event,stop=stop.is_set)
        except Exception as error:
            with lock:
                status['errors'].append({'peer':peer,'class':type(error).__name__,'message':str(error)[:250]})
            stop.set()
        finally:
            box.close()

    def guarded_link(*args):
        try:
            link(*args)
        except Exception as error:
            with lock:
                status['errors'].append({'class':type(error).__name__,'message':str(error)[:250]})
            stop.set()

    try:
        while not stop.is_set() and not mux.stopped.is_set():
            config = json.loads((HOME/'garden.json').read_text())
            garden = str(UUID(config['garden']))
            for key,peer in config['peers'].items():
                number = int(key)
                if number not in (1,2,3) or number == args.member:
                    raise ValueError('Invalid enrolled garden peer')
                if number not in threads:
                    if chat:
                        chat.enroll(number)
                    thread = threading.Thread(target=guarded_link,args=(number,peer,garden),daemon=True)
                    threads[number] = thread
                    thread.start()
            model = chat.snapshot() if chat else None
            if model and model['error']:
                raise RuntimeError('Local model failed: '+json.dumps(model['error']))
            with lock:
                if model:
                    status['model'] = model
                status['heartbeat_sequence'] += 1
                status.update(garden=garden,updated_unix_ms=int(time.time()*1000),wire_error=mux.error)
                status['memory'] = {line.split(':')[0]:line.split(':',1)[1].strip()
                    for line in Path('/proc/self/status').read_text().splitlines() if line.startswith(('VmSize:','VmRSS:'))}
                content = json.dumps(status,ensure_ascii=True)
            temp = HOME/'garden-status.tmp'
            temp.write_text(content+'\n')
            temp.replace(HOME/'garden-status.json')
            stop.wait(.25)
        return 1
    except Exception as error:
        with lock:
            status['errors'].append({'class':type(error).__name__,'message':str(error)[:250]})
        return 1
    finally:
        stop.set()
        with lock:
            status['heartbeat_sequence'] += 1
            status.update(running=False,updated_unix_ms=int(time.time()*1000),wire_error=mux.error)
            content = json.dumps(status,ensure_ascii=True)
        temp = HOME/'garden-status.tmp'
        temp.write_text(content+'\n')
        temp.replace(HOME/'garden-status.json')
        if chat:
            chat.close()
        mux.close()
        for thread in threads.values():
            thread.join(2)


if __name__ == '__main__':
    raise SystemExit(main())
