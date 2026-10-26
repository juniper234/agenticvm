"""Continuous offline-VM agent. TLS endpoint keys are created inside this VM."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from peer_agent import FDTransport
from peer_protocol import BIOStream,PeerTLSConfig
from live_channel import Mailbox,serve

HOME = Path('/workspace/peer')


def initialize(identity):
    HOME.mkdir(mode=0o700,exist_ok=True)
    os.umask(0o077)
    key,cert = HOME/'live.key',HOME/'live.pem'
    if key.exists() or cert.exists():
        raise ValueError('Refusing to replace an existing live identity')
    command = ['/usr/bin/openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
        '-noenc','-sha256','-days','7','-subj','/CN='+identity,
        '-addext','basicConstraints=critical,CA:TRUE,pathlen:0',
        '-addext','keyUsage=critical,digitalSignature,keyCertSign',
        '-addext','extendedKeyUsage=serverAuth,clientAuth',
        '-addext','subjectAltName=URI:urn:agenticvm:peer:'+identity,
        '-keyout',str(key),'-out',str(cert)]
    result = subprocess.run(command,capture_output=True,timeout=15)
    if result.returncode:
        raise RuntimeError('Could not create local TLS identity')
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    return {'identity':identity,'sha256':pin,'private_key_exported':False,'validity_days':7}


def percentiles(values):
    ordered = sorted(values)
    if not ordered:
        return None
    return {'count':len(ordered),'min_ms':round(ordered[0],3),
            'p50_ms':round(ordered[int((len(ordered)-1)*.50)],3),
            'p95_ms':round(ordered[int((len(ordered)-1)*.95)],3),
            'p99_ms':round(ordered[int((len(ordered)-1)*.99)],3),'max_ms':round(ordered[-1],3)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--initialize',action='store_true')
    parser.add_argument('--identity',choices=('guest-a','guest-b'),required=True)
    parser.add_argument('--config',type=Path)
    args = parser.parse_args()
    if args.initialize:
        print(json.dumps(initialize(args.identity)))
        return 0
    config = json.loads(args.config.read_text())
    peer = 'guest-b' if args.identity == 'guest-a' else 'guest-a'
    if sorted(path.name for path in Path('/sys/class/net').iterdir()) != ['lo']:
        raise ValueError('Live offline agent unexpectedly has an external network interface')
    tls = PeerTLSConfig(str(HOME/'live.pem'),str(HOME/'live.key'),str(HOME/'remote.pem'),config['peer_pin'],peer,alpn='agenticvm-live/1')
    mailbox = Mailbox(HOME/'live.sqlite',config['run_id'],args.identity,peer)
    origin, total, interval = time.monotonic()+1,config['messages'],config['interval']
    pauses_at, pause = total//2,config['idle_seconds']
    continuous = total == 0
    counts, rtts, steady_rtts, connections, failures = {},[],[],[],[]
    evidence = (HOME/'live-evidence.jsonl').open('x',encoding='ascii')
    started = time.monotonic()

    def event(name,**fields):
        counts[name] = counts.get(name,0)+1
        if not continuous and evidence.tell() > 8*1024**2:
            raise BufferError('Live metadata evidence limit reached')
        if not continuous:
            evidence.write(json.dumps({'event':name,'at_unix_ms':int(time.time()*1000),**fields},ensure_ascii=True)+'\n')
            evidence.flush()
        if name == 'connected':
            connections.append({'at_seconds':time.monotonic()-started,**fields})
            if continuous:
                del connections[:-16]
        elif name == 'disconnected':
            failures.append(fields)
            if continuous:
                del failures[:-32]
        elif name == 'acknowledged':
            for sequence in range(fields['previous']+1,fields['received']+1):
                payload = json.loads(mailbox.db.execute('SELECT payload FROM outgoing WHERE seq=?',(sequence,)).fetchone()[0])
                elapsed = (time.monotonic_ns()-payload['queued_ns'])/1e6
                rtts.append(elapsed)
                if len(connections) == 1:
                    steady_rtts.append(elapsed)
            if continuous:
                del rtts[:-4096]
                del steady_rtts[:-4096]

    def produce(box,now):
        if continuous:
            # The demo application consumes validated data before retention can
            # discard it. Real applications commit their effects before consume.
            for row in box.incoming():
                data = json.loads(row['payload'])
                if data['counter'] != row['seq'] or data['text'] != 'continuous-private-marker \u4f60\u597d':
                    raise ValueError('Invalid continuous application event')
                box.consume(row['seq'])
            box.prune(keep=128)
        sent = box.state()['sent']
        # At most eight admissions per reactor turn. No message is silently skipped.
        for _ in range(8):
            due = origin+sent*interval+(pause if not continuous and sent >= pauses_at else 0)
            if (not continuous and sent >= total) or now < due:
                break
            try:
                box.enqueue({'op':'event','counter':sent+1,'queued_ns':time.monotonic_ns(),
                             'text':'continuous-private-marker \u4f60\u597d'})
            except BufferError:
                return
            sent += 1

    def complete(box):
        if continuous:
            return False
        state = box.state()
        return state == {'sent':total,'received':total,'acked':total}

    def connect():
        return BIOStream(FDTransport('/dev/virtio-ports/org.agenticvm.peer'),tls,
                         server_side=args.identity == 'guest-a',timeout=6)

    summary = {'passed':False,'identity':args.identity,'peer':peer,'interfaces':['lo'],
               'language_model_used':False,'private_key_exported':False}
    try:
        result = serve(mailbox,connect,seconds=config['deadline_seconds'],produce=produce,completed=complete,event=event)
        # Validate every received payload inside the recipient, independently of TLS metadata.
        rows = mailbox.db.execute('SELECT seq,payload FROM incoming ORDER BY seq').fetchall()
        contents_valid = all(json.loads(row['payload'])['counter'] == row['seq'] and
            json.loads(row['payload'])['text'] == 'continuous-private-marker \u4f60\u597d' for row in rows)
        summary.update(passed=result and complete(mailbox) and contents_valid, state=mailbox.state(),
            counters=counts,connections=connections,disconnects=failures,durable_ack_latency=percentiles(rtts),
            first_connection_durable_ack_latency=percentiles(steady_rtts),payloads_verified=contents_valid,
            seconds=round(time.monotonic()-started,3),
            private_key_sha256=hashlib.sha256((HOME/'live.key').read_bytes()).hexdigest())
    except Exception as error:
        summary['error'] = {'class':type(error).__name__,'message':str(error)[:500]}
    finally:
        evidence.close()
        mailbox.close()
        with (HOME/'live-summary.json').open('x',encoding='ascii') as output:
            output.write(json.dumps(summary,indent=2)+'\n')
            output.flush()
            os.fsync(output.fileno())
    print(json.dumps({'passed':summary['passed'],'state':summary.get('state'),'error':summary.get('error')}))
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
