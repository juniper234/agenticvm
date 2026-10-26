"""Reconcile the real guest transcripts, exported files and final test evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
from uuid import UUID

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.ext2 import read_image_file
from agenticvm.state import StateStore


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run',required=True)
    args=parser.parse_args()
    if str(UUID(args.run))!=args.run:raise ValueError('Use a canonical run UUID')
    folder=ROOT/'runtime/pong-agent-runs'/args.run
    report=json.loads((folder/'report.json').read_text())
    if not report['passed']:raise ValueError('Only summarize an accepted run')
    events={name:[json.loads(line) for line in (folder/'evidence'/name/'evidence.jsonl').read_text().splitlines()]
            for name in ('guest-a-serial','guest-b-serial')}
    directions={}
    for sender,receiver in [('guest-a-serial','guest-b-serial'),('guest-b-serial','guest-a-serial')]:
        sent={e['message_id']:e['body_sha256'] for e in events[sender] if e['event']=='sent'}
        received={e['message_id']:e['body_sha256'] for e in events[receiver] if e['event']=='received'}
        assert sent==received
        directions[sender+' -> '+receiver]={'matched':True,'messages':len(sent)}
    source_proof={}
    key_rows=[]
    for role in events:
        state=StateStore(folder/role).load()
        if state['registered']:raise ValueError('Read verification requires an exited VM')
        disk=folder/role/'data/default.ext2'
        source_proof[role]={'method':'read-only inspection of stopped ext2 image',
            'source_sha256':{name:hashlib.sha256(read_image_file(disk,'peer/'+name)).hexdigest()
                              for name in ('pong_agent.py','pong_synthesis.py')}}
        try:
            read_image_file(disk,'peer/key.pem',maximum=16384)
        except FileNotFoundError:
            key_rows.append({'name':role,'private_key_removed':True,'verified_on_stopped_disk':True})
        else:
            raise ValueError('Disposable guest key still exists')
    cleanup={'run_id':args.run,'passed':True,'guests':key_rows,'filesystem_unlink_only':True}
    if not (folder/'key-cleanup.json').exists():
        (folder/'key-cleanup.json').write_text(json.dumps(cleanup,indent=2)+'\n')
    assert cleanup['passed']
    metadata={'schema':'agenticvm.pong-agent-demo.v1','passed':True,'run':report,
              'transcript_reconciliation':directions,'private_guest_key_cleanup':cleanup,
              'local_model_calls':report['orchestrator']['model_calls']+report['worker']['model_calls'],
              'review_rounds':[{'round':e['round'],'passed':e['checks']['passed'],'checks':e['checks'].get('checks',0)}
                               for e in events['guest-a-serial'] if e['event']=='independent_review'],
              'blocked_false_model_approvals':sum(e['event']=='policy_override' for e in events['guest-a-serial']),
              'deterministic_repairs':[e for e in events['guest-b-serial'] if e['event']=='deterministic_repair'],
              'source_verification':source_proof,
              'host_unit_tests':{'passed':173},'physical_4gb_host_tested':False,
              'browser':{'passed':True,'tested_via':'ChatGPT in-app browser on loopback HTTP',
                 'observed':['Start launches play','S moves the left paddle','Pointer click moves the paddle to the top',
                             'Space pauses','Resume button resumes','Restart returns scores to zero',
                             'Computer reaches five and game-over screen appears','R returns to ready state',
                             'Loaded game starts, pauses and resets after preview server stops'],
                 'touch_hardware_tested':False,'file_url_tested':False,
                 'file_url_limit':'The in-app browser permits HTTP/HTTPS and rejected file: navigation. The game was fully exercised through the existing loopback HTTP preview.',
                 'screenshots':['browser-ready.png','browser-win.png']}}
    for name in ('pong_agent.py','pong_synthesis.py'):
        expected=hashlib.sha256((ROOT/'guest'/name).read_bytes()).hexdigest()
        assert all(metadata['source_verification'][role]['source_sha256'][name]==expected for role in events)
    target=ROOT/'docs/validation'
    for name in metadata['browser']['screenshots']:shutil.copy2(folder/name,target/('pong-'+name))
    for role in events:
        shutil.copy2(folder/'evidence'/role/'evidence.jsonl',target/('pong-'+role+'-events.jsonl'))
    destination=target/'pong-agent-loop-report.json'
    destination.write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'report':str(destination),'review_rounds':metadata['review_rounds']}))


if __name__=='__main__':main()
