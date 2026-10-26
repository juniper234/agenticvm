"""Live encrypted contact between two simultaneous Linux VMs, without NICs.

Default: blind persistent TCP relay, sustained bidirectional delivery, idle
heartbeats, forced relay outage and automatic authenticated recovery.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.ext2 import Node,build_ext2,read_image_file
from agenticvm.live_bridge import Relay,Adapter
from agenticvm.peers import Runner,VM,verify_journal
from agenticvm.qemu import QemuBackend,prepare_pair_directory
from agenticvm.state import StateStore
from agenticvm.transport import SocketTransport


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=('relay','direct'),default='relay')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--smoke',action='store_true',help='Short diagnostic; does not replace the sustained run')
    modes.add_argument('--continuous',action='store_true',help='Keep both agents connected until Ctrl+C; use rolling, consumed-message retention')
    parser.add_argument('--fault-after-start',action='store_true',help=argparse.SUPPRESS)
    args = parser.parse_args()
    run_id = str(uuid4())
    folder = ROOT/'runtime/live-agent-runs'/run_id
    folder.mkdir(parents=True)
    runner = Runner(folder,run_id,256,1)
    runner.journal.add('run_started',purpose='sustained encrypted live VM communication',mode=args.mode)
    machines = (VM(runner,'live-a'),VM(runner,'live-b'))
    total,interval,idle = (40,.05,4) if args.smoke else (600,.1,5)
    if args.continuous:
        total,interval,idle = 0,.25,0
    expected_seconds = total*interval+idle+1
    source = {'live_agent.py':ROOT/'guest/live_agent.py','peer_agent.py':ROOT/'guest/peer_agent.py',
              'peer_protocol.py':ROOT/'src/agenticvm/peer_protocol.py','live_channel.py':ROOT/'src/agenticvm/live_channel.py'}
    report = {'passed':False,'run_id':run_id,'mode':args.mode,'smoke_only':args.smoke,
              'continuous_until_stopped':args.continuous,'physical_hosts_tested':1,'separate_physical_hosts_tested':False,'physical_4gb_host_tested':False,
              'memory_mib_per_vm':256,'guest_ethernet':False,'http_used':False,'usb_used':False,
              'shared_host_directory':False,'language_models_used':False,
              'source_sha256':{name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in source.items()},
              'checks':{},'limitations':['Two VMs share one trusted physical Windows hypervisor.',
                  'Remote physical hosts and Internet latency are untested.',
                  'This measures durable delivery acknowledgements, not zero latency or model thinking time.',
                  'Mailbox storage is bounded: 4096 retained records and 128 pending messages per endpoint. Continuous demo consumes valid data and explicitly retains 128 recent records per direction.',
                  'Production peer enrollment, certificate renewal, public relay access control and application side-effect policy are not implemented.']}
    checks = report['checks']
    service = service_thread = None
    adapters,identities,jobs = [],{},{}
    trace = bytearray()
    relay_bytes = [0,0]
    started = time.monotonic()

    def observe(room,direction,data):
        relay_bytes[direction] += len(data)
        if len(trace) < 1024*1024:
            trace.extend(data[:1024*1024-len(trace)])

    def relay_start(port=0):
        live = Relay(port,observe=observe)
        thread = threading.Thread(target=live.serve_forever,daemon=True)
        thread.start()
        return live,thread

    def connect_owned(vm):
        state = StateStore(vm.workspace).load()
        with QemuBackend(StateStore(vm.workspace),Path(state['executable']))._process(state) as process:
            if not process.alive():
                raise ConnectionError('Owned live VM exited')
            return SocketTransport(state['peer_socket'],3).socket

    try:
        if args.mode == 'direct':
            runner.pair_id = str(uuid4())
            prepare_pair_directory(runner.pair_id)
        for index,vm in enumerate(machines):
            disk = vm.workspace/'data/default.ext2'
            disk.parent.mkdir(parents=True)
            nodes = {'':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000),'peer':Node(stat.S_IFDIR|0o700,uid=1000,gid=1000)}
            nodes.update({'peer/'+name:Node(stat.S_IFREG|0o600,path,1000,1000) for name,path in source.items()})
            build_ext2(disk,nodes,label='AGENTICVM_DATA')
            options = ['--peer-channel'] if args.mode == 'relay' else ['--pair',runner.pair_id,'--peer-role','listen' if index == 0 else 'connect','--peer-link','serial']
            vm.start('--persistent',*options)
            state = StateStore(vm.workspace).load()
            if state['network'] != 'none':
                raise AssertionError('Unexpected guest network')
            topology = json.loads(vm.run('/usr/bin/python3','-I','-c',
                "import json,pathlib;print(json.dumps({'interfaces':sorted(p.name for p in pathlib.Path('/sys/class/net').iterdir()),'routes':pathlib.Path('/proc/net/route').read_text(),'dns':pathlib.Path('/etc/resolv.conf').read_text(),'mounts':pathlib.Path('/proc/mounts').read_text()}))"))
            if topology['interfaces'] != ['lo'] or topology['dns'].strip() or len(topology['routes'].splitlines()) != 1 or any(t in topology['mounts'] for t in (' 9p ',' virtiofs ',' cifs ',' nfs ')):
                raise AssertionError('Unexpected network or shared filesystem')
            identity = 'guest-a' if index == 0 else 'guest-b'
            public = json.loads(vm.run('/usr/bin/python3','-I','/workspace/peer/live_agent.py','--identity',identity,'--initialize'))
            identities[vm.name] = public
            vm.download('peer/live.pem',folder/(vm.name+'.pem'))
        checks['only_loopback_no_routes_dns_shared_mounts'] = True
        checks['independent_guest_generated_identities'] = identities['live-a']['sha256'] != identities['live-b']['sha256']
        for index,vm in enumerate(machines):
            other = machines[1-index]
            vm.upload(folder/(other.name+'.pem'),'peer/remote.pem')
            config = {'run_id':run_id,'peer_pin':identities[other.name]['sha256'],'messages':total,'interval':interval,
                      'idle_seconds':idle,'deadline_seconds':0 if args.continuous else expected_seconds+45}
            path = folder/(vm.name+'-config.json')
            path.write_text(json.dumps(config)+'\n')
            vm.upload(path,'peer/live-config.json')
        if args.mode == 'relay':
            service,service_thread = relay_start()
            port = service.server_address[1]
            for index,vm in enumerate(machines):
                adapter = Adapter(lambda vm=vm:connect_owned(vm),'127.0.0.1',port,run_id,'a' if index == 0 else 'b')
                adapter.start()
                adapters.append(adapter)
        for index,vm in enumerate(machines):
            job = vm.cli('exec','--async','--timeout-ms','0','--','/usr/bin/python3','-I','/workspace/peer/live_agent.py',
                '--identity','guest-a' if index == 0 else 'guest-b','--config','/workspace/peer/live-config.json')['job_id']
            jobs[vm.name] = job
            vm.jobs.append(job)
        runner.journal.add('live_agents_started',both_guests_running=True,app_message_delivery_uses_admin_rpc=False,
                           medium='dedicated direct virtio serial' if args.mode == 'direct' else 'virtio serial + blind persistent TCP byte relay',
                           messages_per_direction=total,interval_seconds=interval,idle_heartbeat_seconds=idle)
        print(json.dumps({'event':'live_contact_started','run_id':run_id,'mode':args.mode,
                          'continuous':args.continuous,'message':'Both Linux agents are running. Ctrl+C stops the owned VMs.'}),flush=True)
        if args.fault_after_start:
            runner.journal.add('fault_injected',exit_code=23,owned_vms=2,tasks_replayed=False)
            os._exit(23)
        running = time.monotonic()
        fault_at = 1.5 if args.smoke else 40
        interrupted = resumed = False
        exited = {}
        next_poll = running+1
        while args.continuous or time.monotonic()-running < expected_seconds+60:
            if (folder/'CANCEL').is_file():
                raise KeyboardInterrupt()
            elapsed = time.monotonic()-running
            if not args.continuous and args.mode == 'relay' and elapsed >= fault_at and not interrupted:
                service.stop()
                service_thread.join(3)
                service = service_thread = None
                interrupted, outage_start = True,time.monotonic()
                runner.journal.add('live_relay_interrupted',both_guest_processes_left_running=True)
            if interrupted and not resumed and time.monotonic()-outage_start >= 3:
                service,service_thread = relay_start(port)
                resumed = True
                runner.journal.add('live_relay_restarted',outage_seconds=round(time.monotonic()-outage_start,3),manual_agent_restart=False)
            if time.monotonic() >= next_poll:
                for vm in machines:
                    if vm.name not in exited:
                        snapshot = vm.cli('poll',jobs[vm.name],'--wait-ms','0')
                        if snapshot['state'] == 'exited':
                            exited[vm.name] = snapshot
                if len(exited) == 2:
                    break
                next_poll = time.monotonic()+2
            time.sleep(.1)
        if len(exited) != 2 or any(snapshot['exit_code'] != 0 for snapshot in exited.values()):
            raise AssertionError('Live guests did not complete: '+json.dumps(exited)[:1200])
        summaries,events = {},{}
        for vm in machines:
            target = folder/'evidence'/vm.name
            target.mkdir(parents=True)
            for name in ('live-summary.json','live-evidence.jsonl','live.sqlite'):
                vm.download('peer/'+name,target/name)
            summaries[vm.name] = json.loads((target/'live-summary.json').read_text())
            events[vm.name] = [json.loads(line) for line in (target/'live-evidence.jsonl').read_text().splitlines()]
        report['agents'] = summaries
        for summary in summaries.values():
            if not summary['passed'] or summary['state'] != {'sent':total,'received':total,'acked':total}:
                raise AssertionError('Endpoint did not pass all delivery checks')
            if not all(c['tls']['tls'] == 'TLSv1.3' and c['tls']['alpn'] == 'agenticvm-live/1' for c in summary['connections']):
                raise AssertionError('Live authentication or ALPN mismatch')
        checks['bidirectional_application_messages_delivered_and_durably_acked'] = True
        checks['mutual_tls13_exact_pins_and_live_alpn'] = all(
            all(connection['tls']['peer_cert_sha256'] == identities[other.name]['sha256'] for connection in summaries[vm.name]['connections'])
            for vm,other in ((machines[0],machines[1]),(machines[1],machines[0])))
        checks['unicode_payloads_and_counters_validated_by_recipients'] = all(s['payloads_verified'] for s in summaries.values())
        checks['idle_heartbeats_roundtrip'] = all(s['counters'].get('heartbeat_acknowledged',0) > 0 for s in summaries.values())
        for left,right in (('live-a','live-b'),('live-b','live-a')):
            sent = {e['message_id']:e['payload_sha256'] for e in events[left] if e['event']=='data_sent'}
            received = {e['message_id']:e['payload_sha256'] for e in events[right] if e['event']=='data_received'}
            if len(sent) != total or sent != received:
                raise AssertionError('Continuous message IDs and hashes do not reconcile')
        checks['message_ids_and_hashes_reconcile_both_directions'] = True
        if args.mode == 'relay':
            checks['recovered_after_forced_relay_outage_without_agent_restart'] = resumed and all(len(s['connections'])>=2 for s in summaries.values())
            checks['relay_observed_only_ciphertext'] = relay_bytes[0]>0 and relay_bytes[1]>0 and b'continuous-private-marker' not in trace and b'"queued_ns"' not in trace
            report['relay'] = {'bytes_by_direction':relay_bytes,'adapter_connections':[a.generations for a in adapters],
                               'adapter_errors':[getattr(a,'last_error',None) for a in adapters],
                               'tls_terminated_at_relay':False,'capture_bytes':len(trace)}
            (folder/'relay-prefix.tls').write_bytes(trace)
        report['messages_per_direction'],report['active_contact_seconds'] = total,round(time.monotonic()-running,3)
        report['passed'] = all(checks.values())
    except KeyboardInterrupt:
        report.update(passed=None,stopped_by_user=True,status='stopped; no pending application task is replayed')
    except Exception as error:
        report['error'] = {'class':type(error).__name__,'message':str(error)[:1800]}
    finally:
        cleanup_errors = []
        for adapter in adapters:
            try:
                adapter.stop()
            except Exception as error:
                cleanup_errors.append({'adapter':adapter.side,'class':type(error).__name__})
        if service:
            service.stop()
            service_thread.join(3)
        for vm in machines:
            try:
                state = StateStore(vm.workspace).load(required=False)
                if state and state['registered']:
                    for job in vm.jobs:
                        try:
                            vm.cli('cancel',job)
                        except Exception:
                            pass
                    vm.run('/usr/bin/python3','-I','-c',"import os,pathlib;p=pathlib.Path('/workspace/peer/live.key');p.unlink(missing_ok=True);os.sync();assert not p.exists()")
                    vm.stop()
                    try:
                        read_image_file(vm.workspace/'data/default.ext2','peer/live.key')
                        raise AssertionError('Disposable guest key remains')
                    except FileNotFoundError:
                        pass
            except Exception as error:
                cleanup_errors.append({'vm':vm.name,'class':type(error).__name__,'message':str(error)[:150]})
        cleanup_errors.extend(runner.cleanup())
        report['cleanup_failures'] = cleanup_errors
        if cleanup_errors:
            report['passed'] = False
        runner.journal.close()
        report['checkpoints'] = verify_journal(folder/'checkpoints.jsonl')
        report['seconds'] = round(time.monotonic()-started,3)
        report['evidence_directory'] = str(folder.relative_to(ROOT))
        (folder/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        if report['passed'] and not (ROOT/'live-runtime-lock.json').exists():
            suffix = '-smoke' if args.smoke else ''
            (ROOT/'docs/validation'/('live-'+args.mode+suffix+'-report.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'report':str(folder/'report.json'),'seconds':report['seconds'],'error':report.get('error')}))
    return 0 if report['passed'] or report.get('stopped_by_user') and not report['cleanup_failures'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
