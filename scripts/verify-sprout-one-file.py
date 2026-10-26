"""Acceptance: launch exactly one EXE; observe only, with no setup/repair calls.

Leaves the successful three-VM garden alive. Every installation/VM start/
enrollment/message operation must be performed by that one file's process tree.
"""
import hashlib
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.garden import inspect_status
from agenticvm.peers import verify_journal
from agenticvm.qemu import QemuBackend
from agenticvm.state import StateStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lfm',action='store_true')
    args = parser.parse_args()
    build = json.loads((ROOT/('dist/Garden-Sprout-LFM-v1/build-report.json' if args.lfm else 'dist/Garden-Sprout-v1/build-report.json')).read_text())
    exe,installed = ROOT/build['exe'],Path(build['installed_root'])
    with exe.open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest() != build['sha256']:
            raise ValueError('Single-file artifact changed')
    if installed.exists():
        raise ValueError('Acceptance requires a fresh installation destination')
    directory = ROOT/'runtime'/(('one-file-lfm-sprout-' if args.lfm else 'one-file-sprout-')+uuid4().hex[:12])
    directory.mkdir()
    report = {'passed':False,'launch_count':0,'manual_install_commands':0,'manual_connection_commands':0,
              'post_launch_mutations':0,'fresh_install':True,'executable':str(exe),'exe_sha256':build['sha256'],
              'cwd':str(Path(os.environ['SystemRoot'])/'Temp'),'system_python_required':False,
              'guest_memory_mib':512 if args.lfm else 256,'physical_hosts_tested':1,'physical_4gb_host_tested':False,'model_inference':args.lfm}
    start = time.monotonic()
    env = dict(os.environ,PATH=os.pathsep.join((str(Path(os.environ['SystemRoot'])/'System32'),os.environ['SystemRoot'])),
               AGENTICVM_QEMU=str(Path(os.environ['SystemRoot'])/'System32/whoami.exe'))
    try:
        with (directory/'stdout.txt').open('wb') as stdout,(directory/'stderr.txt').open('wb') as stderr:
            # This is the only launched file/command in the acceptance test.
            process = subprocess.Popen([str(exe)],cwd=report['cwd'],env=env,stdin=subprocess.DEVNULL,
                stdout=stdout,stderr=stderr,creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)
            report.update(launch_count=1,launcher_pid=process.pid)
            while time.monotonic()-start<(600 if args.lfm else 240):
                if process.poll() is not None:
                    raise RuntimeError('Single-file launcher exited '+str(process.returncode))
                latest = installed/'runtime/gardens/last-join.json'
                if latest.exists():
                    pointer = json.loads(latest.read_text())
                    if not pointer['passed']:
                        raise RuntimeError('Garden reported failed enrollment')
                    break
                time.sleep(.5)
            else:
                raise TimeoutError('One-file garden did not become ready within four minutes')
            folder = installed/'runtime/gardens'/pointer['garden']
            join = json.loads((folder/'join-report.json').read_text())
            first_health = None
            until = time.monotonic()+180
            observed_since = None
            def heartbeat_activity(edge):
                return sum(edge.get('events',{}).get(k,0) for k in ('heartbeat_acknowledged','heartbeat_received'))
            while time.monotonic()<until:
                health_path = folder/'health.json'
                if health_path.exists():
                    health = json.loads(health_path.read_text())
                    if first_health is None:
                        first_health = health
                        observed_since = time.monotonic()
                    elif args.lfm and time.monotonic()-observed_since>=60 and all(
                            heartbeat_activity(health[str(i)]['links'][str(j)])-
                            heartbeat_activity(first_health[str(i)]['links'][str(j)])>=5
                            for i in (1,2,3) for j in (1,2,3) if i!=j):
                        break
                    elif not args.lfm and min(health[str(i)]['links'][str(j)]['state']['acked']-
                             first_health[str(i)]['links'][str(j)]['state']['acked']
                             for i in (1,2,3) for j in (1,2,3) if i!=j)>=135:
                        break
                if process.poll() is not None or (folder/'failure.json').exists():
                    raise RuntimeError('Garden stopped during sustained observation')
                time.sleep(.5)
            else:
                raise TimeoutError('Sustained contact did not advance on all six directions')
            identities = {int(k):v for k,v in join['identities'].items()}
            live = []
            for member in (1,2,3):
                store = StateStore(folder/('sprout-'+str(member)))
                state = store.load()
                with QemuBackend(store,Path(state['executable']))._process(state) as owned:
                    if not owned.alive():
                        raise AssertionError('The owned QEMU process exited')
                if Path(state['executable']).resolve() != (installed/'tools/qemu/11.1.0/qemu-system-x86_64.exe').resolve():
                    raise AssertionError('Used an external QEMU executable')
                live.append({'member':member,'pid':state['pid'],'uuid':state['uuid'],'memory_mib':state['memory_mib'],
                             'network':state['network'],'exact_owned_process_alive':True})
            installation = json.loads((installed/'installation.json').read_text(encoding='utf-8-sig'))
            checks = {'single_file_opened_once':report['launch_count']==1,
                      'fresh_runtime_installed_and_sha256_verified':installation['payload_sha256']==build['payload_sha256'],
                      'no_admin_or_windows_feature_changes':not installation['administrator_required'] and not installation['system_features_changed'],
                      'two_seeds_verified_before_third_started':join['before']['1']['links']['2']['state']['acked']>=(2 if args.lfm else 5),
                      'third_joined_both_existing_members':join['passed'] and all(join['checks'].values()),
                      'six_directions_kept_communicating_after_join':inspect_status(health,identities,(1,2,3),require_model=args.lfm),
                      'all_three_owned_vms_still_alive':len(live)==3,
                      'no_manual_install_connect_or_repair':True,
                      'installer_still_running':process.poll() is None}
            if args.lfm:
                from agenticvm.garden_model import verify_conversation
                checks.update(verify_conversation(health))
                checks['idle_encrypted_heartbeats_continued_for_60_seconds'] = time.monotonic()-observed_since>=60 and all(
                    heartbeat_activity(health[str(i)]['links'][str(j)])-heartbeat_activity(first_health[str(i)]['links'][str(j)])>=5
                    for i in (1,2,3) for j in (1,2,3) if i!=j)
            else:
                checks['all_six_directions_advanced_135_durable_acks'] = all(
                    health[str(i)]['links'][str(j)]['state']['acked']-first_health[str(i)]['links'][str(j)]['state']['acked']>=135
                    for i in (1,2,3) for j in (1,2,3) if i!=j)
            report.update(passed=all(checks.values()),checks=checks,garden=pointer['garden'],installed_root=str(installed),
                          join_report=str(folder/'join-report.json'),installation=installation,vms=live,
                          first_observed_health=first_health,last_observed_health=health,
                          journal=verify_journal(folder/'checkpoints.jsonl'),left_running=True,
                          stop_instruction='Close with Ctrl+C, or create '+str(folder/'STOP'))
    except Exception as error:
        report['error'] = {'class':type(error).__name__,'message':str(error)}
        report['failure_logs'] = str(directory)
        # No recovery command or installation workaround is allowed here: a
        # failed acceptance is preserved as failed, never repaired into a pass.
    report['seconds'] = round(time.monotonic()-start,3)
    (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    if report['passed']:
        (ROOT/'docs/validation'/('garden-lfm-one-file-report.json' if args.lfm else 'garden-one-file-report.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'report':str(directory/'report.json'),
                      'garden':report.get('garden'),'seconds':report['seconds'],'error':report.get('error')}),flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
