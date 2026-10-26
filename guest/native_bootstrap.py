"""Root first-boot adapter: verified user-scoped installer plus systemd service.

This file arrives through the declared native cloud-init/Ignition input. The
actual agent/runtime/model arrive over pinned HTTPS after mother opens admission.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

HOME = Path('/var/lib/garden')
TRUST = Path('/etc/garden/trust.json')
ORIGIN = 'https://192.0.2.1:8443'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    trust = json.loads(TRUST.read_text())
    ctx = ssl.create_default_context(cadata=trust['mother_certificate'])
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    HOME.mkdir(parents=True, exist_ok=True)
    os.chown(HOME, 1000, 1000)
    HOME.chmod(0o700)
    before = {name: (HOME / name).exists() for name in ('peer/lan_agent.py', 'model.gguf', 'identity.key')}
    if any(before.values()):
        raise ValueError('Native first-boot target is not agent-free')
    with opener.open(ORIGIN + '/native/config', timeout=15) as response:
        config = json.loads(response.read(32769))
    if config['mother_certificate'] != trust['mother_certificate']:
        raise ValueError('Native first-boot trust changed')
    with opener.open(ORIGIN + '/native/installer', timeout=15) as response:
        raw = response.read(65537)
    if len(raw) > 65536 or sha(raw) != trust['installer_sha256']:
        raise ValueError('Native installer digest failed before execution')
    python = '/usr/bin/python3' if Path('/usr/bin/python3').exists() else str(HOME / 'runtime/python')
    # The root adapter starts the real service after the verified user installer
    # atomically writes its configuration. It never launches a transient agent.
    service = '''[Unit]
Description=Authorized native garden member
After=network-online.target
Wants=network-online.target
ConditionPathExists=/var/lib/garden/lan-config.json
[Service]
User=1000
Group=1000
Environment=MALLOC_ARENA_MAX=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 LLAMA_ARG_REPACK=0
Environment=HOME=/var/lib/garden
ExecStart=PYTHON -I -B /var/lib/garden/peer/lan_agent.py
Restart=on-failure
RestartSec=3
StandardOutput=append:/var/lib/garden/agent.log
StandardError=append:/var/lib/garden/agent.log
[Install]
WantedBy=multi-user.target
'''.replace('PYTHON', python)
    if Path('/sys/fs/selinux/enforce').exists():
        # The delivered interpreter/inference executables live in /var, whose
        # default data label cannot be executed by a systemd service on CoreOS.
        # Label only these two approved executable trees at each service start;
        # SELinux stays enforcing and the agent still runs as UID/GID 1000.
        trees = ('/var/lib/garden/runtime ' if python != '/usr/bin/python3' else '') + '/var/lib/garden/llama'
        service = service.replace('ExecStart=', 'ExecStartPre=+/usr/bin/chcon -R -t bin_t ' + trees + '\nExecStart=', 1)
    (Path('/etc/systemd/system') / 'garden-native.service').write_text(service)
    system_env = {key: value for key, value in os.environ.items() if key != 'LD_LIBRARY_PATH'}
    system_env['SYSTEMD_OFFLINE'] = '0'
    for args in (['daemon-reload'], ['enable', 'garden-native.service']):
        subprocess.run(['/usr/bin/systemctl', *args], check=True, capture_output=True, timeout=20, env=system_env)
    activation_errors = []
    activation_done = threading.Event()
    def activate():
        deadline = time.monotonic() + 350
        while time.monotonic() < deadline and not activation_done.wait(.1):
            path = HOME / 'lan-config.json'
            if path.exists():
                try:
                    if json.loads(path.read_text()) != config:
                        raise ValueError('Native service activation configuration changed')
                    child = subprocess.run(['/usr/bin/systemctl', 'start', 'garden-native.service'],
                        capture_output=True, text=True, timeout=30, env=system_env)
                    if child.returncode:
                        raise RuntimeError('Native service activation failed: ' + child.stderr[-1200:])
                except Exception as error:
                    activation_errors.append(type(error).__name__ + ': ' + str(error))
                return
    threading.Thread(target=activate, daemon=True).start()
    # The original reviewed installer is relocated into the persistent native
    # OS path. Its only process-launch hook waits for the actual systemd PID.
    installer = raw.decode().replace('/workspace', '/var/lib/garden')
    if python != '/usr/bin/python3':
        installer = installer.replace('/usr/bin/openssl', str(HOME / 'runtime/bin/openssl'))
        # A native CoreOS OpenSSL binary can require symbols newer than the
        # explicitly delivered Debian libraries used by portable Python.
        os.environ['OPENSSL_CONF'] = '/dev/null'
    program = '''import json,sys,time,types,subprocess
cfg=json.load(sys.stdin)
scope={'__name__':'verified_native_installer'}
exec(compile(SOURCE,'<verified-native-installer>','exec'),scope)
def service_process(argv,**kwargs):
    if argv!=['/usr/bin/python3','-I','/var/lib/garden/peer/lan_agent.py']:
        raise ValueError('Unapproved native process launch')
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        result=subprocess.run(['/usr/bin/systemctl','show','--property=MainPID','--value','garden-native.service'],capture_output=True,text=True,timeout=5,
                              env={k:v for k,v in __import__('os').environ.items() if k!='LD_LIBRARY_PATH'})
        if result.returncode==0 and result.stdout.strip().isdigit() and int(result.stdout)>0:
            pid=int(result.stdout)
            state=scope['process_identity'](pid)
            if state and '/var/lib/garden/peer/lan_agent.py' in state['argv']:
                return types.SimpleNamespace(pid=pid)
        time.sleep(.1)
    raise TimeoutError('Native systemd service did not start: '+str(result.returncode)+': '+result.stdout[-200:]+result.stderr[-400:])
proxy=types.SimpleNamespace(**vars(subprocess));proxy.Popen=service_process
scope['subprocess']=proxy
first=scope['install'](cfg);again=scope['install'](cfg)
if not first['ok'] or first['duplicate'] or not again.get('duplicate') or again['process']!=first['process']:
    raise ValueError('Native duplicate installation changed service identity')
print(json.dumps({'installed':first,'duplicate':again}),flush=True)
'''.replace('SOURCE', repr(installer))
    try:
        child = subprocess.run([python, '-I', '-B', '-c', program], input=json.dumps(config), text=True,
                               capture_output=True, timeout=360, user=1000, group=1000, extra_groups=[],
                               env={**os.environ, 'MALLOC_ARENA_MAX': '1', 'HOME': str(HOME), 'LLAMA_ARG_REPACK': '0'})
    finally:
        activation_done.set()
    if activation_errors:
        raise RuntimeError('; '.join(activation_errors))
    if child.returncode:
        raise RuntimeError('Native user installer failed: ' + child.stderr[-1400:] + child.stdout[-800:])
    installed = json.loads(child.stdout)
    receipt = {'ok': True, **installed, 'initial_absence': before, 'native_os': Path('/etc/os-release').read_text(),
               'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'root_bootstrap_uid': os.getuid(),
               'agent_service_user': 1000, 'native_python': python, 'ssh_used': False,
               'systemd_enabled': subprocess.run(['/usr/bin/systemctl', 'is-enabled', 'garden-native.service'],
                                                capture_output=True, text=True, timeout=10, env=system_env).stdout.strip()}
    request = urllib.request.Request(ORIGIN + '/native/receipt', data=json.dumps({
        'request_id': config['request_id'], 'identity': 'sprout-4', 'grant': config['grant'], 'receipt': receipt}).encode(),
        headers={'Content-Type': 'application/json'})
    with opener.open(request, timeout=15) as response:
        if json.loads(response.read(4097)) != {'ok': True}:
            raise ValueError('Native installation receipt was not accepted')
    (HOME / 'native-install-complete.json').write_text(json.dumps(receipt) + '\n')
    with open('/dev/ttyS0', 'w') as console:
        print('NATIVE_INSTALL_COMPLETE ' + json.dumps({'boot_id': receipt['boot_id'], 'systemd_enabled': receipt['systemd_enabled']}), file=console, flush=True)
    os.sync()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        with open('/dev/ttyS0', 'w') as console:
            # Read-only native OS evidence for deliberate failure cases. A
            # failed HTTP request alone cannot prove activation was prevented.
            state = {'native_os': Path('/etc/os-release').read_text(),
                     'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                     'uid': os.getuid(), 'error': type(error).__name__ + ': ' + str(error),
                     'activation_paths': {name: (HOME / name).exists() for name in
                        ('peer/lan_agent.py', 'model.gguf', 'identity.key', 'lan-config.json')},
                     'agent_service_active': subprocess.run(
                         ['/usr/bin/systemctl', 'is-active', 'garden-native.service'],
                         capture_output=True, timeout=10).returncode == 0}
            print('\nNATIVE_DENIAL_PROOF ' + json.dumps(state), file=console, flush=True)
            print('NATIVE_INSTALL_FAILED ' + type(error).__name__ + ': ' + str(error), file=console, flush=True)
            for args in (['/usr/bin/systemctl', 'status', '--no-pager', 'garden-native.service'],
                         ['/usr/bin/journalctl', '--no-pager', '-n', '12', '-u', 'garden-native.service']):
                try:
                    diagnostic = subprocess.run(args, capture_output=True, text=True, timeout=10,
                        env={key: value for key, value in os.environ.items() if key != 'LD_LIBRARY_PATH'})
                    print(diagnostic.stdout[-6000:] + diagnostic.stderr[-2000:], file=console, flush=True)
                except Exception:
                    pass
            log = HOME / 'agent.log'
            if log.exists():
                print(log.read_text(errors='replace')[-6000:], file=console, flush=True)
        raise
