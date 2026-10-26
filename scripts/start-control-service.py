"""Start the local VM service in the background, without desktop automation."""
from pathlib import Path
import json
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from agenticvm.control_client import ControlClient

client = ControlClient()
try:
    client.request('/api/info')
    print(json.dumps({'ok':True,'result':{'reused':True}}))
    raise SystemExit(0)
except (OSError, ValueError, KeyError):
    pass
data = ROOT/'runtime/glass-app'
data.mkdir(mode=0o700,parents=True,exist_ok=True)
environment = {**os.environ,'AGENTICVM_SOCKET_ROOT':str(ROOT/'runtime/ipc')}
with (data/'service.log').open('ab') as log:
    child = subprocess.Popen([sys.executable,'-I','-B','-m','agenticvm.control_cli','serve'], cwd=ROOT, env=environment,
        stdin=subprocess.DEVNULL, stdout=log, stderr=log,
        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
for _ in range(50):
    try:
        info = client.request('/api/info')
        ready = json.loads(client.ready_file.read_text(encoding='utf-8'))
        if ready['pid'] == child.pid:
            print(json.dumps({'ok':True,'result':{'pid':child.pid,'reused':False,'gui_opened':False}}))
            break
    except (OSError, ValueError, KeyError):
        pass
    if child.poll() is not None:
        raise RuntimeError('The VM service exited. Inspect runtime/glass-app/service.log.')
    time.sleep(.1)
else:
    raise RuntimeError('The VM service did not become ready.')
