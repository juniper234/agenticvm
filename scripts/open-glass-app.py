"""Open the glass desktop in its own development workspace; never auto-boot."""
from pathlib import Path
import json
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    app = ROOT / 'dist/AgenticVM-Glass/AgenticVM.dll'
    dotnet = ROOT / 'tools/dotnet/runtime/dotnet.exe'
    if not dotnet.is_file():
        dotnet = ROOT / 'tools/dotnet/sdk/dotnet.exe'
    if not app.is_file() or not dotnet.is_file():
        raise RuntimeError('Build the desktop shell with scripts/build-glass-desktop.py first.')
    data = ROOT / 'runtime/glass-app'
    data.mkdir(parents=True, exist_ok=True)
    # QMP uses Windows AF_UNIX, whose encoded socket path is limited to 108 bytes.
    # Keep its private temp parent short even when the checkout path is long.
    temporary = ROOT / 'runtime/tmp'
    temporary.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(AGENTICVM_HOME=str(ROOT), AGENTICVM_APP_DATA=str(data),
        AGENTICVM_PYTHON=sys.executable, DOTNET_ROOT=str(dotnet.parent),
        DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_GENERATE_ASPNET_CERTIFICATE='false',
        TEMP=str(temporary), TMP=str(temporary), AGENTICVM_SOCKET_ROOT=str(ROOT / 'runtime/ipc'))
    Path(environment['TEMP']).mkdir(parents=True, exist_ok=True)
    with (data / 'launch.log').open('ab') as log:
        child = subprocess.Popen([str(dotnet), str(app)], cwd=ROOT, env=environment,
            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
    receipt = {'pid':child.pid, 'created_unix':time.time(), 'executable':str(dotnet),
        'assembly':str(app), 'data':str(data), 'ipc_root':str(ROOT / 'runtime/ipc'), 'vm_auto_start':False}
    (data / 'launch.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps(receipt))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        out = ROOT / 'runtime/glass-app'
        out.mkdir(parents=True, exist_ok=True)
        (out / 'launcher-error.txt').write_text(str(error), encoding='utf-8')
        raise
