"""Verify an idle DeepSeek SDK session's directory without making a model call.

Uses the installed official dsh launcher and its documented JSON-RPC protocol.
Does not read credentials, change global settings, or prompt a language model.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    shim = shutil.which('dsh.cmd')
    node = shutil.which('node.exe')
    if not shim or not node:
        raise RuntimeError('Install the official @deepseek-ai/dsh and Node.js first')
    package = Path(shim).parent / 'node_modules/@deepseek-ai/dsh'
    manifest = json.loads((package / 'package.json').read_text())
    if manifest['name'] != '@deepseek-ai/dsh':
        raise ValueError('The launcher does not resolve to the official package name')
    launcher = package / 'lib/bin.js'
    result = {'workspace': str(ROOT), 'harness': manifest['name'], 'version': manifest['version'],
        'launcher': str(launcher), 'model_calls_made': 0, 'credentials_read_or_changed': False,
        'global_configuration_changed': False, 'passed': False}
    if args.check_only:
        print(json.dumps(result | {'installed': launcher.is_file()}, indent=2))
        return 0
    folder = ROOT / 'runtime/deepseek-handover' / str(uuid4())
    folder.mkdir(parents=True)
    messages = queue.Queue()
    session_id = str(uuid4())
    with (folder / 'sdk-stderr.log').open('wb') as stderr:
        child = subprocess.Popen([node, str(launcher), '--profile', 'sdk'], cwd=ROOT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True,
            encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        def read():
            for line in child.stdout:
                try:
                    messages.put(json.loads(line))
                except json.JSONDecodeError:
                    messages.put({'non_protocol_output': True})
            messages.put({'eof': True})
        threading.Thread(target=read, daemon=True).start()
        counter = 0
        def rpc(method, params=None):
            nonlocal counter
            counter += 1
            request = {'jsonrpc': '2.0', 'id': counter, 'method': method}
            if params is not None:
                request['params'] = params
            child.stdin.write(json.dumps(request) + '\n')
            child.stdin.flush()
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                reply = messages.get(timeout=max(.01, deadline-time.monotonic()))
                if reply.get('eof') or reply.get('non_protocol_output'):
                    raise RuntimeError('SDK ended or emitted invalid protocol output')
                if reply.get('id') == counter:
                    if 'error' in reply:
                        error = reply['error']
                        raise RuntimeError('SDK request rejected: ' + method + ' / ' + str(error.get('message')))
                    return reply['result']
            raise TimeoutError('SDK did not acknowledge ' + method)
        try:
            initialized = rpc('initialize', {'cwd': str(ROOT), 'provider': 'deepseek-official', 'model': 'deepseek-flash'})
            if initialized['serverInfo']['name'] != 'deepseek-harness-sdk-runtime':
                raise ValueError('Unexpected SDK server identity')
            changed = rpc('session/working-directory/set', {'sessionId': session_id, 'path': str(ROOT)})
            observed = rpc('session/working-directory/get', {'sessionId': session_id})
            if Path(observed['cwd']).resolve() != ROOT.resolve() or changed != observed:
                raise ValueError('DeepSeek session directory does not match this workspace')
            result.update(passed=True, session_id=session_id, server=initialized['serverInfo'],
                working_directory_observed=observed['cwd'], session_created_without_model_turn=True,
                model_has_read_handover=False, browser_workspace_registration_verified=False)
            rpc('shutdown')
            child.wait(20)
            if child.returncode:
                raise RuntimeError('SDK shutdown did not complete successfully')
        except Exception as error:
            result.update(passed=False, error=type(error).__name__ + ': ' + str(error))
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(15)
    output = folder / 'connection.json'
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result | {'report': str(output)}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
