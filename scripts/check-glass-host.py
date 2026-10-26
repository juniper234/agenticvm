"""Scoped host regression: mocked VM operations, real HTTP/stdio subprocesses."""
from pathlib import Path
import hashlib
import json
import sys
import time
import unittest
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'src'),str(ROOT/'tests')]


def pins():
    files = list((ROOT/'src/agenticvm').glob('*.py'))
    files += list((ROOT/'src/agenticvm/web').glob('*.*'))
    files += list((ROOT/'tests').glob('test_*.py'))
    files += [ROOT/'scripts/windows-desktop-supervisor.py',ROOT/'guest/windows_desktop_agent.py',ROOT/'guest/control_job.py']
    files += list((ROOT/'guest/android-jobs').rglob('*.java'))
    return {str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def main():
    folder = ROOT/'runtime/glass-host-tests'/str(uuid4())
    folder.mkdir(parents=True)
    before = pins()
    names = ['test_viewer','test_android_integration','test_android','test_desktop',
        'test_qemu_local_ipc','test_ipc_state','test_resources','test_windows_desktop','test_control_client',
        'test_control_diagnostics','test_control_advanced','test_beta_settings']
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    with (folder/'tests.log').open('w',encoding='utf-8') as stream:
        result = unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    report = {'schema':'agenticvm.glass-host-regression.v1','at':time.time(),
        'native_guest_test':False,'modules':names,'tests':result.testsRun,'failures':len(result.failures),
        'errors':len(result.errors),'skipped':len(result.skipped),'source_pins':before,
        'source_unchanged':before==pins()}
    report['ok'] = result.wasSuccessful() and report['source_unchanged'] and not result.skipped
    (folder/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({key:value for key,value in report.items() if key!='source_pins'}))
    print(str(folder/'report.json'))
    return 0 if report['ok'] else 1


if __name__=='__main__':
    raise SystemExit(main())
