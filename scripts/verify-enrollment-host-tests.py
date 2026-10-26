"""Run the complete host regression suite and save an inspectable receipt."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save


def integrity_level():
    if os.name != 'nt':
        return None
    try:
        output = subprocess.run(['whoami', '/groups'], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in output.splitlines():
        if 'Mandatory Label\\' in line:
            return line.split('Mandatory Label\\', 1)[1].strip().split(' ', 1)[0]
    return None


def symlink_check():
    try:
        with tempfile.TemporaryDirectory(prefix='dsh-host-symlink-') as directory:
            root = Path(directory)
            target = root / 'target.txt'
            target.write_text('x', encoding='ascii')
            os.symlink(target, root / 'link.txt')
        return True, None
    except (OSError, NotImplementedError) as error:
        return False, type(error).__name__ + ': ' + str(error)


def interpreter_identity():
    executable = Path(sys.executable).resolve()
    bundled = ROOT / 'tools/python-runtime/3.13.16/python.exe'
    executable_sha = digest(executable) if executable.is_file() else None
    bundled_sha = digest(bundled) if bundled.is_file() else None
    symlink_ok, symlink_error = symlink_check()
    value = {'executable': str(executable), 'version': sys.version.split()[0],
             'implementation': platform.python_implementation(), 'platform': platform.platform(),
             'executable_sha256': executable_sha, 'bundled_python_sha256': bundled_sha,
             'matches_bundled_python': executable_sha == bundled_sha if executable_sha and bundled_sha else None,
             'integrity_level': integrity_level(), 'symlink_capable': symlink_ok}
    if symlink_error:
        value['symlink_error'] = symlink_error
    return value


def main():
    folder = ROOT / 'runtime/enrollment-host-tests' / str(uuid4())
    folder.mkdir(parents=True)
    interpreter = interpreter_identity()
    pins = {path.relative_to(ROOT).as_posix(): digest(path) for base in ('src/agenticvm', 'guest', 'tests', 'scripts')
            for path in (ROOT / base).glob('*.py')}
    with (folder / 'tests.log').open('w') as log:
        tests = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(tests)
    changed = [name for name, pin in pins.items() if digest(ROOT / name) != pin]
    receipt = {'passed': result.wasSuccessful() and not result.skipped and not changed and interpreter['symlink_capable'],
        'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
        'skipped': len(result.skipped), 'source_sha256': pins, 'changed_during_tests': changed,
        'interpreter': interpreter, 'log_sha256': digest(folder / 'tests.log'), 'native_acceptance_claimed': False}
    if not interpreter['symlink_capable']:
        receipt['environment_error'] = 'Symbolic-link creation is unavailable: ' + str(interpreter.get('symlink_error'))
    save(folder / 'report.json', receipt)
    print(json.dumps({key: value for key, value in receipt.items() if key != 'source_sha256'}
        | {'report': str(folder / 'report.json')}, indent=2))
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
