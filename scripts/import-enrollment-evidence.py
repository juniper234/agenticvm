"""Index existing pinned lab evidence without upgrading its original fidelity."""
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save


def main():
    folder = ROOT / 'docs/validation/enrollment-existing'
    folder.mkdir(exist_ok=True)
    delegated = json.loads((ROOT / 'docs/validation/delegated-validation-final.json').read_text())
    spec = importlib.util.spec_from_file_location('existing_delegated_suite', ROOT / 'scripts/verify-delegated-suite.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for case in delegated['cases']:
        source = ROOT / 'runtime/delegated-enrollment-runs' / case['run_id']
        if digest(source / 'report.json') != case['report_sha256']:
            raise ValueError('Existing delegated case changed')
        module.verify(source, case['case'])
    result = {'route': 'ssh-delegated-torrent', 'level': 'native-enrollment-tested', 'passed': True,
        'native_os_observed': True, 'native_platform': 'Linux kernel and Debian package appliance',
        'source_sha256': delegated['source_sha256'],
        'evidence': [{'path': 'docs/validation/delegated-validation-final.json',
                      'sha256': digest(ROOT / 'docs/validation/delegated-validation-final.json'),
                      'actual_model_completions': delegated['actual_model_completions'],
                      'native_scenarios': delegated['native_scenarios']}],
        'limitations': ['Existing current-source native cases were independently re-audited, not rerun by this indexer',
                        'Preauthorized SSH is required; target cold-reboot persistence was not tested',
                        'Native fault cases and exact-resource controller recovery passed; they do not establish cold-reboot acceptance']}
    destination = folder / 'ssh-delegated-torrent.json'
    save(destination, result)
    print(json.dumps({'passed': True, 'receipt': destination.relative_to(ROOT).as_posix()}))


if __name__ == '__main__':
    main()
