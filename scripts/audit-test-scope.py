"""Run host tests and record their scope separately from live VM evidence."""
import ast
from collections import Counter
import hashlib
import inspect
import json
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    suite = unittest.defaultTestLoader.discover(str(ROOT/'tests'))
    cases = list(flatten(suite))
    files = []
    for filename in sorted({inspect.getfile(case.__class__) for case in cases}):
        path = Path(filename)
        content = path.read_bytes()
        tree = ast.parse(content.decode('utf-8-sig'))
        selected = [case for case in cases if Path(inspect.getfile(case.__class__)) == path]
        files.append({'path': path.relative_to(ROOT).as_posix(), 'sha256': hashlib.sha256(content).hexdigest(),
                      'description': ast.get_docstring(tree), 'count': len(selected),
                      'scope': 'host unit/component tests; no VM launched',
                      'includes_test_doubles': b'unittest.mock' in content,
                      'tests': [case.id() for case in selected]})
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=1).run(unittest.TestSuite(cases))
    live = [
        ('live-relay-report.json', 'simultaneous live VMs with blind persistent byte relay', 'No guest NIC; TLS terminates inside the guests. Shared trusted physical hypervisor; remote physical hosts are untested.'),
        ('live-direct-report.json', 'simultaneous live VMs with direct virtual serial', 'Sustained two-way TLS over a live virtual connection on one host; no physical air-gap claim.'),
        ('live-native-portable-report.json', 'native portable launcher and live Linux VMs', 'Restricted PATH/foreign CWD test on one physical host; no cross-host or physical 4 GB result.'),
        ('live-recovery-report.json', 'actual live controller fault and owned VM recovery', 'Disposable local pair only. No application task replay or separate physical-host validation.'),
        ('agent-multilink-report.json', 'live same-host VMs', 'Live virtual serial or virtual Ethernet connects the guests; no direct physical-host independence.'),
        ('agent-multilink-portable-report.json', 'live same-host VMs', 'Portable rerun of the same three connected virtual transports.'),
        ('pong-agent-loop-report.json', 'live same-host model VMs', 'Two guests communicate over a live dedicated virtual serial connection.'),
        ('torrent-agent-chain-report.json', 'live same-host model VMs plus loopback torrent', 'Host TCP loopback distributes the package; guests use a live virtual serial connection.'),
        ('self-replication-report.json', 'live same-host model VMs with trusted host broker', 'Host broker terminates TLS and can read messages; agents share a live broker.'),
        ('agent-recovery-report.json', 'live same-host fault/recovery', 'Controller interruption and owned resource cleanup; no disconnected physical-host proof.'),
        ('pong-recovery-report.json', 'live same-host fault/recovery', 'Controller interruption and guest key cleanup; no physical-host independence.'),
        ('replication-recovery-report.json', 'live same-host fault/recovery', 'Two live guests remain at controller crash; recovery does not replay pending births.'),
        ('disconnected-transfer-report.json', 'sequential offline-VM simulation on one physical host', 'No NIC or peer device, only one test VM on at a time; explicit ciphertext file carrier via host control. Shared hypervisor remains trusted.'),
    ]
    evidence = []
    for name, scope, limit in live:
        path = ROOT/'docs/validation'/name
        if path.is_file():
            evidence.append({'path': path.relative_to(ROOT).as_posix(), 'scope': scope, 'limitation': limit,
                             'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                             'separate_physical_hosts_tested': False})
    report = {'schema': 'agenticvm.test-scope-audit.v1', 'passed': result.wasSuccessful(),
        'host_tests': {'count': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
                       'skipped': len(result.skipped), 'seconds': round(time.monotonic()-started, 3),
                       'files': files},
        'live_vm_evidence': evidence, 'physical_hosts_available_in_this_validation': 1,
        'separate_physical_hosts_tested': False, 'physical_4gb_host_tested': False,
        'claim': 'Host test totals are not counts of physical systems or end-to-end isolation experiments.',
        'no_carrier_means_no_new_delivery': True,
        'all_validation_json_files': [p.name for p in sorted((ROOT/'docs/validation').glob('*.json'))],
        'limits': ['Single-host simulation cannot establish physical air-gap properties, independent host trust, USB safety, or cross-OS hardware behavior.',
                   'Unit/component tests include real local sockets, TLS, HTTP, cryptography and SQLite, plus mocked VM/controller operations.',
                   'A filesystem mailbox is plaintext at rest on its endpoint; encryption protects the carrier, not a compromised endpoint or hypervisor.',
                   'Historical validation reports remain snapshots; their earlier test counts do not describe the current suite.']}
    target = ROOT/'docs/validation/test-scope-audit.json'
    target.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'passed': report['passed'], 'tests': result.testsRun, 'report': str(target)}))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
