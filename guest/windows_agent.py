"""Windows task entry point; shared TLS/message ledger, native OS observations."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lan_agent

BASE = Path(os.environ.get('ProgramData', 'C:/ProgramData')) / 'Garden'
lan_agent.BASE = BASE


def powershell(script):
    child = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
        capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
    if child.returncode:
        raise RuntimeError('Native Windows observation failed: ' + child.stderr[-1000:])
    return json.loads(child.stdout)


class WindowsNode(lan_agent.Node):
    def snapshot(self):
        native = powershell("$os = Get-CimInstance Win32_OperatingSystem; "
            "$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
            "$n = @(Get-NetAdapter | Where-Object {$_.MacAddress -eq '52-54-00-4C-41-04'}); "
            "$routes = @(Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,NextHop,InterfaceIndex); "
            "@{sid=$sid; os=$os.Caption; build=$os.BuildNumber; boot=$os.LastBootUpTime.ToUniversalTime().Ticks.ToString(); "
            "adapters=@($n | Select-Object Name,InterfaceIndex,MacAddress,Status); routes=$routes; "
            "default_route=@($routes | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'}); "
            "uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID.ToLower()} | ConvertTo-Json -Depth 5 -Compress")
        if (native['sid'] != 'S-1-5-19' or native['default_route'] or len(native['adapters']) != 1
                or native['uuid'] != self.config['target_uuid']):
            raise ValueError('Windows agent privileges or isolated native networking differ from the prepared policy')
        with self.lock:
            calls = [dict(row) for row in self.db.execute('SELECT * FROM calls ORDER BY id')]
            for row in calls:
                if row['proof']:
                    row['proof'] = json.loads(row['proof'])
            return {'identity': self.identity, 'role': 'worker', 'ready': self.ready, 'error': self.error,
                'model': self.model.snapshot(), 'calls': calls,
                'received': [json.loads(row['payload']) for row in self.db.execute('SELECT payload FROM inbox')],
                'delivered': [{'hello': json.loads(row['hello']), 'reply': json.loads(row['reply'])}
                              for row in self.db.execute('SELECT * FROM delivered')],
                'heartbeat_received': dict(self.heartbeats), 'heartbeat_acknowledged': dict(self.sent_heartbeats),
                'public_identity': self.public, 'pid': os.getpid(), 'native_windows': native,
                'native_boot_id': native['boot']}


def main():
    if os.name != 'nt':
        raise RuntimeError('Windows target task entry requires the Windows guest')
    node = None
    try:
        log = (BASE / 'peer/agent.log').open('a', buffering=1)
        sys.stdout = sys.stderr = log
        config = json.loads((BASE / 'lan-config.json').read_text())
        identity = powershell("$p=Get-CimInstance Win32_Process -Filter \"ProcessId=" + str(os.getpid()) + "\"; "
            "@{sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
            "uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID.ToLower(); "
            "created=$p.CreationDate.ToUniversalTime().Ticks.ToString()} | ConvertTo-Json -Compress")
        if identity.get('sid') != 'S-1-5-19' or identity.get('uuid') != config['target_uuid']:
            raise ValueError('Windows task account or owned target UUID mismatch before model startup')
        node = WindowsNode(config)
        lan_agent.save(BASE / 'agent-process.json', {'pid': os.getpid(),
            'created': identity['created'], 'started_at': time.time()})
        node.run()
    except Exception as error:
        if node:
            node.error = type(error).__name__ + ': ' + str(error)
        lan_agent.save(BASE / 'windows-agent-error.json', {'error': type(error).__name__ + ': ' + str(error)})
        raise


if __name__ == '__main__':
    main()
