"""Local upstream IPMI 2.0 wire probe; this probe has no VM backend."""
import json
from pathlib import Path
import secrets
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/enrollment-management'))
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.ipmi_protocol import LoopbackBMC
from pyghmi.ipmi.command import Command
from pyghmi.ipmi.private.session import Session


class Probe(LoopbackBMC):
    state = 'off'
    def get_system_guid(self):
        return self.uuid
    def get_power_state(self):
        return self.state
    def power_on(self):
        self.state = 'on'
    def power_shutdown(self):
        self.state = 'off'
    def get_boot_device(self):
        return 'hd'
    def set_boot_device(self, value):
        if value != 'hd':
            raise NotImplementedError()


class Suite3Session(Session):
    def _open_rmcpplus_request(self):
        self.attemptedhash = 1
        return super()._open_rmcpplus_request()


def main():
    if '--server' in sys.argv:
        config = json.loads(sys.stdin.readline())
        server = Probe({'gardenlab': config['password']}, bmcuuid=uuid4())
        print(json.dumps({'port': server.port}), flush=True)
        while True:
            Session.wait_for_rsp(.1)
    password = secrets.token_hex(10)
    child = subprocess.Popen([sys.executable, '-I', '-B', __file__, '--server'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    child.stdin.write(json.dumps({'password': password}) + '\n');child.stdin.flush()
    port = json.loads(child.stdout.readline())['port']
    print('Local upstream RMCP+ authentication probe on loopback', flush=True)
    try:
        client = Suite3Session(bmc='::1', userid='gardenlab', password=password, port=port, keepalive=False)
        before = client.raw_command(netfn=0, command=1)
        client.raw_command(netfn=0, command=8, data=[5, 128, 8, 0, 0, 0])
        client.raw_command(netfn=0, command=2, data=[1])
        after = client.raw_command(netfn=0, command=1)
        client.raw_command(netfn=0, command=2, data=[5])
        final = client.raw_command(netfn=0, command=1)
        print(json.dumps({'before': before, 'after': after, 'final': final,
                          'native_vm_tested': False, 'authtype': client.authtype,
                          'integrityalgo': client.integrityalgo, 'confalgo': client.confalgo},
                          default=lambda value: list(value) if isinstance(value, (bytes, bytearray)) else str(value)), flush=True)
    finally:
        child.terminate();child.wait(5)


if __name__ == '__main__':
    main()
