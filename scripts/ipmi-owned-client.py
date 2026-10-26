"""One bounded authenticated IPMI operation, exclusively on IPv6 loopback."""
import json
from pathlib import Path
import sys
import time
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/enrollment-management'))
from pyghmi.ipmi.private.session import Session


class Suite3Session(Session):
    def _open_rmcpplus_request(self):
        self.attemptedhash = 1  # upstream BMC supports SHA1/AES suite 3
        return super()._open_rmcpplus_request()


def main():
    config = json.loads(sys.stdin.read(4097))
    if (set(config) != {'port', 'password', 'uuid', 'operation'} or config['operation'] not in ('boot-disk', 'on', 'softoff', 'status')
            or type(config['port']) is not int or not 1024 <= config['port'] <= 65535):
        raise ValueError('Unknown owned IPMI operation')
    client = Suite3Session(bmc='::1', userid='gardenlab', password=config['password'], port=config['port'], keepalive=False)
    guid = client.raw_command(netfn=6, command=0x37)
    if guid.get('code') or UUID(bytes_le=bytes(guid['data'])) != UUID(config['uuid']):
        raise ValueError('IPMI controller does not match the owned target UUID')
    operation = config['operation']
    if operation == 'boot-disk':
        result = client.raw_command(netfn=0, command=8, data=[5, 128, 8, 0, 0, 0])
    elif operation in ('on', 'softoff'):
        result = client.raw_command(netfn=0, command=2, data=[1 if operation == 'on' else 5])
    else:
        result = client.raw_command(netfn=0, command=1)
    if result.get('code') or 'error' in result:
        raise ValueError('Owned IPMI operation was refused')
    if operation in ('on', 'softoff'):
        desired = 1 if operation == 'on' else 0
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            state = client.raw_command(netfn=0, command=1)
            if not state.get('code') and state['data'][0] & 1 == desired:
                break
            time.sleep(.2)
        else:
            raise TimeoutError('Owned IPMI backend did not reach requested power state')
    print(json.dumps({'ok': True, 'operation': operation, 'target_uuid': config['uuid'],
                      'ipmi_version': client.ipmiversion, 'authentication_type': client.authtype,
                      'integrity': client.integrityalgo, 'privacy': client.confalgo}), flush=True)
    client.logout()


if __name__ == '__main__':
    main()
