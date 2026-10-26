"""Real Subiquity autoinstall into a blank owned disk with offline media."""
from __future__ import annotations
import base64
import hashlib
import json
import sys

from .debian_installer_lab import InstalledVM, DebianInstallerAdapter
from .installer_profiles import profile
from .lan_lab import ROOT, save, digest


class UbuntuInstalledVM(InstalledVM):
    manifest_relative = 'runtime/enrollment-images/ubuntu-installer/manifest.json'
    disk_capacity = '16G'
    def kernel_parameters(self):
        return ('boot=casper autoinstall console=ttyS0,115200n8 '
                'ds=nocloud-net;s=http://192.0.2.1:8080/installer/' + self.folder.parent.name + '/ ---')


class UbuntuInstallerAdapter(DebianInstallerAdapter):
    route, kind = 'ubuntu-autoinstall', 'ubuntu'
    memory = 3072
    install_marker = 'UBUNTU_INSTALL_PREPARED'
    source_paths = ['src/agenticvm/ubuntu_installer_lab.py', 'src/agenticvm/debian_installer_lab.py',
                    'src/agenticvm/installer_profiles.py', 'tools/enrollment-validators/autoinstall-schema.json']
    limitations = ['Actual Subiquity installer on one blank 16 GiB virtual disk; 3072 MiB installer RAM, then 1024 MiB for the installed target',
                   'Publisher-pinned local live-server media with offline-install fallback; no external guest network',
                   'Installer boot is separate from the two enrolled-OS boots; no physical hardware acceptance']
    def prepare_inputs(self, folder, public, runtime, payloads, metadata):
        built = profile(self.route, folder.name, public, runtime)
        install = json.loads(built['profile'].decode().split('\n', 1)[1])['autoinstall']
        # The full server image already supplies Python/OpenSSL. Do not ask apt
        # to fetch optional packages from an unreachable external mirror.
        install.pop('packages')
        install['source'] = {'id': 'ubuntu-server'}
        install['apt'] = {'fallback': 'offline-install', 'geoip': False, 'mirror-selection': {'primary': []}}
        install['network'] = {'version': 2, 'ethernets': {'garden': {'match': {'macaddress': '52:54:00:4c:41:04'},
                                                                  'dhcp4': True, 'dhcp6': False}}}
        prefix = '/installer/' + folder.name + '/'
        url = 'http://192.0.2.1:8080' + prefix + 'firstboot.sh'
        fetch = ("import hashlib,pathlib,urllib.request; data=urllib.request.urlopen(" + repr(url) + ",timeout=15).read(262145); "
                 "assert len(data)<=262144 and hashlib.sha256(data).hexdigest()==" + repr(built['firstboot_sha256']) + "; "
                 "pathlib.Path('/target/root/garden-firstboot.sh').write_bytes(data)")
        install['late-commands'] = [['python3', '-c', fetch],
            ['curtin', 'in-target', '--target=/target', '--', '/bin/sh', '/root/garden-firstboot.sh'],
            ['/bin/sh', '-c', 'echo ' + self.install_marker + ' ' + folder.name + ' > /dev/ttyS0']]
        userdata = ('#cloud-config\n' + json.dumps({'autoinstall': install})).encode()
        sys.path.insert(0, str(ROOT / 'tools/enrollment-validators'))
        import jsonschema
        schema = ROOT / 'tools/enrollment-validators/autoinstall-schema.json'
        provenance = json.loads(schema.with_suffix('.provenance.json').read_text())
        if digest(schema) != provenance['sha256']:
            raise ValueError('Pinned upstream autoinstall schema changed')
        jsonschema.validate(install, json.loads(schema.read_text()))
        meta = json.dumps({'instance-id': folder.name, 'local-hostname': 'garden-ubuntu-install'}).encode()
        (folder / 'autoinstall-user-data').write_bytes(userdata)
        (folder / 'installer-firstboot.sh').write_bytes(built['firstboot_script'])
        save(folder / 'autoinstall-input-pins.json', {'user_data_sha256': hashlib.sha256(userdata).hexdigest(),
              'firstboot_sha256': built['firstboot_sha256'], 'upstream_schema_validated': True,
              'upstream_schema_sha256': digest(schema)})
        return payloads, {**metadata, prefix + 'user-data': base64.b64encode(userdata).decode(),
            prefix + 'meta-data': base64.b64encode(meta).decode(),
            prefix + 'network-config': base64.b64encode(payloads['network-config']).decode(),
            prefix + 'firstboot.sh': base64.b64encode(built['firstboot_script']).decode()}
    def create_vm(self, *args, **kwargs):
        self.vm = UbuntuInstalledVM(*args, **kwargs)
        return self.vm
