"""Native Anaconda/AutoYaST adapters; acceptance requires a real installer run."""
from __future__ import annotations
import base64
import json
import re
import sys
import warnings
import xml.etree.ElementTree as ET

from .debian_installer_lab import InstalledVM, DebianInstallerAdapter
from .installer_profiles import firstboot_script, profile
from .lan_lab import ROOT, digest, save
from .portable_userspace import adapt_native_config
from .autoyast_validation import validate as validate_autoyast


class FedoraInstalledVM(InstalledVM):
    manifest_relative = 'runtime/enrollment-images/fedora-installer/manifest.json'
    disk_capacity = '16G'
    def kernel_parameters(self):
        label = self.manifest['volume_id']
        if re.fullmatch(r'[A-Za-z0-9_.-]{1,32}', label) is None:
            raise ValueError('Unexpected pinned Fedora CD volume label')
        return ('inst.text inst.stage2=hd:LABEL=' + label + ' inst.ks=http://192.0.2.1:8080/installer/'
                + self.folder.parent.name + '/ks.cfg ip=dhcp console=ttyS0,115200n8')


class OpenSUSEInstalledVM(InstalledVM):
    manifest_relative = 'runtime/enrollment-images/opensuse-installer/manifest.json'
    disk_capacity = '16G'
    def kernel_parameters(self):
        return ('install=cd:/ textmode=1 netsetup=dhcp autoyast=http://192.0.2.1:8080/installer/'
                + self.folder.parent.name + '/autoinst.xml console=ttyS0,115200n8')


class RPMInstallerAdapter(DebianInstallerAdapter):
    memory = 2048
    seed_route = 'cloud-init-local'
    source_paths = ['src/agenticvm/rpm_installer_lab.py', 'src/agenticvm/debian_installer_lab.py',
                    'src/agenticvm/installer_profiles.py', 'src/agenticvm/portable_userspace.py',
                    'src/agenticvm/autoyast_validation.py']
    def __init__(self, route):
        if route not in ('anaconda-kickstart', 'autoyast'):
            raise ValueError('Known native RPM installer required')
        super().__init__()
        self.route = route
        self.kind = 'fedora' if route == 'anaconda-kickstart' else 'opensuse'
        self.install_marker = 'RPM_INSTALL_PREPARED'
        self.limitations = ['One blank owned 16 GiB virtual disk with publisher-pinned offline DVD; no host disk',
            'Native installation and the two installed-OS boots are counted separately',
            'The prepared adapter is not native acceptance until the real installer and model/reboot checks pass']
        if self.kind == 'opensuse':
            self.limitations += ['App-local delivered loader/libc/Python/OpenSSL support the older OS; system libraries are unchanged',
                                 'The distribution RelaxNG schema validates inputs; native YaST installation still requires acceptance']
    def prepare_inputs(self, folder, public, runtime, payloads, metadata):
        if self.kind == 'opensuse':
            userspace = json.loads((ROOT / 'runtime/enrollment-images/portable-userspace.json').read_text())
            if digest(ROOT / userspace['path']) != userspace['sha256']:
                raise ValueError('Pinned older-distro userspace changed')
            runtime.clear()
            runtime.update(userspace)
            firstboot = firstboot_script(folder.name, public, runtime, native_transform=adapt_native_config)
            built = profile(self.route, folder.name, public, runtime, firstboot=firstboot)
            root = ET.fromstring(built['profile'])
            ns = {'y': 'http://www.suse.com/1.0/yast2ns'}
            hook = root.find('y:scripts/y:chroot-scripts/y:script/y:source', ns)
            if hook is None or built['firstboot_sha256'] not in hook.text:
                raise ValueError('AutoYaST lost its verified late hook')
            hook.text += '\necho ' + self.install_marker + ' ' + folder.name + ' > /dev/ttyS0\n'
            raw = ET.tostring(root, encoding='utf-8', xml_declaration=True)
            validate_autoyast(raw)
            validation = 'Independent openSUSE Leap 15.6 compiled AutoYaST RelaxNG schemas via lxml'
        else:
            built = profile(self.route, folder.name, public, runtime)
            raw = built['profile'].decode().replace('firstboot --disable\n', 'firstboot --disable\nfirewall --enabled --port=9443:tcp\n')
            if raw.count('%end') != 2:
                raise ValueError('Reviewed Kickstart sections changed')
            position = raw.rfind('%end')
            raw = (raw[:position] + 'echo ' + self.install_marker + ' ' + folder.name + ' > /dev/ttyS0\n' + raw[position:]).encode()
            sys.path.insert(0, str(ROOT / 'tools/enrollment-validators'))
            from pykickstart.parser import KickstartParser
            from pykickstart.version import makeVersion
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                parser = KickstartParser(makeVersion('F44'), followIncludes=False, errorsAreFatal=True)
                parser.readKickstartFromString(raw.decode())
            if parser.handler.ignoredisk.onlyuse != ['vda'] or parser.handler.clearpart.drives != ['vda']:
                raise ValueError('Kickstart disk scope changed')
            validation = 'Independent upstream pykickstart F44 parser'
        (folder / built['profile_name']).write_bytes(raw)
        (folder / 'installer-firstboot.sh').write_bytes(built['firstboot_script'])
        save(folder / 'rpm-installer-inputs.json', {'profile_sha256': digest(folder / built['profile_name']),
            'firstboot_sha256': built['firstboot_sha256'], 'validation': validation,
            'app_local_userspace': self.kind == 'opensuse'})
        prefix = '/installer/' + folder.name + '/'
        return payloads, {**metadata, prefix + built['profile_name']: base64.b64encode(raw).decode(),
                          prefix + 'firstboot.sh': base64.b64encode(built['firstboot_script']).decode()}
    def create_vm(self, *args, **kwargs):
        cls = FedoraInstalledVM if self.kind == 'fedora' else OpenSUSEInstalledVM
        self.vm = cls(*args, **kwargs)
        return self.vm
    def finish(self, folder):
        evidence = super().finish(folder)
        path = folder / 'guest-report.json'
        if self.kind == 'fedora' and path.exists():
            report = json.loads(path.read_text())
            for phase in ('initial_statuses', 'final_statuses'):
                if report[phase]['sprout-4'].get('native_selinux_enforcing') is not True:
                    raise ValueError('Fedora native acceptance requires SELinux enforcing on both installed-OS boots')
            evidence['selinux_enforcing_both_boots'] = True
        return evidence
