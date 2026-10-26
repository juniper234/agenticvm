"""Native unattended installer inputs, restricted to one disposable virtio disk.

These are adapters. Only booting the real installer and checking the installed
OS can establish native acceptance; parsing these files cannot do that.
"""
from __future__ import annotations
import base64
import hashlib
import json
import shlex
from uuid import UUID
import xml.etree.ElementTree as ET

from .native_enrollment import native_config

ROUTES = ('ubuntu-autoinstall', 'debian-preseed', 'anaconda-kickstart', 'autoyast')
ORIGIN = 'http://192.0.2.1:8080'


def firstboot_script(run_id, public, runtime, *, native_transform=None):
    """Install the reviewed first-boot files without executing the agent yet."""
    payload, _ = native_config('cloud-init-local', run_id, public, runtime)
    config = json.loads(payload['user-data'].decode().split('\n', 1)[1])
    if native_transform:
        config = native_transform(config)
    lines = ['#!/bin/sh', 'set -eu', 'umask 077', 'mkdir -p /etc/garden /var/lib/garden',
             'if ! id -u 1000 >/dev/null 2>&1; then useradd --uid 1000 --user-group --no-create-home --shell /usr/sbin/nologin garden-agent; fi']
    for item in config['write_files']:
        path = item['path']
        if not path.startswith(('/etc/garden/', '/etc/systemd/system/')):
            raise ValueError('Unexpected native first-boot path')
        raw = base64.b64encode(item['content'].encode()).decode()
        lines.extend([f"printf '%s' {shlex.quote(raw)} | base64 -d > {shlex.quote(path)}",
                      f"chmod {item['permissions']} {shlex.quote(path)}"])
    lines += ['chown 1000:1000 /var/lib/garden', 'chmod 0700 /var/lib/garden',
              'systemctl enable garden-native-install.service']
    return ('\n'.join(lines) + '\n').encode()


def profile(route, run_id, public, runtime, *, firstboot=None):
    if route not in ROUTES or str(UUID(run_id)) != run_id:
        raise ValueError('Known installer and canonical owned run UUID required')
    script = firstboot_script(run_id, public, runtime) if firstboot is None else firstboot
    if not isinstance(script, bytes) or not 1 <= len(script) <= 256 * 1024:
        raise ValueError('Bounded reviewed first-boot script bytes required')
    pin = hashlib.sha256(script).hexdigest()
    url = ORIGIN + '/installer/' + run_id + '/firstboot.sh'
    # An immutable bootstrap pin travels inside the owner-supplied profile.
    stage = f"curl --fail --silent --show-error {url} -o /root/garden-firstboot.sh && printf '%s  %s\\n' {pin} /root/garden-firstboot.sh | sha256sum -c - && /bin/sh /root/garden-firstboot.sh"
    if route == 'ubuntu-autoinstall':
        install = {'version': 1, 'refresh-installer': {'update': False}, 'locale': 'en_US.UTF-8',
            'keyboard': {'layout': 'us'}, 'timezone': 'Etc/UTC',
            'identity': {'hostname': 'garden-installed', 'username': 'garden-agent', 'password': '!'},
            'ssh': {'install-server': False, 'allow-pw': False},
            'storage': {'layout': {'name': 'direct', 'match': {'path': '/dev/vda'}}},
            'packages': ['python3', 'openssl', 'curl'],
            'late-commands': [['curtin', 'in-target', '--target=/target', '--', '/bin/sh', '-c', stage]],
            'shutdown': 'poweroff'}
        name, raw = 'user-data', ('#cloud-config\n' + json.dumps({'autoinstall': install}, indent=2) + '\n').encode()
        boot = 'autoinstall ds=nocloud;s=' + ORIGIN + '/installer/' + run_id + '/'
    elif route == 'debian-preseed':
        # No mirror is contacted. A pinned installation CD/repository must
        # contain these packages before the runner may start this profile.
        late = f"wget -O /target/root/garden-firstboot.sh {url}; echo '{pin}  /target/root/garden-firstboot.sh' | sha256sum -c - && in-target /bin/sh /root/garden-firstboot.sh"
        text = '''d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string garden-installed
d-i netcfg/get_domain string garden.invalid
d-i netcfg/get_gateway string none
d-i netcfg/get_nameservers string
d-i mirror/country string manual
d-i apt-setup/use_mirror boolean false
d-i passwd/root-login boolean false
d-i passwd/make-user boolean true
d-i passwd/user-fullname string Garden Agent
d-i passwd/username string garden-agent
d-i passwd/user-password-crypted password !
d-i passwd/user-uid string 1000
d-i clock-setup/utc boolean true
d-i time/zone string Etc/UTC
d-i clock-setup/ntp boolean false
d-i partman-auto/disk string /dev/vda
d-i partman-auto/method string regular
d-i partman-auto/choose_recipe select atomic
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i pkgsel/run_tasksel boolean false
d-i pkgsel/include string python3 openssl
d-i pkgsel/upgrade select none
d-i popularity-contest/participate boolean false
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string /dev/vda
d-i finish-install/reboot_in_progress note
d-i debian-installer/exit/poweroff boolean true
'''
        name, raw = 'preseed.cfg', (text + 'd-i preseed/late_command string ' + late + '\n').encode()
        boot = 'auto=true priority=critical preseed/url=' + ORIGIN + '/installer/' + run_id + '/preseed.cfg'
    elif route == 'anaconda-kickstart':
        text = '''text
cdrom
lang en_US.UTF-8
keyboard us
timezone Etc/UTC --utc
rootpw --lock
user --name=garden-agent --uid=1000 --lock
network --bootproto=dhcp --device=link --activate
ignoredisk --only-use=vda
clearpart --all --initlabel --drives=vda
autopart --type=plain --nohome
bootloader --location=mbr --boot-drive=vda
firstboot --disable
poweroff
%packages
@core
python3
openssl
curl
%end
%post --erroronfail
'''
        name, raw = 'ks.cfg', (text + stage + '\n%end\n').encode()
        boot = 'inst.ks=' + ORIGIN + '/installer/' + run_id + '/ks.cfg'
    else:
        ns, conf = 'http://www.suse.com/1.0/yast2ns', 'http://www.suse.com/1.0/configns'
        ET.register_namespace('', ns)
        ET.register_namespace('config', conf)
        root = ET.Element('{' + ns + '}profile')
        def add(parent, name, text=None, kind=None):
            item = ET.SubElement(parent, '{' + ns + '}' + name)
            if text is not None:
                item.text = text
            if kind:
                item.set('{' + conf + '}type', kind)
            return item
        general = add(root, 'general')
        mode = add(general, 'mode')
        add(mode, 'confirm', 'false', 'boolean')
        add(mode, 'halt', 'true', 'boolean')
        add(mode, 'second_stage', 'false', 'boolean')
        keyboard = add(root, 'keyboard')
        add(keyboard, 'keymap', 'english-us')
        language = add(root, 'language')
        add(language, 'language', 'en_US')
        add(language, 'languages', 'en_US')
        groups = add(root, 'groups', kind='list')
        group = add(groups, 'group')
        add(group, 'groupname', 'garden-agent')
        add(group, 'gid', '1000')
        users = add(root, 'users', kind='list')
        administrator = add(users, 'user')
        for key, value in {'username': 'root', 'uid': '0', 'gid': '0', 'user_password': '!', 'encrypted': 'true'}.items():
            add(administrator, key, value, 'boolean' if key == 'encrypted' else None)
        user = add(users, 'user')
        for key, value in {'username': 'garden-agent', 'uid': '1000', 'gid': '1000', 'user_password': '!',
                           'encrypted': 'true'}.items():
            add(user, key, value, 'boolean' if key == 'encrypted' else None)
        drive = add(add(root, 'partitioning', kind='list'), 'drive')
        add(drive, 'device', '/dev/vda')
        add(drive, 'initialize', 'true', 'boolean')
        add(drive, 'use', 'all')
        partition = add(add(drive, 'partitions', kind='list'), 'partition')
        add(partition, 'mount', '/')
        add(partition, 'size', 'max')
        add(partition, 'filesystem', 'ext4', 'symbol')
        bootloader = add(root, 'bootloader')
        add(bootloader, 'loader_type', 'grub2')
        add(bootloader, 'device_map', kind='list')
        loader = add(bootloader, 'global')
        add(loader, 'boot_mbr', 'true')
        networking = add(root, 'networking')
        add(networking, 'keep_install_network', 'true', 'boolean')
        software = add(root, 'software')
        patterns = add(software, 'patterns', kind='list')
        add(patterns, 'pattern', 'base')
        add(software, 'install_recommended', 'false', 'boolean')
        packages = add(software, 'packages', kind='list')
        for package in ('python3', 'openssl', 'curl'):
            add(packages, 'package', package)
        hook = add(add(add(root, 'scripts'), 'chroot-scripts', kind='list'), 'script')
        add(hook, 'chrooted', 'true', 'boolean')
        add(hook, 'interpreter', 'shell')
        add(hook, 'source', '#!/bin/sh\nset -eu\n' + stage + '\n')
        name, raw = 'autoinst.xml', ET.tostring(root, encoding='utf-8', xml_declaration=True)
        boot = 'autoyast=' + ORIGIN + '/installer/' + run_id + '/autoinst.xml'
    return {'route': route, 'profile_name': name, 'profile': raw, 'firstboot_script': script,
            'firstboot_sha256': pin, 'kernel_parameters': boot, 'disk': '/dev/vda',
            'native_acceptance': False, 'requires': ['Fresh owned VM with only one disposable target disk',
                'Publisher-pinned real installer and local package source', 'Native installation/reboot/model verification']}
