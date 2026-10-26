"""Security-on realism gate for CP1; evidence input only, no VM execution."""
from __future__ import annotations

from dataclasses import dataclass
import re

SCHEMA = 'agenticvm.garden-realism.v1'
OS = {'ubuntu', 'debian'}
INIT = {'systemd'}
LSM = {'apparmor': {'enabled', 'Y'}, 'selinux': {'enforcing'}}
FIREWALL = {'active'}
SSHD = {'installed', 'not-installed'}
DISABLED = {'apparmor', 'selinux', 'firewall', 'ssh', 'secureboot', 'defender', 'uac', 'wdac'}


@dataclass(frozen=True)
class Observation:
    os_id: str
    init: str
    apparmor: str
    selinux: str
    firewall: str
    sshd: str
    ssh_active: bool
    sudo: bool
    security_disabled: tuple[str, ...]
    host_mounts: bool
    real_disk: bool

    @classmethod
    def from_dict(cls, value):
        fields = {'os_id', 'init', 'apparmor', 'selinux', 'firewall', 'sshd', 'ssh_active', 'sudo',
                  'security_disabled', 'host_mounts', 'real_disk'}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError('Invalid realism observation fields')
        if not isinstance(value['security_disabled'], list):
            raise ValueError('security_disabled must be an array')
        for name in ('ssh_active', 'sudo', 'host_mounts', 'real_disk'):
            if type(value[name]) is not bool:
                raise ValueError(name + ' must be boolean')
        return cls(value['os_id'], value['init'], value['apparmor'], value['selinux'],
                   value['firewall'], value['sshd'], value['ssh_active'], value['sudo'],
                   tuple(value['security_disabled']), value['host_mounts'], value['real_disk'])

    def to_dict(self):
        return {'os_id': self.os_id, 'init': self.init, 'apparmor': self.apparmor,
                'selinux': self.selinux, 'firewall': self.firewall, 'sshd': self.sshd,
                'ssh_active': self.ssh_active, 'sudo': self.sudo,
                'security_disabled': list(self.security_disabled),
                'host_mounts': self.host_mounts, 'real_disk': self.real_disk}


def evaluate(value):
    """Return pass/fail with explicit reasons; no profile is grandfathered."""
    observation = Observation.from_dict(value)
    failures = []
    if observation.os_id not in OS:
        failures.append('unsupported OS: ' + observation.os_id)
    if observation.init not in INIT:
        failures.append('PID 1 is not systemd: ' + observation.init)
    if observation.apparmor not in LSM['apparmor'] and observation.selinux not in LSM['selinux']:
        failures.append('no enforcing LSM (AppArmor or SELinux)')
    if observation.firewall not in FIREWALL:
        failures.append('firewall is not active')
    if observation.sshd != 'installed':
        failures.append('sshd is not installed')
    if not observation.ssh_active:
        failures.append('sshd is not active')
    if not observation.sudo:
        failures.append('no non-interactive sudo path')
    if observation.security_disabled:
        failures.append('security disabled: ' + ', '.join(observation.security_disabled))
    if observation.host_mounts:
        failures.append('host mounts present')
    if not observation.real_disk:
        failures.append('no real installed disk')
    for name in observation.security_disabled:
        if name not in DISABLED:
            failures.append('unknown disabled feature: ' + name)
    return {'schema': SCHEMA, 'passed': not failures, 'failures': failures,
            'warnings': [], 'observation': observation.to_dict()}
