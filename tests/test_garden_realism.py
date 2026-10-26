"""CP1 security-on gate rejects development appliances and disabled defenses."""
import unittest

from agenticvm.garden_realism import evaluate


def profile(**changes):
    value = {'os_id': 'ubuntu', 'init': 'systemd', 'apparmor': 'enabled',
             'selinux': 'disabled', 'firewall': 'active', 'sshd': 'installed',
             'ssh_active': True, 'sudo': True, 'security_disabled': [],
             'host_mounts': False, 'real_disk': True}
    value.update(changes)
    return value


class RealismGateTests(unittest.TestCase):
    def test_real_installed_profile_passes(self):
        result = evaluate(profile())
        self.assertTrue(result['passed'], result['failures'])
        self.assertEqual(result['failures'], [])

    def test_busybox_appliance_is_rejected_with_every_reason(self):
        result = evaluate(profile(os_id='debian', init='busybox', apparmor='disabled',
                                  firewall='absent', sshd='not-installed', sudo=False,
                                  real_disk=True))
        self.assertFalse(result['passed'])
        joined = ' | '.join(result['failures'])
        for expected in ('PID 1', 'LSM', 'firewall', 'sshd', 'sudo'):
            self.assertIn(expected, joined)

    def test_disabling_defenses_or_mounting_host_fails(self):
        for changes, expected in (({'security_disabled': ['apparmor']}, 'security disabled'),
                                  ({'security_disabled': ['nftables']}, 'unknown disabled'),
                                  ({'host_mounts': True}, 'host mounts'),
                                  ({'real_disk': False}, 'real installed disk'),
                                  ({'selinux': 'permissive', 'apparmor': 'disabled'}, 'LSM')):
            with self.subTest(changes=changes):
                result = evaluate(profile(**changes))
                self.assertFalse(result['passed'])
                self.assertIn(expected, ' | '.join(result['failures']))

    def test_selinux_enforcing_is_an_alternative_lsm(self):
        result = evaluate(profile(os_id='debian', apparmor='disabled', selinux='enforcing'))
        self.assertTrue(result['passed'], result['failures'])

    def test_apparmor_kernel_y_value_is_accepted(self):
        result = evaluate(profile(apparmor='Y'))
        self.assertTrue(result['passed'], result['failures'])

    def test_extra_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            evaluate(dict(profile(), extra=True))
