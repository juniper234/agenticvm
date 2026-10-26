"""Offline preparation contracts for resource-gated enrollment platforms.

This module emits review artifacts only. It has no transport, credentials,
tenant client or native package builder. Local validation is deliberately
reported separately from platform API, OS and hardware acceptance.
"""
from __future__ import annotations
import hashlib
import json
import re
from uuid import UUID
import xml.etree.ElementTree as ET

REFERENCES = {
    'windows-unattend': 'https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-a-custom-script-to-windows-setup',
    'windows-openssh': 'https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement',
    'windows-winrm': 'https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/winrmsecurity',
    'windows-gpo': 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/use-group-policy-to-install-software',
    'mdm-required-app': 'https://learn.microsoft.com/en-us/intune/app-management/deployment/add-win32',
    'intel-amt': 'https://www.intel.com/content/www/us/en/developer/articles/guide/getting-started-with-active-management-technology.html',
    'autopilot-self-deploy': 'https://learn.microsoft.com/en-us/windows/deployment/windows-autopilot/demonstrate-deployment-on-vm',
    'apple-ade': 'https://support.apple.com/guide/deployment/automated-device-enrollment-management-dep73069dd57/web',
    'azure-extension': 'https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-linux',
    'aws-ssm': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-command-ssm-plugin-reference.html',
}
REQUIREMENTS = {
    'windows-unattend': ['evaluation-media', 'windows-native-package', 'windows-setup-validation', 'host-storage-40-gib'],
    'windows-openssh': ['owned-windows-vm', 'prepared-sshd-and-key', 'pinned-host-key', 'windows-native-package', 'host-storage-40-gib'],
    'windows-winrm': ['owned-windows-vm', 'prepared-winrm-https', 'trusted-server-and-client-identity', 'windows-native-package', 'host-storage-40-gib'],
    'windows-gpo': ['owned-domain-controller-and-member', 'computer-scoped-test-ou', 'signed-msi-and-share-acls', 'host-storage-40-gib'],
    'mdm-required-app': ['test-tenant', 'enrolled-test-device', 'required-device-assignment', 'signed-native-package'],
    'intel-amt': ['compatible-physical-amt', 'owner-provisioned-management', 'tls-identity', 'applicable-redirection-consent'],
    'autopilot-self-deploy': ['test-tenant', 'registered-physical-device', 'hardware-tpm-attestation', 'entra-join'],
    'apple-ade': ['apple-hardware', 'organization-and-device-management', 'assigned-device', 'ethernet-and-power', 'signed-macos-package'],
    'azure-extension': ['azure-test-subscription', 'owned-vm-resource-id', 'healthy-azure-vm-agent', 'least-privilege-extension-role'],
    'aws-ssm': ['aws-test-account', 'registered-managed-node', 'healthy-ssm-agent', 'least-privilege-run-command-role'],
}


def canonical_uuid(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError('Canonical explicit lab UUID required')
    return value


def preparation(route, run_id, target_id, payload_sha256, *, now):
    if route not in REFERENCES:
        raise ValueError('Unknown resource-gated platform')
    canonical_uuid(run_id)
    canonical_uuid(target_id)
    if not isinstance(payload_sha256, str) or re.fullmatch('[0-9a-f]{64}', payload_sha256) is None:
        raise ValueError('An explicit reviewed payload SHA256 is required')
    if type(now) is not int or now < 0:
        raise ValueError('Explicit integer test clock required')
    result = {'schema': 'agenticvm.platform-preparation.v1', 'route': route, 'run_id': run_id,
        'owned_target_uuid': target_id, 'action': 'prepare-reviewed-enrollment',
        'issued_at': now, 'expires_at': now + 900, 'payload_sha256': payload_sha256,
        'required_resources': REQUIREMENTS[route], 'reference': REFERENCES[route],
        'native_implementation_available': False, 'native_acceptance': False,
        'delivery_enabled': False, 'credentials': None,
        'acceptance_required': ['Native mechanism logs and target OS/build', 'Initial agent/model/identity absence',
            'Payload hash and scoped admission', 'Actual correlated target model replies',
            'Duplicate request without duplicate identity/process', 'Two cold boots with durable identity and fresh reply',
            'Interrupted transfer and changed grant/payload/bootstrap refusal', 'Exact owned-resource cleanup']}
    if route == 'windows-unattend':
        # Setup customization fragment only: no disk wipe, account password,
        # automatic logon or implicit image/edition/license selection.
        ns = 'urn:schemas-microsoft-com:unattend'
        ET.register_namespace('', ns)
        root = ET.Element('{' + ns + '}unattend')
        settings = ET.SubElement(root, '{' + ns + '}settings', {'pass': 'specialize'})
        ET.SubElement(settings, '{' + ns + '}component', {'name': 'Microsoft-Windows-Deployment',
            'processorArchitecture': 'amd64', 'publicKeyToken': '31bf3856ad364e35', 'language': 'neutral', 'versionScope': 'nonSxS'})
        result['artifact'] = {'format': 'unattend-customization-fragment', 'xml': ET.tostring(root, encoding='unicode'),
            'hook': '%WINDIR%\\Setup\\Scripts\\SetupComplete.cmd',
            'requires': 'A validated edition-specific answer file and a signed Windows package; this fragment does not install an OS',
            'limitation': 'SetupComplete eligibility varies by product key/edition; FirstLogonCommands requires logon and is not used'}
    elif route == 'windows-openssh':
        result['artifact'] = {'transport': 'ssh', 'authentication': 'publickey', 'host_key_checking': 'strict',
            'account_kind': 'owner-prepared local or AD account', 'destination': '192.0.2.4',
            'administrators_key_file': '%ProgramData%\\ssh\\administrators_authorized_keys',
            'operation': 'invoke one reviewed fixed installer; no discovery or extra hop', 'native_payload_available': False}
    elif route == 'windows-winrm':
        result['artifact'] = {'transport': 'https', 'endpoint': 'https://192.0.2.4:5986/wsman',
            'authentication': 'certificate', 'allow_unencrypted': False, 'skip_certificate_checks': False,
            'trusted_hosts_wildcard': False, 'operation': 'invoke one reviewed fixed installer', 'native_payload_available': False}
    elif route == 'windows-gpo':
        result['artifact'] = {'policy_scope': 'Computer Configuration', 'deployment': 'Assigned',
            'target_kind': 'one dedicated test OU and computer security filter', 'package_kind': 'signed MSI',
            'share_requirement': 'explicit UNC path readable by the assigned computer', 'domain_joined': False}
    elif route == 'mdm-required-app':
        result['artifact'] = {'installExperience': {'runAsAccount': 'system'}, 'assignment': {'intent': 'required',
            'target': {'@odata.type': '#microsoft.graph.groupAssignmentTarget', 'groupId': target_id}},
            'package_format': 'intunewin', 'detection_rule': 'native package version and installed identity',
            'not_a_complete_graph_create_request': True}
    elif route == 'intel-amt':
        result['artifact'] = {'transport': 'TLS WS-Management', 'host': 'amt-lab.invalid',
            'physical_hardware_observed': False, 'provisioned_mode': None, 'consent_policy': 'must be observed; never bypass',
            'allowed_operations': ['inventory', 'one-time-boot', 'power'], 'native_wire_client_implemented': False}
    elif route == 'autopilot-self-deploy':
        result['artifact'] = {'deployment_mode': 'self-deploying', 'join': 'Microsoft Entra join',
            'requires_hardware_tpm_attestation': True, 'virtual_machine_supported': False,
            'offline_json_cannot_replace_attestation': True, 'tenant_profile_created': False}
    elif route == 'apple-ade':
        result['artifact'] = {'mechanism': 'Automated Device Enrollment plus Auto Advance',
            'device_type': 'Mac', 'requires_ethernet_and_power': True, 'device_management_assignment': False,
            'installer': 'signed managed package after enrollment', 'physical_hardware_observed': False}
    elif route == 'azure-extension':
        result['artifact'] = {'publisher': 'Microsoft.Azure.Extensions', 'type': 'CustomScript',
            'typeHandlerVersion': '2.1', 'settings': {'skipDos2Unix': True},
            'resource_id': '/subscriptions/' + run_id + '/resourceGroups/GardenLab/providers/Microsoft.Compute/virtualMachines/garden-' + target_id,
            'protected_settings_required': 'Reviewed fixed installer, payload pin and scoped admission; never put credentials in public settings',
            'extension_write_implemented': False}
    else:
        result['artifact'] = {'schemaVersion': '2.2', 'description': 'Prepared garden enrollment contract; delivery is disabled',
            'parameters': {}, 'mainSteps': [{'name': 'EnrollReviewed', 'action': 'aws:runShellScript',
                'precondition': {'StringEquals': ['platformType', 'Linux']},
                'inputs': {'timeoutSeconds': '900', 'runCommand': ['/opt/garden-control/enroll-reviewed']}}],
            'target_selection': {'explicit_managed_node_required': True, 'tag_or_wildcard_selection': False},
            'send_command_implemented': False}
    return result


def validate_preparation(value, *, route, run_id, target_id, payload_sha256, now):
    """Check a fixed preparation against owner-selected scope; never deliver it."""
    expected = preparation(route, run_id, target_id, payload_sha256, now=value.get('issued_at'))
    if type(now) is not int or not value['issued_at'] <= now < value['expires_at']:
        raise ValueError('Preparation has expired or has a future clock')
    # Exact immutable serialization rejects injected commands, broadened
    # assignments, altered recipients, resource claims and unknown fields.
    if json.dumps(value, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError('Preparation differs from the owner-scoped reviewed contract')
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
