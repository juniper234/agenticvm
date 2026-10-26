"""Independent receipt checks for the bounded mother/sponsor/target workflow."""
from .lan_lab import MODEL_SHA


def verify_delegation(guest, target_uuid):
    receipt = guest['delegation']
    statuses = guest['statuses']
    sponsor, target = statuses['offshoot-1'], statuses['sprout-4']
    if (receipt['target_uuid'] != target_uuid or receipt['garden'] != guest['garden']
            or receipt['target'] != 'sprout-4' or receipt['sponsor'] != 'offshoot-1'
            or receipt.get('ok') is not True or receipt.get('duplicate') is not False
            or not receipt['target_model_ready'] or not guest['mother_independently_verified']
            or receipt['target_pid'] != target['pid']
            or receipt['target_sha256'] != target['public_identity']['sha256']
            or receipt['installed']['model_sha256'] != MODEL_SHA):
        raise ValueError('Delegated enrollment receipt does not match target evidence')
    for tls in (guest['delegation_tls'], receipt['confirmation_tls'], guest['mother_confirmation_tls']):
        if tls['version'] != 'TLSv1.3':
            raise ValueError('Delegation and confirmation require TLS 1.3')
    exchange = receipt['sponsor_exchange']
    if exchange not in target['delivered'] or exchange['hello'] not in sponsor['received']:
        raise ValueError('Sponsor has no independently matching introduction')
    ledger = sponsor['delegations']
    if len(ledger) != 1 or ledger[0]['state'] != 'complete' or ledger[0]['id'] != receipt['request_id']:
        raise ValueError('Exactly one completed sponsor transaction required')
    if guest['duplicate_delegation'] != {**receipt, 'duplicate': True}:
        raise ValueError('Duplicate delegation did not retain its original receipt')
    if receipt['duplicate_bootstrap']['process'] != receipt['installed']['process']:
        raise ValueError('Duplicate bootstrap changed target process')
    downloads = receipt['installed']['downloads']
    if {row['name'] for row in downloads} != {'model.gguf', 'llama.tar.gz', 'libgomp.so.1', 'agent.tar.gz'} or len(downloads) != 4:
        raise ValueError('Torrent receipt inventory mismatch')
    for row in downloads:
        if (row.get('protocol') != 'BitTorrent v1' or not row.get('sha256_verified')
                or row.get('peer') != ['192.0.2.1', 6881] or row.get('trackers') != []
                or row.get('dht') is not False or row.get('peer_discovery') is not False
                or row['payload_downloaded_bytes'] < row['bytes']):
            raise ValueError('Actual bounded torrent transfer evidence required')
    seed = statuses['mother']['torrent_seed']
    if seed['errors'] or seed['payload_bytes_sent'] < sum(row['bytes'] for row in downloads):
        raise ValueError('Seeder transfer evidence does not reconcile')
    return {'mother_to_sponsor_to_new_sprout_to_sponsor_to_mother': True,
            'torrent_assets_verified': 4, 'actual_torrent_payload_bytes': sum(row['payload_downloaded_bytes'] for row in downloads),
            'mother_independently_verified': True, 'duplicate_delegation_same_receipt': True,
            'sponsor_transactions': 1, 'new_sprout_inherits_installation_key': False,
            'authorization': 'One owned VM, preauthorized SSH, strict host pin, isolated virtual Ethernet'}
