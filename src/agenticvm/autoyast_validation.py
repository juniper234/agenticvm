"""Validate profiles against pinned compiled schemas shipped by openSUSE 15.6."""
import json
import sys
from .lan_lab import ROOT, digest


def validate(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 262144 or b'<!DOCTYPE' in raw or b'<!ENTITY' in raw:
        raise ValueError('Bounded standalone AutoYaST profile required')
    folder = ROOT / 'tools/enrollment-validators/autoyast'
    manifest = json.loads((folder / 'manifest.json').read_text())
    for name, pin in manifest['schemas'].items():
        if digest(folder / 'rng' / name) != pin:
            raise ValueError('Pinned distribution AutoYaST schema changed')
    sys.path.insert(0, str(ROOT / 'tools/enrollment-validators'))
    from lxml import etree
    parser = etree.XMLParser(no_network=True, resolve_entities=False)
    schema = etree.RelaxNG(etree.parse(str(folder / 'rng/profile.rng'), parser))
    schema.assertValid(etree.fromstring(raw, parser))
    return {'validator': manifest['validator'], 'schema_sha256': digest(folder / 'rng/profile.rng'),
            'distribution': 'openSUSE Leap 15.6', 'native_acceptance': False}
