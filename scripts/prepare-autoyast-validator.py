"""Extract the distribution's compiled AutoYaST RelaxNG schemas; no RPM runs."""
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import save, digest


def main():
    root = ROOT / 'tools/enrollment-validators/autoyast'
    manifest = root / 'manifest.json'
    if manifest.exists():
        data = json.loads(manifest.read_text())
        for name, pin in data['schemas'].items():
            if digest(root / 'rng' / name) != pin:
                raise ValueError('Pinned upstream AutoYaST schema changed')
        return print(json.dumps({'ready': True, 'manifest': str(manifest), 'native_acceptance': False}))
    root.mkdir(exist_ok=True)
    source = 'https://download.opensuse.org/distribution/leap/15.6/repo/oss/x86_64/yast2-schema-default-4.6.3-150600.1.2.x86_64.rpm'
    package = root / 'yast2-schema-default.rpm'
    if not package.exists():
        with urllib.request.urlopen(source, timeout=30) as response:
            raw = response.read(2 * 1024**2 + 1)
        if len(raw) > 2 * 1024**2 or raw[:4] != b'\xed\xab\xee\xdb':
            raise ValueError('Expected a bounded upstream schema RPM')
        package.write_bytes(raw)
    stage = root / str(uuid4())
    stage.mkdir()
    seven = ROOT / 'tools/7zip/26.04/7z.exe'
    child = subprocess.run([str(seven), 'e', '-y', str(package), '-o' + str(stage)], capture_output=True, text=True)
    if child.returncode:
        raise RuntimeError('Schema RPM extraction failed: ' + child.stdout[-500:])
    archives = [p for p in stage.iterdir() if p.is_file()]
    if len(archives) != 1:
        raise ValueError('Expected exactly one RPM payload archive')
    archive = archives[0]
    child = subprocess.run([str(seven), 'l', '-slt', str(archive)], capture_output=True, text=True)
    names = re.findall(r'^Path = (.+)$', child.stdout, re.M)
    paths = [name.strip() for name in names if name.strip().endswith('.rng')]
    if (not paths or len(paths) > 128 or len({Path(name).name for name in paths}) != len(paths)
            or any(not name.replace('\\', '/').lstrip('./').startswith('usr/share/YaST2/schema/autoyast/rng/') for name in paths)):
        raise ValueError('Unexpected schema package member layout')
    output = root / 'rng'
    output.mkdir(exist_ok=True)
    child = subprocess.run([str(seven), 'e', '-y', str(archive), *paths, '-o' + str(output)], capture_output=True, text=True)
    if child.returncode or not (output / 'profile.rng').exists():
        raise RuntimeError('Compiled AutoYaST profile schema extraction failed')
    for path in output.iterdir():
        if not re.fullmatch(r'[A-Za-z0-9_.-]+\.rng', path.name) or path.stat().st_size > 1024**2:
            raise ValueError('Unexpected schema filename or size')
        for href in re.findall(r'href=[\'"]([^\'"]+)', path.read_text()):
            if not re.fullmatch(r'[A-Za-z0-9_.-]+\.rng', href) or not (output / href).is_file():
                raise ValueError('Schema has an external or missing include')
    sys.path.insert(0, str(ROOT / 'tools/enrollment-validators'))
    try:
        import lxml.etree
    except ImportError:
        with urllib.request.urlopen('https://pypi.org/pypi/lxml/json', timeout=30) as response:
            version = json.load(response)['info']['version']
        if re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}', version) is None:
            raise ValueError('Unexpected lxml release version')
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-compile', '--target',
            str(ROOT / 'tools/enrollment-validators'), 'lxml==' + version,
            '--report', str(ROOT / 'tools/enrollment-lxml-install.json')], check=True)
        import lxml.etree
    parser = lxml.etree.XMLParser(no_network=True, resolve_entities=False)
    lxml.etree.RelaxNG(lxml.etree.parse(str(output / 'profile.rng'), parser))
    save(manifest, {'source_url': source, 'rpm_sha256': digest(package),
        'trust': 'Publisher distribution HTTPS, locally SHA256 pinned; detached RPM signature not verified',
        'schemas': {path.name: digest(path) for path in output.iterdir()},
        'validator': 'lxml ' + '.'.join(map(str, lxml.etree.LXML_VERSION)), 'native_acceptance': False})
    print(json.dumps({'ready': True, 'manifest': str(manifest), 'schemas': len(paths), 'native_acceptance': False}))


if __name__ == '__main__':
    main()
