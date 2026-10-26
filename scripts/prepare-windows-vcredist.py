"""Download and verify Microsoft's runtime for later installation inside a VM."""
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save


def main():
    manifest = ROOT / 'runtime/enrollment-images/windows-vcredist.json'
    if manifest.exists():
        value = json.loads(manifest.read_text())
        if digest(ROOT / value['path']) != value['sha256']:
            raise ValueError('Microsoft redistributable changed')
        return print(json.dumps({'ready': True, 'installed_on_host': False, 'manifest': str(manifest)}))
    path = ROOT / 'downloads/enrollment/vc_redist.x64.exe'
    source = 'https://aka.ms/vc14/vc_redist.x64.exe'
    if not path.exists():
        with urllib.request.urlopen(source, timeout=30) as response, path.with_suffix('.partial').open('wb') as output:
            url, total = response.url, 0
            while raw := response.read(1024 * 1024):
                total += len(raw)
                if total > 64 * 1024**2:
                    raise ValueError('Microsoft runtime download exceeded its bound')
                output.write(raw)
        path.with_suffix('.partial').replace(path)
    else:
        url = source
    quoted = str(path).replace("'", "''")
    code = "$s=Get-AuthenticodeSignature -LiteralPath '" + quoted + "'; @{status=$s.Status.ToString(); subject=$s.SignerCertificate.Subject; thumbprint=$s.SignerCertificate.Thumbprint} | ConvertTo-Json -Compress"
    child = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', code],
        capture_output=True, text=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW,
        env={**os.environ, 'PSModulePath': str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')})
    if child.returncode or not child.stdout.strip():
        raise RuntimeError('Microsoft runtime signature check failed: ' + child.stderr[-1000:])
    signed = json.loads(child.stdout)
    if signed['status'] != 'Valid' or 'O=Microsoft Corporation' not in signed['subject']:
        raise ValueError('Expected a valid Microsoft runtime publisher signature')
    save(manifest, {'source_url': source, 'resolved_url': url, 'path': path.relative_to(ROOT).as_posix(),
        'bytes': path.stat().st_size, 'sha256': digest(path), 'authenticode': signed,
        'trust': 'Official Microsoft HTTPS plus valid Microsoft Authenticode; locally SHA256 pinned',
        'installed_on_host': False, 'native_acceptance': False})
    print(json.dumps({'ready': True, 'installed_on_host': False, 'authenticode': signed, 'manifest': str(manifest)}, indent=2))


if __name__ == '__main__':
    main()
