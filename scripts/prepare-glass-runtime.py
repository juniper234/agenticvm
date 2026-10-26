"""Copy only the .NET desktop runtime needed to open the app, not the SDK."""
from pathlib import Path
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'tools/dotnet/sdk'
target = ROOT / 'tools/dotnet/runtime'
target.mkdir(parents=True, exist_ok=True)
for name in ('dotnet.exe', 'LICENSE.txt', 'ThirdPartyNotices.txt'):
    if (source / name).is_file():
        shutil.copy2(source / name, target / name)
for relative in ('host/fxr/9.0.21', 'shared/Microsoft.NETCore.App/9.0.21', 'shared/Microsoft.WindowsDesktop.App/9.0.21'):
    shutil.copytree(source / relative, target / relative, dirs_exist_ok=True)
files = []
for path in sorted(target.rglob('*')):
    if path.is_file() and path.name != 'manifest.json':
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        files.append({'path': path.relative_to(target).as_posix(), 'bytes': path.stat().st_size, 'sha256': digest})
receipt = {'version': '9.0.21', 'purpose': 'Framework-dependent AgenticVM desktop runtime',
    'sdk_required_to_open': False, 'files': files, 'bytes': sum(item['bytes'] for item in files)}
(target / 'manifest.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
print(json.dumps({'files': len(files), 'bytes': receipt['bytes'], 'sdk_required_to_open': False}))
