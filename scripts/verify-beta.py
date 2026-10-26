"""Verify shipped beta files offline. Runtime/user-created files are independent."""
from pathlib import Path
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parents[1]


def verify(root):
    manifest=json.loads((root/'package-manifest.json').read_text(encoding='utf-8'))
    if manifest.get('schema')!='agenticvm.beta.v1' or not isinstance(manifest.get('files'),list):
        raise ValueError('Invalid beta manifest')
    errors=[]
    seen=set()
    for entry in manifest['files']:
        relative=entry['path']
        path=root/relative
        if (not isinstance(relative,str) or Path(relative).is_absolute() or '..' in Path(relative).parts
                or ':' in relative or relative.casefold() in seen):
            raise ValueError('Invalid inventory path')
        seen.add(relative.casefold())
        if any(parent.is_symlink() or getattr(parent,'is_junction',lambda:False)() for parent in (path,*path.parents)):
            errors.append({'path':relative,'error':'redirected path'});continue
        if not path.is_file() or path.stat().st_size!=entry['bytes']:
            errors.append({'path':relative,'error':'missing or changed size'});continue
        with path.open('rb') as stream:
            actual=hashlib.file_digest(stream,'sha256').hexdigest()
        if actual!=entry['sha256']:errors.append({'path':relative,'error':'digest mismatch'})
    return {'ok':not errors,'files_verified':len(seen),'version':manifest['version'],'errors':errors}


if __name__=='__main__':
    try:
        result=verify(ROOT);print(json.dumps(result,indent=2));raise SystemExit(0 if result['ok'] else 1)
    except (OSError,ValueError,KeyError,TypeError) as error:
        print(json.dumps({'ok':False,'error':str(error)}));raise SystemExit(1)
