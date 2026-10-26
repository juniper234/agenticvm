"""Update only the owned Windows guest's tools, using its existing guest channel.

No host account, password, driver or service changes. Takes effect at next boot.
"""
from pathlib import Path
import base64
import hashlib
import json
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agenticvm.control_client import ControlClient


def main():
    client = ControlClient()
    state = client.status('windows')
    assert state.get('guest_ready') is True,'Start Windows and wait for its tools'
    source = (ROOT/'guest/windows_desktop_agent.py').read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    payload = base64.b64encode(source).decode('ascii')
    temporary = 'C:\\workspace\\tools-update-'+uuid4().hex+'.b64'
    for offset in range(0,len(payload),768):
        chunk = payload[offset:offset+768]
        operation = 'WriteAllText' if offset==0 else 'AppendAllText'
        command = "$ErrorActionPreference='Stop'; [IO.File]::"+operation+"('"+temporary+"','"+chunk+"',[Text.Encoding]::ASCII)"
        result = client.action('windows','exec',command=command)
        assert result['exit_code']==0,result
    destination = 'C:\\ProgramData\\AgenticVM\\agent.py'
    command = "$ErrorActionPreference='Stop'; (Get-Item -LiteralPath '"+destination+"').IsReadOnly=$false; [IO.File]::WriteAllBytes('"+destination+"',[Convert]::FromBase64String([IO.File]::ReadAllText('"+temporary+"'))); (Get-FileHash -Algorithm SHA256 -LiteralPath '"+destination+"').Hash; Remove-Item -LiteralPath '"+temporary+"'"
    result = client.action('windows','exec',command=command)
    assert result['exit_code']==0 and result['stdout'].strip().lower()==digest,result
    receipt = {'ok':True,'uuid':state['uuid'],'guest_path':destination,'sha256':digest,
        'next_boot_required':True,'account_changed':False,'host_settings_changed':False}
    folder = ROOT/'runtime/glass-acceptance'/('tools-update-'+uuid4().hex)
    folder.mkdir(parents=True)
    (folder/'report.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps(receipt))


if __name__=='__main__':
    main()
