"""Prepare one offline Windows evaluation guest; installation requires consent.

Without --accept-eula and --create-guest-account this writes only a reviewable
plan. It never starts a VM or accepts terms by default.
"""
from pathlib import Path
import argparse
import hashlib
import io
import json
import secrets
import sys
import time
from uuid import uuid4
import zipfile
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'runtime/windows-desktop'


def digest(path):
    return hashlib.file_digest(Path(path).open('rb'), 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--accept-eula', action='store_true', help='Explicit owner consent to Microsoft evaluation terms')
    parser.add_argument('--create-guest-account', action='store_true', help='Explicit consent to a random guest-only Administrator password')
    parser.add_argument('--refresh-guest-tools', action='store_true', help='Keep the approved account and refresh setup tools before boot')
    args = parser.parse_args()
    source = json.loads((ASSETS / 'media-source.json').read_text())['iso']
    if digest(ASSETS / 'install.iso') != source['sha256']:
        raise ValueError('The official locally pinned Microsoft ISO has changed')
    sys.path.insert(0, str(ROOT / 'tools/python/iso'))
    import pycdlib
    image = pycdlib.PyCdlib()
    image.open(str(ASSETS / 'install.iso'))
    licenses = []
    try:
        for path, folders, names in image.walk(udf_path='/'):
            for name in names:
                if name.lower().endswith('license.rtf') and 'serverstandard' in path.lower() and 'en-us' in path.lower():
                    output = io.BytesIO()
                    image.get_file_from_iso_fp(output, udf_path=path.rstrip('/') + '/' + name)
                    target = ASSETS / 'microsoft-evaluation-license.rtf'
                    target.write_bytes(output.getvalue())
                    licenses.append(str(target.relative_to(ROOT)))
                    break
            if licenses:
                break
    finally:
        image.close()
    existing = ASSETS / 'install-plan.json'
    plan = json.loads(existing.read_text()) if existing.exists() else {'uuid': str(uuid4())}
    plan.update(os='Windows Server 2025 Standard Evaluation (Desktop Experience)', image_index=2,
        memory_mib=2048, cpus=2, virtual_disk_gib=48, network='none', accelerator='whpx',
        local_guest_account='Administrator, unique generated password, guest only',
        host_disks_attached=False, host_security_changes=False,
        source=source, license_files=licenses, consent_required=['Microsoft evaluation terms', 'guest-only test account'])
    existing.write_text(json.dumps(plan, indent=2), encoding='utf-8')
    approved = ASSETS / 'prepared.json'
    refresh = args.refresh_guest_tools and approved.is_file()
    if not (args.accept_eula and args.create_guest_account) and not refresh:
        print(json.dumps({'plan': str(existing), 'prepared': False, 'consent_required': plan['consent_required']}))
        return 0
    if approved.exists() and not refresh:
        raise ValueError('An existing Windows guest is prepared; preserve its account and setup files')
    private = ASSETS / 'private'
    private.mkdir(mode=0o700, exist_ok=True)
    if refresh:
        previous = json.loads(approved.read_text(encoding='utf-8'))
        if previous['uuid'] != plan['uuid'] or not all(previous['consent'][key] for key in ('evaluation_terms', 'guest_only_account')):
            raise ValueError('The existing Windows consent and guest identity must match')
        password = (private / 'guest-account.txt').read_text(encoding='utf-8').splitlines()[1]
    else:
        password = 'Avm!' + secrets.token_hex(14)
        (private / 'guest-account.txt').write_text('Administrator\n' + password + '\n', encoding='utf-8')
    package = io.BytesIO()
    runtime = ROOT / 'tools/python-runtime/3.13.16'
    with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in runtime.iterdir():
            if path.is_file() and path.suffix.lower() in {'.dll', '.pyd', '.exe', '.zip'}:
                archive.write(path, path.name)
        archive.writestr('python313._pth', 'python313.zip\n.\n')
    install = r'''$ErrorActionPreference = 'Stop'
$root = 'C:\ProgramData\AgenticVM'
New-Item -ItemType Directory -Path $root,'C:\workspace' -Force | Out-Null
$source = Get-Volume | Where-Object { $_.FileSystemLabel -eq 'AVMSETUP' } | Select-Object -First 1
if (-not $source.DriveLetter) { throw 'Owned setup CD was not found' }
$cd = $source.DriveLetter + ':\'
Expand-Archive -LiteralPath ($cd + 'python.zip') -DestinationPath ($root + '\python') -Force
Copy-Item -LiteralPath ($cd + 'agent.py'),($cd + 'guest.json') -Destination $root -Force
(Get-Item -LiteralPath ($root + '\agent.py')).IsReadOnly=$false
$startup = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\AgenticVM.cmd'
Set-Content -LiteralPath $startup -Value '@start "" "C:\ProgramData\AgenticVM\python\pythonw.exe" -I -B "C:\ProgramData\AgenticVM\agent.py"' -Encoding ASCII
Start-Process -FilePath ($root + '\python\pythonw.exe') -ArgumentList '-I','-B',($root + '\agent.py') -WindowStyle Hidden
'''
    first_logon = 'powershell.exe -NoProfile -NonInteractive -Command &quot;$v=Get-Volume|Where-Object FileSystemLabel -eq AVMSETUP; &amp; ($v.DriveLetter+\':\\Install.ps1\')&quot;'
    xml = '''<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
 <settings pass="windowsPE">
  <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
   <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage><InputLocale>0409:00000409</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
  </component>
  <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
   <DiskConfiguration><Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
    <CreatePartitions><CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Size>500</Size></CreatePartition><CreatePartition wcm:action="add"><Order>2</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition></CreatePartitions>
    <ModifyPartitions><ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Active>true</Active><Format>NTFS</Format><Label>System</Label></ModifyPartition><ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID><Format>NTFS</Format><Letter>C</Letter><Label>Windows</Label></ModifyPartition></ModifyPartitions>
   </Disk><WillShowUI>OnError</WillShowUI></DiskConfiguration>
   <ImageInstall><OSImage><InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>2</Value></MetaData></InstallFrom><InstallTo><DiskID>0</DiskID><PartitionID>2</PartitionID></InstallTo><WillShowUI>OnError</WillShowUI></OSImage></ImageInstall>
   <UserData><AcceptEula>true</AcceptEula><FullName>AgenticVM</FullName><Organization>Local VM</Organization></UserData>
  </component>
 </settings>
 <settings pass="specialize">
  <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><ComputerName>AgenticVM-Win</ComputerName><TimeZone>Singapore Standard Time</TimeZone></component>
 </settings>
 <settings pass="oobeSystem">
  <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><InputLocale>0409:00000409</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale></component>
  <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
   <OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>
   <UserAccounts><AdministratorPassword><Value>__PASSWORD__</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
   <AutoLogon><Password><Value>__PASSWORD__</Value><PlainText>true</PlainText></Password><Enabled>true</Enabled><LogonCount>999999</LogonCount><Username>Administrator</Username></AutoLogon>
   <FirstLogonCommands><SynchronousCommand wcm:action="add"><Order>1</Order><Description>Local guest tools</Description><CommandLine>__FIRST_LOGON__</CommandLine><RequiresUserInput>false</RequiresUserInput></SynchronousCommand></FirstLogonCommands>
  </component>
 </settings>
</unattend>'''.replace('__PASSWORD__', escape(password)).replace('__FIRST_LOGON__', first_logon)
    import xml.etree.ElementTree as ET
    ET.fromstring(xml)
    files = {'Autounattend.xml': xml.encode(), 'Install.ps1': install.encode(),
        'agent.py': (ROOT / 'guest/windows_desktop_agent.py').read_bytes(),
        'guest.json': json.dumps({'uuid': plan['uuid']}).encode(), 'python.zip': package.getvalue()}
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, vol_ident='AVMSETUP')
    try:
        for index, (name, data) in enumerate(files.items()):
            iso.add_fp(io.BytesIO(data), len(data), iso_path=f'/FILE{index}.;1', joliet_path='/' + name)
        iso.write(str(ASSETS / 'seed.iso'))
    finally:
        iso.close()
    receipt = {'schema': 'agenticvm.windows-desktop-preparation.v1', 'uuid': plan['uuid'],
        'os': plan['os'], 'consent': {'evaluation_terms': True, 'guest_only_account': True, 'recorded_at': time.time()},
        'files': {name: {'sha256': digest(ASSETS / name), 'bytes': (ASSETS / name).stat().st_size} for name in ('install.iso', 'seed.iso')},
        'guest_agent_sha256': digest(ROOT / 'guest/windows_desktop_agent.py'), 'network': 'none'}
    (ASSETS / 'prepared.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps({'prepared': True, 'receipt': str(ASSETS / 'prepared.json'), 'password_printed': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
