"""Owner-scoped Windows Setup inputs for a fresh disposable SATA disk only."""
from __future__ import annotations
import base64
import hashlib
import json
import re
import secrets
from uuid import UUID
import xml.etree.ElementTree as ET

from .lan_lab import ROOT, digest


def inputs(run_id, target_uuid, mother_certificate, administrator_password, *, route='windows-unattend',
           install_token=None):
    if (route != 'windows-unattend' or str(UUID(run_id)) != run_id or str(UUID(target_uuid)) != target_uuid
            or not re.fullmatch(r'[A-Za-z0-9!@_+-]{20,64}', administrator_password)):
        raise ValueError('Explicit owned Windows setup scope and bounded fixture password required')
    if install_token is None:
        install_token = secrets.token_urlsafe(32)
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,64}', install_token):
        raise ValueError('Bounded provisioning token required')
    runtime = json.loads((ROOT / 'runtime/enrollment-images/windows-application-runtime.json').read_text())['assets']['python']
    if digest(ROOT / runtime['path']) != runtime['sha256']:
        raise ValueError('Pinned Windows Python dependency changed')
    image = json.loads((ROOT / 'runtime/enrollment-images/windows-installer/manifest.json').read_text())['selected_image']
    if image['installation_type'] != 'Server Core' or image['architecture'] != '9':
        raise ValueError('Explicit x64 Server Core evaluation selection required')

    trust = {'garden': run_id, 'target_uuid': target_uuid, 'route': route,
        'mother_certificate': mother_certificate, 'installer_sha256': digest(ROOT / 'guest/windows_install.py'),
        'install_token': install_token}
    prep = r'''$ErrorActionPreference = 'Stop'
try { Add-Content -LiteralPath 'C:\GardenPrep.log' -Value 'prep-start' -Encoding ASCII } catch {}
if ((Get-CimInstance Win32_ComputerSystemProduct).UUID.ToLower() -ne 'TARGET_UUID') {throw 'Wrong owned Windows VM'}
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {throw 'SYSTEM setup context required'}
$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$control = 'C:\Program Files\GardenControl'
if (Test-Path -LiteralPath $control -PathType Leaf) { Remove-Item -LiteralPath $control -Force }
New-Item -ItemType Directory -Force -Path $control | Out-Null
$archive = Join-Path $source 'windows-python.zip'
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLower() -ne 'PYTHON_SHA256') {throw 'Python dependency hash mismatch'}
Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $control 'python') -Force
if (-not (Test-Path -LiteralPath (Join-Path $control 'python\python.exe'))) {throw 'Pinned Python did not expand'}
try { Add-Content -LiteralPath 'C:\GardenPrep.log' -Value 'python-expanded' -Encoding ASCII } catch {}
foreach ($name in @('trust.json','windows_bootstrap.py','GardenActivate.ps1')) {
    Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $control $name) -Force
}
& icacls.exe $control /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' /T /Q | Out-Null
if ($LASTEXITCODE -eq 0) { Add-Content -LiteralPath 'C:\GardenPrep.log' -Value 'acl-granted' -Encoding ASCII }
Get-ChildItem -LiteralPath $control -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
& attrib.exe -R (Join-Path $control '*') /S /D | Out-Null
try { Add-Content -LiteralPath 'C:\GardenPrep.log' -Value 'acl-set' -Encoding ASCII } catch {}
# Always rerun activation after a repair; bootstrap is duplicate-safe.
Remove-Item -LiteralPath (Join-Path $control 'activated') -Force -ErrorAction SilentlyContinue
& (Join-Path $control 'GardenActivate.ps1')
'''.replace('TARGET_UUID', target_uuid).replace('PYTHON_SHA256', runtime['sha256'])
    activate = r'''$ErrorActionPreference = 'Stop'
$control = 'C:\Program Files\GardenControl'
$owned = $false
function Write-LabSerial([string]$marker, $value) {
    $serial = New-Object IO.Ports.SerialPort 'COM1',115200,'None',8,'One'
    try {$serial.Open(); $serial.WriteLine($marker + ' ' + ($value | ConvertTo-Json -Depth 5 -Compress))}
    finally {$serial.Close(); $serial.Dispose()}
}
try {
    $uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID.ToLower()
    if ($uuid -ne 'TARGET_UUID') {throw 'Wrong owned Windows VM'}
    $owned = $true
    try { Add-Content -LiteralPath ($control + '\activate.log') -Value 'activate-start' -Encoding ASCII } catch {}
    $marker = Join-Path $control 'activated'
    if (Test-Path -LiteralPath $marker) { exit 0 }
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $adapters = @(Get-NetAdapter | Where-Object {$_.MacAddress -eq '52-54-00-4C-41-04'})
        if ($adapters.Count -eq 1) {break}
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($adapters.Count -ne 1) {throw 'The single owner-scoped native network adapter was not found'}
    $index = $adapters[0].InterfaceIndex
    Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Disabled
    Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
    Get-NetRoute -InterfaceIndex $index -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false
    New-NetIPAddress -InterfaceIndex $index -IPAddress '192.0.2.4' -PrefixLength 24 | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses
    $os = Get-CimInstance Win32_OperatingSystem
    Write-LabSerial 'WINDOWS_OS_PREPARED' @{uuid=$uuid; os=$os.Caption; build=$os.BuildNumber; garden='RUN_UUID'}
    $python = Join-Path $control 'python\python.exe'
    $code = -1
    $diag = @{}
    try {
        $diag.attributes = (Get-Item -LiteralPath $python).Attributes.ToString()
        $diag.acl = (icacls.exe $python | Out-String).Trim()
        $diag.signature = (Get-AuthenticodeSignature -LiteralPath $python).Status.ToString()
        $cmdOut = & cmd.exe /c ('"' + $python + '" -V 2>&1')
        $diag.cmd_exit = $LASTEXITCODE
        $diag.cmd_out = (($cmdOut | Out-String).Trim())
    } catch {
        $diag.probe_error = $_.Exception.Message
    }
    Write-LabSerial 'WINDOWS_PYTHON_DIAG' $diag
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $env:GARDEN_CONTROL = $control
            $bootOut = & $python -I -B (Join-Path $control 'windows_bootstrap.py') 2>&1
            $code = $LASTEXITCODE
            $ErrorActionPreference = $previous
            if ($code -eq 0) { break }
            Write-LabSerial 'WINDOWS_BOOTSTRAP_FAILED' @{code=$code; output=(($bootOut | Out-String).Trim())}
        } catch {
            $ErrorActionPreference = $previous
            Write-LabSerial 'WINDOWS_BOOTSTRAP_LAUNCH_ERROR' @{attempt=$attempt; error=$_.Exception.Message}
            if ($attempt -eq 5) { $code = -1; break }
        }
        Start-Sleep -Seconds 2
    }
    if ($code -ne 0) {
        try {
            $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | ConvertTo-Json -Compress -Depth 3
            Write-LabSerial 'WINDOWS_ACTIVATION_POLICY' @{python=$python; code=$code; policy=$policy}
        } catch {}
        throw 'The reviewed Windows bootstrap failed; inspect native serial evidence'
    }
    try { Add-Content -LiteralPath ($control + '\activate.log') -Value 'bootstrap-ok' -Encoding ASCII } catch {}
    New-Item -ItemType File -Path $marker -Force | Out-Null
} catch {
    try { Add-Content -LiteralPath ($control + '\activate.log') -Value ('activate-failed ' + $_.Exception.Message) -Encoding ASCII } catch {}
    if ($owned) {Write-LabSerial 'WINDOWS_PREPARATION_FAILED' @{error=$_.Exception.Message; uuid=$uuid}}
    exit 1
}
'''.replace('TARGET_UUID', target_uuid).replace('RUN_UUID', run_id)
    setup = (b'@echo off\r\ncall "%~dp0GardenPrep.cmd"\r\n'
             b'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "%~dp0GardenActivate.ps1"\r\n'
             b'exit /b %errorlevel%\r\n')
    files = {
        'GardenSetup.cmd': setup,
        'GardenPrep.cmd': b'@echo off\r\npowershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "%~dp0GardenPrep.ps1"\r\nexit /b %errorlevel%\r\n',
        'GardenPrep.ps1': prep.encode(), 'GardenActivate.ps1': activate.encode(),
        'trust.json': json.dumps(trust).encode(), 'windows_bootstrap.py': (ROOT / 'guest/windows_bootstrap.py').read_bytes(),
        'windows-python.zip': (ROOT / runtime['path']).read_bytes()}
    want = base64.b64encode(json.dumps(
        {name: hashlib.sha256(value).hexdigest() for name, value in files.items()}, sort_keys=True).encode()).decode()
    seed = r'''$ErrorActionPreference = 'Stop'
$Source = $PSScriptRoot
$want = @{}
(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__WANT__')))|ConvertFrom-Json).psobject.Properties|%{$want[$_.Name]=$_.Value}
$dst = 'C:\Windows\Setup\Scripts'
$ok = $true
foreach ($name in $want.Keys) {
    $path = Join-Path $Source $name
    if (-not (Test-Path -LiteralPath $path)) { $ok = $false; break }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() -ne $want[$name]) { $ok = $false; break }
}
if (-not $ok) { exit 1 }
New-Item -ItemType Directory -Force -Path $dst | Out-Null
foreach ($name in $want.Keys) {
    Copy-Item -LiteralPath (Join-Path $Source $name) -Destination (Join-Path $dst $name) -Force
}
Copy-Item -LiteralPath (Join-Path $dst 'GardenSetup.cmd') -Destination (Join-Path $dst 'SetupComplete.cmd') -Force
exit 0
'''.replace('__WANT__', want)
    files['G.ps1'] = seed.encode()
    seed_hash = hashlib.sha256(seed.encode()).hexdigest()
    selector = (
        "$h='" + seed_hash.upper() + "';"
        "foreach($d in 'D','E','F','G','H'){"
        "$p=$d+':\\G.ps1';"
        "if((Get-FileHash $p).Hash -eq $h){& $p;exit 0}};exit 1")
    setup_copy = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + selector + '"'

    ns, wcm = 'urn:schemas-microsoft-com:unattend', 'http://schemas.microsoft.com/WMIConfig/2002/State'
    ET.register_namespace('', ns)
    ET.register_namespace('wcm', wcm)
    root = ET.Element('{' + ns + '}unattend')
    def add(parent, name, value=None, *, action=False):
        node = ET.SubElement(parent, '{' + ns + '}' + name)
        if value is not None:
            node.text = str(value)
        if action:
            node.set('{' + wcm + '}action', 'add')
        return node
    def component(parent, name):
        node = add(parent, 'component')
        node.attrib.update(name=name, processorArchitecture='amd64', publicKeyToken='31bf3856ad364e35',
                           language='neutral', versionScope='nonSxS')
        return node
    pe = add(root, 'settings')
    pe.set('pass', 'windowsPE')
    international = component(pe, 'Microsoft-Windows-International-Core-WinPE')
    add(add(international, 'SetupUILanguage'), 'UILanguage', 'en-US')
    for name, value in {'InputLocale': '0409:00000409', 'SystemLocale': 'en-US', 'UILanguage': 'en-US', 'UserLocale': 'en-US'}.items():
        add(international, name, value)
    setup_component = component(pe, 'Microsoft-Windows-Setup')
    configuration = add(setup_component, 'DiskConfiguration')
    disk = add(configuration, 'Disk', action=True)
    add(disk, 'DiskID', '0')
    add(disk, 'WillWipeDisk', 'true')
    partitions = add(disk, 'CreatePartitions')
    for order, size in ((1, '500'), (2, None)):
        partition = add(partitions, 'CreatePartition', action=True)
        add(partition, 'Order', order)
        add(partition, 'Type', 'Primary')
        add(partition, 'Size' if size else 'Extend', size if size else 'true')
    modifications = add(disk, 'ModifyPartitions')
    for index, label in ((1, 'System'), (2, 'Windows')):
        change = add(modifications, 'ModifyPartition', action=True)
        add(change, 'Order', index)
        add(change, 'PartitionID', index)
        add(change, 'Format', 'NTFS')
        add(change, 'Label', label)
        add(change, 'Active' if index == 1 else 'Letter', 'true' if index == 1 else 'C')
    add(configuration, 'WillShowUI', 'OnError')
    osimage = add(add(setup_component, 'ImageInstall'), 'OSImage')
    metadata = add(add(osimage, 'InstallFrom'), 'MetaData', action=True)
    add(metadata, 'Key', '/IMAGE/INDEX')
    add(metadata, 'Value', image['index'])
    destination = add(osimage, 'InstallTo')
    add(destination, 'DiskID', '0')
    add(destination, 'PartitionID', '2')
    add(osimage, 'WillShowUI', 'OnError')
    user = add(setup_component, 'UserData')
    add(user, 'AcceptEula', 'true')
    add(user, 'FullName', 'Garden Lab')
    add(user, 'Organization', 'Owned isolated evaluation lab')
    specialize = add(root, 'settings')
    specialize.set('pass', 'specialize')
    shell = component(specialize, 'Microsoft-Windows-Shell-Setup')
    add(shell, 'ComputerName', 'Garden-' + target_uuid[:8])
    add(shell, 'TimeZone', 'UTC')
    deployment = component(specialize, 'Microsoft-Windows-Deployment')
    run_sync = add(deployment, 'RunSynchronous')
    command = add(run_sync, 'RunSynchronousCommand', action=True)
    add(command, 'Order', '1')
    add(command, 'Description', 'Install the hash-verified post-OOBE garden preparation entry point')
    add(command, 'Path', setup_copy)
    add(command, 'WillReboot', 'Never')
    privacy = add(run_sync, 'RunSynchronousCommand', action=True)
    add(privacy, 'Order', '2')
    add(privacy, 'Description', 'Suppress the Server 2025 OOBE privacy prompt with the documented policy')
    add(privacy, 'Path', r'reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE /v DisablePrivacyExperience /t REG_DWORD /d 1 /f')
    add(privacy, 'WillReboot', 'Never')
    oobe = add(root, 'settings')
    oobe.set('pass', 'oobeSystem')
    shell = component(oobe, 'Microsoft-Windows-Shell-Setup')
    add(add(shell, 'OOBE'), 'HideEULAPage', 'true')
    passwords = add(shell, 'UserAccounts')
    password = add(passwords, 'AdministratorPassword')
    add(password, 'Value', administrator_password)
    add(password, 'PlainText', 'true')
    autologon = add(shell, 'AutoLogon')
    add(autologon, 'Password', administrator_password)
    add(autologon, 'Username', 'Administrator')
    add(autologon, 'Enabled', 'true')
    add(autologon, 'LogonCount', '1')
    oobe_deployment = component(oobe, 'Microsoft-Windows-Deployment')
    oobe_command = add(add(oobe_deployment, 'RunSynchronous'), 'RunSynchronousCommand', action=True)
    add(oobe_command, 'Order', '1')
    add(oobe_command, 'Description', 'Reinstall the hash-verified preparation entry point before first logon')
    add(oobe_command, 'Path', setup_copy)
    add(oobe_command, 'WillReboot', 'Never')
    files['Autounattend.xml'] = ET.tostring(root, encoding='utf-8', xml_declaration=True)
    return files
