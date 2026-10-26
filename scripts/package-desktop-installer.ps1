param(
    [switch]$SkipPayload
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dotnet = Join-Path $root 'tools\dotnet\sdk\dotnet.exe'
$env:DOTNET_CLI_HOME = Join-Path $root 'tools\dotnet\home'
$env:NUGET_PACKAGES = Join-Path $root 'tools\nuget-packages'
$env:TEMP = Join-Path $root 'tools\dotnet\tmp'
$env:TMP = $env:TEMP
$env:APPDATA = Join-Path $root 'tools\dotnet\appdata'
$env:LOCALAPPDATA = Join-Path $root 'tools\dotnet\localappdata'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$app = Join-Path $root 'dist\AgenticVM-Desktop'
$out = Join-Path $root 'dist\AgenticVM-Setup'
$payload = Join-Path $out 'payload\AgenticVM'
$project = Join-Path $root 'desktop\AgenticVM.Setup\AgenticVM.Setup.csproj'
if (-not (Test-Path (Join-Path $app 'bundle-manifest.json'))) {
    throw "Portable app bundle is missing. Run scripts\package-desktop-app.ps1 first."
}
if (Get-Process AgenticVM -ErrorAction SilentlyContinue) {
    throw "Close AgenticVM before packaging the installer."
}
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Force $out | Out-Null
& $dotnet publish $project -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=false -p:PublishReadyToRun=false -o $out --nologo
if ($LASTEXITCODE -ne 0) { throw "setup publish failed" }
if (-not $SkipPayload) {
    New-Item -ItemType Directory -Force (Split-Path $payload) | Out-Null
    $arguments = @($app, $payload, '/E', '/NJH', '/NJS', '/NDL', '/NP', '/R:1', '/W:1',
        '/XD', (Join-Path $app 'bundle\runtime\desktop-app'), '/XF', 'viewer-ready.json')
    & robocopy @arguments | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "payload copy failed ($LASTEXITCODE)" }
}
$payloadBytes = (Get-ChildItem $payload -Recurse -File | Measure-Object Length -Sum).Sum
$setupExe = Join-Path $out 'AgenticVM-Setup.exe'
if (-not (Test-Path $setupExe)) { throw "Missing $setupExe" }
$manifest = [ordered]@{
    schema = 'agenticvm.desktop-setup.v1'
    built_utc = (Get-Date).ToUniversalTime().ToString('o')
    setup_exe = 'AgenticVM-Setup.exe'
    setup_sha256 = (Get-FileHash $setupExe -Algorithm SHA256).Hash.ToLower()
    payload = 'payload\AgenticVM'
    payload_bytes = $payloadBytes
    payload_files = (Get-ChildItem $payload -Recurse -File).Count
    install_mode = 'per-user copy; no admin; shortcut; no service/firewall changes'
    silent_usage = 'AgenticVM-Setup.exe --silent [--install-dir=PATH] [--no-shortcuts]'
    limits = @('Folder installer; not a single-file self-extractor', 'Unsigned', 'Installer requires the payload folder beside setup.exe')
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $out 'setup-manifest.json') -Encoding utf8
Write-Host ("Installer: {0} ({1:N0} MB payload, {2} files)" -f $setupExe, ($payloadBytes / 1MB), $manifest.payload_files)
