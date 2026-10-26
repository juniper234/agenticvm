param(
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = Join-Path $root 'dist\AgenticVM-Desktop'
$bundle = Join-Path $output 'bundle'
$python = Join-Path $root 'tools\python-runtime\3.13.16'
$qemu = Join-Path $root 'tools\qemu\11.1.0'
$desktop = Join-Path $root 'runtime\linux-desktop'

if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot 'build-desktop-app.ps1') -Clean
    if ($LASTEXITCODE -ne 0) { throw "app build failed" }
}
if (-not (Test-Path (Join-Path $output 'AgenticVM.exe'))) { throw "Missing native app build" }
foreach ($required in @(
    (Join-Path $python 'python.exe'),
    (Join-Path $qemu 'qemu-system-x86_64.exe'),
    (Join-Path $desktop 'rootfs.ext2'),
    (Join-Path $desktop 'agenticvm-linux-desktop.iso'),
    (Join-Path $root 'src\agenticvm\viewer.py'),
    (Join-Path $root 'desktop\backend_host.py')
)) {
    if (-not (Test-Path $required)) { throw "Missing payload input: $required" }
}

if (Test-Path $bundle) { Remove-Item $bundle -Recurse -Force }
New-Item -ItemType Directory -Force $bundle | Out-Null

function Copy-Tree([string]$source, [string]$target) {
    New-Item -ItemType Directory -Force $target | Out-Null
    $arguments = @($source, $target, '/E', '/NJH', '/NJS', '/NDL', '/NP', '/R:1', '/W:1')
    & robocopy @arguments | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE): $source -> $target" }
}

Copy-Tree $python (Join-Path $bundle 'python')
$pth = Join-Path $bundle 'python\python313._pth'
$pthText = Get-Content $pth -Raw
$pthText = $pthText.Replace('../../../src', '../src')
[System.IO.File]::WriteAllText($pth, $pthText, (New-Object System.Text.UTF8Encoding($false)))
Copy-Tree (Join-Path $root 'src') (Join-Path $bundle 'src')
Copy-Tree (Join-Path $root 'desktop') (Join-Path $bundle 'desktop')
Copy-Tree $qemu (Join-Path $bundle 'tools\qemu\11.1.0')
New-Item -ItemType Directory -Force (Join-Path $bundle 'runtime\linux-desktop') | Out-Null
Copy-Item (Join-Path $desktop 'rootfs.ext2') (Join-Path $bundle 'runtime\linux-desktop\rootfs.ext2')
Copy-Item (Join-Path $desktop 'agenticvm-linux-desktop.iso') (Join-Path $bundle 'runtime\linux-desktop\agenticvm-linux-desktop.iso')
Copy-Item (Join-Path $desktop 'build-manifest.json') (Join-Path $bundle 'runtime\linux-desktop\build-manifest.json')

$files = @(
    'AgenticVM.exe',
    'bundle\python\python.exe',
    'bundle\src\agenticvm\viewer.py',
    'bundle\desktop\backend_host.py',
    'bundle\tools\qemu\11.1.0\qemu-system-x86_64.exe',
    'bundle\runtime\linux-desktop\rootfs.ext2',
    'bundle\runtime\linux-desktop\agenticvm-linux-desktop.iso'
)
$pins = [ordered]@{}
foreach ($relative in $files) {
    $path = Join-Path $output $relative
    $pins[$relative] = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
}
$total = (Get-ChildItem $output -Recurse -File | Measure-Object Length -Sum).Sum
$manifest = [ordered]@{
    schema = 'agenticvm.desktop-bundle.v1'
    built_utc = (Get-Date).ToUniversalTime().ToString('o')
    portable_root = $output
    app_bytes = (Get-Item (Join-Path $output 'AgenticVM.exe')).Length
    total_files = (Get-ChildItem $output -Recurse -File).Count
    total_bytes = $total
    files = $pins
    excluded = @('rootfs.pre-freeze.ext2', 'content', 'kernel-modules', 'other lab images')
    mode = 'portable; no installer yet'
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $output 'bundle-manifest.json') -Encoding utf8
Write-Host ("Portable bundle: {0} ({1:N1} MB, {2} files)" -f $output, ($total / 1MB), (Get-ChildItem $output -Recurse -File).Count)
