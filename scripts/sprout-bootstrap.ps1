# Embedded in the native one-file installer. No network or administrator writes.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.IO.Compression
$self = $env:AGARDEN_INSTALLER_SELF
$expected = '__PAYLOAD_SHA256__'
# A stable user-profile path also works outside a packaged desktop parent.
# LocalApplicationData can be redirected into Codex's MSIX LocalCache.
$base = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.agenticvm\Garden-v1'
$root = Join-Path $base $expected.Substring(0,16)
function Assert-Plain([string]$path) {
    $probe = [IO.Path]::GetFullPath($path)
    while ($probe) {
        if ([IO.File]::Exists($probe) -or [IO.Directory]::Exists($probe)) {
            if (([IO.File]::GetAttributes($probe) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Redirected installation path refused' }
        }
        $parent = [IO.Path]::GetDirectoryName($probe)
        if ($parent -eq $probe) { break }
        $probe = $parent
    }
}
function Hash-File([string]$path) {
    $stream = [IO.File]::OpenRead($path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','').ToLowerInvariant() }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}
Assert-Plain $base
[IO.Directory]::CreateDirectory($base) | Out-Null
$lockPath = Join-Path $base 'install.lock'
$guard = [IO.File]::Open($lockPath,'OpenOrCreate','ReadWrite','None')
$archive = $null
$reader = $null
$zipPath = Join-Path $base ('payload-'+[guid]::NewGuid().ToString('N')+'.zip')
try {
    Write-Host 'Sprout: checking the included runtime...'
    $inputFile = [IO.File]::OpenRead($self)
    try {
        if ($inputFile.Length -lt 24) { throw 'Incomplete sprout file' }
        [void]$inputFile.Seek(-24,'End')
        $footer = New-Object byte[] 24
        if ($inputFile.Read($footer,0,24) -ne 24 -or [Text.Encoding]::ASCII.GetString($footer,0,16) -ne 'AGARDEN-PAYLOAD1') { throw 'Invalid sprout footer' }
        $length = [BitConverter]::ToInt64($footer,16)
        if ($length -lt 1 -or $length -gt 1500000000 -or $length -gt $inputFile.Length-24) { throw 'Invalid sprout payload size' }
        [void]$inputFile.Seek($inputFile.Length-24-$length,'Begin')
        $out = [IO.File]::Open($zipPath,'CreateNew','Write','None')
        $hash = [Security.Cryptography.SHA256]::Create()
        try {
            $buffer = New-Object byte[] 1048576
            $remaining = $length
            while ($remaining -gt 0) {
                $count = $inputFile.Read($buffer,0,[int][Math]::Min($remaining,$buffer.Length))
                if ($count -le 0) { throw 'Truncated sprout payload' }
                $out.Write($buffer,0,$count)
                [void]$hash.TransformBlock($buffer,0,$count,$buffer,0)
                $remaining -= $count
            }
            [void]$hash.TransformFinalBlock((New-Object byte[] 0),0,0)
            $actual = [BitConverter]::ToString($hash.Hash).Replace('-','').ToLowerInvariant()
            if ($actual -ne $expected) { throw 'Sprout payload integrity check failed' }
        } finally { $out.Dispose(); $hash.Dispose() }
    } finally { $inputFile.Dispose() }
    $reader = [IO.File]::OpenRead($zipPath)
    $archive = New-Object IO.Compression.ZipArchive($reader,[IO.Compression.ZipArchiveMode]::Read)
    $entry = $archive.GetEntry('sprout-manifest.json')
    if ($null -eq $entry -or $entry.Length -gt 1000000) { throw 'Missing sprout manifest' }
    $textReader = New-Object IO.StreamReader($entry.Open())
    try { $manifest = $textReader.ReadToEnd() | ConvertFrom-Json } finally { $textReader.Dispose() }
    if ($manifest.schema -ne 'agenticvm.sprout.v1' -or $archive.Entries.Count -ne $manifest.files.Count+1) { throw 'Sprout inventory mismatch' }
    Assert-Plain $root
    $fresh = -not [IO.Directory]::Exists($root)
    $finalRoot = $root
    if ($fresh) {
        $root = Join-Path $base ('installing-'+[guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($root) | Out-Null
        Write-Host 'Installing into your user folder...'
    }
    $names = @{}
    foreach ($item in $manifest.files) {
        $name = [string]$item.path
        if ($name -notmatch '^[a-zA-Z0-9_./ +\-]+$' -or $name.Contains('..') -or $name.StartsWith('/') -or $names.ContainsKey($name)) { throw 'Unsafe sprout inventory path' }
        $names[$name] = $true
        $file = $archive.GetEntry($name)
        if ($null -eq $file -or $file.Length -ne $item.bytes -or $file.Length -gt 1500000000) { throw 'Sprout entry mismatch' }
        $target = Join-Path $root $name.Replace('/','\')
        Assert-Plain $target
        if ($fresh) {
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
            $source = $file.Open()
            $destination = [IO.File]::Open($target,'CreateNew','Write','None')
            try { $source.CopyTo($destination,1048576) } finally { $source.Dispose(); $destination.Dispose() }
        }
        if (-not [IO.File]::Exists($target) -or ([IO.FileInfo]$target).Length -ne $item.bytes -or (Hash-File $target) -ne $item.sha256) { throw ('Installed runtime changed: '+$name) }
    }
    if ($fresh) { [IO.Directory]::Move($root,$finalRoot); $root=$finalRoot }
    $installed = @{ schema='agenticvm.sprout-install.v1'; payload_sha256=$expected; verified_files=$manifest.files.Count; installed_root=$root; administrator_required=$false; system_features_changed=$false; one_file_entry=$self; verified_at_utc=[DateTime]::UtcNow.ToString('o') }
    $installed | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'installation.json') -Encoding UTF8
    Write-Host 'Installation verified. Joining the local garden...'
} finally {
    if ($null -ne $archive) { $archive.Dispose() }
    if ($null -ne $reader) { $reader.Dispose() }
    if ([IO.File]::Exists($zipPath)) { [IO.File]::Delete($zipPath) }
    $guard.Dispose()
}
& (Join-Path $root 'tools\python\python.exe') -I -B (Join-Path $root 'scripts\run-garden.py')
exit $LASTEXITCODE
