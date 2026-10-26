param(
    [switch]$Clean
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dotnet = Join-Path $root 'tools\dotnet\sdk\dotnet.exe'
$project = Join-Path $root 'desktop\AgenticVM.Desktop\AgenticVM.Desktop.csproj'
$output = Join-Path $root 'dist\AgenticVM-Desktop'
$env:DOTNET_CLI_HOME = Join-Path $root 'tools\dotnet\home'
$env:NUGET_PACKAGES = Join-Path $root 'tools\nuget-packages'
$env:TEMP = Join-Path $root 'tools\dotnet\tmp'
$env:TMP = $env:TEMP
$env:APPDATA = Join-Path $root 'tools\dotnet\appdata'
$env:LOCALAPPDATA = Join-Path $root 'tools\dotnet\localappdata'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
New-Item -ItemType Directory -Force $env:DOTNET_CLI_HOME, $env:NUGET_PACKAGES, $env:TEMP, $env:APPDATA, $env:LOCALAPPDATA | Out-Null
if ($Clean -and (Test-Path $output)) {
    Remove-Item $output -Recurse -Force
}
& $dotnet publish $project -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=false -p:PublishReadyToRun=false -o $output --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with $LASTEXITCODE" }
$exe = Join-Path $output 'AgenticVM.exe'
if (-not (Test-Path $exe)) { throw "Missing $exe" }
Write-Host "Built: $exe"
