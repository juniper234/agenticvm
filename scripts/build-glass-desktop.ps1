param([string]$Output = 'dist/AgenticVM-Glass')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$dotnet = Join-Path $projectRoot 'tools\dotnet\sdk\dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet)) { throw 'The local .NET 9 SDK is missing.' }
$env:DOTNET_CLI_HOME = Join-Path $projectRoot 'tools\dotnet\home'
$env:NUGET_PACKAGES = Join-Path $projectRoot 'tools\nuget-packages'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$env:TEMP = Join-Path $projectRoot 'runtime\build-temp'
$env:TMP = $env:TEMP
$env:APPDATA = Join-Path $projectRoot 'runtime\build-appdata'
$env:LOCALAPPDATA = Join-Path $projectRoot 'runtime\build-localappdata'
foreach ($folder in @($env:TEMP,$env:APPDATA,$env:LOCALAPPDATA)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
$config = Join-Path $projectRoot 'tools\NuGet.Config'
& $dotnet restore 'desktop/AgenticVM.Desktop/AgenticVM.Desktop.csproj' --configfile $config --nologo
if ($LASTEXITCODE -ne 0) { throw 'Desktop restore failed.' }
& $dotnet build 'desktop/AgenticVM.Desktop/AgenticVM.Desktop.csproj' --no-restore -c Release -o $Output --nologo -v minimal
if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed.' }
