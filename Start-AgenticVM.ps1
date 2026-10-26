# Compatibility entry point for the native glass app; -NoBrowser starts the service only.
param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$pythonPath = Join-Path $PSScriptRoot 'tools\python-runtime\3.13.16\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    throw 'The bundled Python runtime is missing. Use the complete AgenticVM folder.'
}
$entryPoint = if ($NoBrowser) { 'scripts\start-control-service.py' } else { 'scripts\open-glass-app.py' }
& $pythonPath -I -B (Join-Path $PSScriptRoot $entryPoint)
exit $LASTEXITCODE
