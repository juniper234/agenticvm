# Checkout launcher; does not install packages or change machine-wide settings.
$ErrorActionPreference = 'Stop'
$controllerPython = $null
foreach ($candidate in @((Join-Path $PSScriptRoot 'tools\python\python.exe'), (Join-Path $PSScriptRoot 'tools\python-runtime\3.13.16\python.exe'))) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $controllerPython = $candidate; break }
}
if (-not $controllerPython) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) { throw 'Python is missing. Use the complete AgenticVM portable folder, or prepare its local Python runtime.' }
    $controllerPython = $pythonCommand.Source
}
$priorPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = (Join-Path $PSScriptRoot 'src') + [IO.Path]::PathSeparator + $priorPath
    Push-Location -LiteralPath $PSScriptRoot
    try { & $controllerPython -B -m agenticvm @args; $controllerExit = $LASTEXITCODE }
    finally { Pop-Location }
} finally { $env:PYTHONPATH = $priorPath }
exit $controllerExit
