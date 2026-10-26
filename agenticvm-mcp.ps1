# Local stdio MCP launcher. No global registration or package installation.
$ErrorActionPreference = 'Stop'
$serverPython = $null
foreach ($candidate in @((Join-Path $PSScriptRoot 'tools\python\python.exe'), (Join-Path $PSScriptRoot 'tools\python-runtime\3.13.16\python.exe'))) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $serverPython = $candidate; break }
}
if (-not $serverPython) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) { throw 'Python is missing. Use the complete AgenticVM portable folder, or prepare its local Python runtime.' }
    $serverPython = $pythonCommand.Source
}
$priorPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = (Join-Path $PSScriptRoot 'src') + [IO.Path]::PathSeparator + $priorPath
    Push-Location -LiteralPath $PSScriptRoot
    try { & $serverPython -B -m agenticvm.mcp @args; $serverExit = $LASTEXITCODE }
    finally { Pop-Location }
} finally { $env:PYTHONPATH = $priorPath }
exit $serverExit
