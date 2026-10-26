@echo off
setlocal
cd /d "%~dp0"
if not exist "tools\python-runtime\3.13.16\pythonw.exe" (
  echo The local Python runtime is missing.
  pause
  exit /b 1
)
"tools\python-runtime\3.13.16\pythonw.exe" -I -B "scripts\open-glass-app.py"
