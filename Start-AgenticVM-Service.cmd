@echo off
cd /d "%~dp0"
"%~dp0tools\python-runtime\3.13.16\python.exe" -I -B "%~dp0scripts\start-control-service.py"
