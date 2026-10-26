@echo off
cd /d "%~dp0"
"%LOCALAPPDATA%\Programs\Python\Python313\python.exe" -I -B "%~dp0scripts\deepseek-remote.py" --stop
pause
