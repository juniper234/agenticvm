@echo off
cd /d "%~dp0"
echo Starting temporary HTTPS access to your enabled DeepSeek companion.
echo Keep this window running. The private connection file is saved in your DSH profile.
rem This host launcher needs normal user-profile writes; the guest-tool Python runs at low integrity.
"%LOCALAPPDATA%\Programs\Python\Python313\python.exe" -I -B "%~dp0scripts\deepseek-remote.py" --start
pause
