@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-dbglink.ps1" %*
exit /b %ERRORLEVEL%
