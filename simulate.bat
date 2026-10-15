@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0simulate.ps1" %*
if not defined ARGUS_NO_PAUSE if "%~1"=="" pause
exit /b %ERRORLEVEL%
