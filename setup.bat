@echo off
rem ArgusGrid setup. Options are passed through: -CheckOnly  -DryRun  -AssumeYes  -WithDemo  -DatabaseUrl <url>
rem   demo package only: acts without questions (-Ask to be asked), installs what is missing, loads the demo
rem   site and starts the application. Options: -EmbeddedPython  -LocalCache <folder>  -NoDemo  -NoStart
rem   -NoBrowser  -Port <n>
rem After a fully successful setup this file deletes itself (the package must be downloaded again to repeat).
setlocal
set ARGS=%*
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
set RC=%ERRORLEVEL%
rem started by a double click (no options): keep the window open so the result can be read
if "%ARGS%"=="" pause
if not "%RC%"=="0" exit /b %RC%
if exist "%~dp0.setup-done" (
    del "%~dp0.setup-done" >nul 2>&1
    (goto) 2>nul & del "%~f0"
)
exit /b 0
