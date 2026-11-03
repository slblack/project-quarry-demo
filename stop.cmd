@echo off
rem Double-click to stop the Project Quarry demo (runs stop.ps1 next to this file).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop.ps1" %*
echo.
pause
