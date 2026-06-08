@echo off
setlocal
cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\launch-workbench.ps1" %*
set EXIT_CODE=%ERRORLEVEL%

echo.
if not "%EXIT_CODE%"=="0" (
  echo Workbench launcher failed with exit code %EXIT_CODE%.
)

if /I not "%VPW_NO_PAUSE%"=="1" (
  pause
)

exit /b %EXIT_CODE%
