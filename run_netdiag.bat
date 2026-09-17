@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "VENV=%~dp0.venv"
set "VENV_PY=%VENV%\Scripts\python.exe"
set "VENV_PYW=%VENV%\Scripts\pythonw.exe"
set "REQ=%~dp0requirements.txt"

goto :main

:find_python
set "SYS_PY="
where py >nul 2>&1
if %errorlevel%==0 (
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
  if %errorlevel%==0 (
    set "SYS_PY=py -3"
    exit /b 0
  )
)
where python >nul 2>&1
if %errorlevel%==0 (
  python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
  if %errorlevel%==0 (
    set "SYS_PY=python"
    exit /b 0
  )
)
exit /b 1

:ensure_venv
if exist "%VENV_PY%" exit /b 0
echo First run: creating local Python environment (.venv)...
call :find_python
if errorlevel 1 (
  echo.
  echo Python 3.10 or newer is not installed, or it is not on PATH.
  echo Install it from https://www.python.org/downloads/
  echo During setup, check "Add python.exe to PATH".
  echo Then double-click run_netdiag.bat again.
  echo.
  pause
  exit /b 1
)
%SYS_PY% -m venv "%VENV%"
if errorlevel 1 (
  echo Failed to create .venv
  pause
  exit /b 1
)
if not exist "%VENV_PY%" (
  echo venv was created but python.exe is missing.
  pause
  exit /b 1
)
exit /b 0

:ensure_deps
"%VENV_PY%" -c "import serial, scapy" >nul 2>&1
if %errorlevel%==0 exit /b 0
echo Installing packages from requirements.txt...
if not exist "%REQ%" (
  echo requirements.txt not found in this folder.
  pause
  exit /b 1
)
"%VENV_PY%" -m pip install --disable-pip-version-check -r "%REQ%"
if errorlevel 1 (
  echo pip install failed.
  pause
  exit /b 1
)
"%VENV_PY%" -c "import serial" >nul 2>&1
if errorlevel 1 (
  echo pyserial did not import after install.
  pause
  exit /b 1
)
exit /b 0

:ensure_tk
"%VENV_PY%" -c "import tkinter" >nul 2>&1
if %errorlevel%==0 exit /b 0
echo.
echo This Python install has no tkinter (GUI library).
echo Install Python from https://www.python.org/downloads/
echo ^(not the Microsoft Store stub^), then delete the .venv folder
echo in this directory and run this file again.
echo.
pause
exit /b 1

:read_venv_created
set "VENV_CREATED=0"
if not exist "%~dp0settings.json" exit /b 0
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $j = Get-Content -Raw -LiteralPath '%~dp0settings.json' | ConvertFrom-Json; if ([int](('0' + $j.venv_created))) { exit 1 } else { exit 0 } } catch { exit 0 }"
if errorlevel 1 set "VENV_CREATED=1"
exit /b 0

:mark_venv_created
"%VENV_PY%" "%~dp0netdiag.py" --mark-venv-created
exit /b 0

:main
call :read_venv_created
if "%VENV_CREATED%"=="1" if exist "%VENV_PY%" goto :after_setup

call :ensure_venv
if errorlevel 1 exit /b 1
call :ensure_deps
if errorlevel 1 exit /b 1
call :ensure_tk
if errorlevel 1 exit /b 1
call :mark_venv_created

:after_setup
if not exist "%VENV_PY%" (
  echo .venv is missing. Set venv_created to 0 in settings.json and run again.
  pause
  exit /b 1
)

echo Creating desktop shortcut...
"%VENV_PY%" "%~dp0netdiag.py" --install-shortcut
if errorlevel 1 (
  echo Shortcut could not be created. Starting anyway.
)

echo Starting netDiag...
if exist "%VENV_PYW%" (
  start "" "%VENV_PYW%" "%~dp0netdiag.py"
) else (
  "%VENV_PY%" "%~dp0netdiag.py"
)
