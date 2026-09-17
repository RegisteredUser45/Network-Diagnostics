@echo off
setlocal
cd /d "%~dp0"

if exist "%~dp0.venv\Scripts\pythonw.exe" (
  "%~dp0.venv\Scripts\pythonw.exe" "%~dp0netdiag.py"
  goto :done
)
where pythonw >nul 2>&1
if %errorlevel%==0 (
  pythonw "%~dp0netdiag.py"
  goto :done
)
where python >nul 2>&1
if %errorlevel%==0 (
  python "%~dp0netdiag.py"
  goto :done
)

echo netDiag could not find Python.
echo Install Python 3, then either:
echo   python netdiag.py
echo or create a venv in this folder:
echo   python -m venv .venv
echo   .venv\Scripts\pip install -r requirements.txt
echo   run_netdiag.bat
pause
exit /b 1

:done
if errorlevel 1 (
  echo netDiag failed to start.
  pause
)
