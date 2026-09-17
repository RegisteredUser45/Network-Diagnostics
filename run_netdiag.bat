@echo off
setlocal
cd /d "%~dp0"
"%~dp0.venv\Scripts\pythonw.exe" "%~dp0netdiag.py"
if errorlevel 1 (
  echo netDiag failed to start.
  pause
)
