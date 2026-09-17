@echo off
setlocal
rem One UAC prompt: allow CDP/LLDP capture without Administrator every time.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

reg query "HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters" /v AdminOnly >nul 2>&1
if errorlevel 1 (
  echo Npcap does not appear to be installed.
  echo Install from https://npcap.com with WinPcap API-compatible Mode enabled
  echo and "Restrict Npcap driver's access to Administrators only" unchecked.
  pause
  exit /b 1
)

reg add "HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters" /v AdminOnly /t REG_DWORD /d 0 /f
if errorlevel 1 (
  echo Failed to set Npcap AdminOnly=0.
  pause
  exit /b 1
)

echo Npcap Admin-only is now OFF. Start netDiag normally.
pause
