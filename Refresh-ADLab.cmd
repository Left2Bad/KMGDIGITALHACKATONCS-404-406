@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Complete-ADLab.ps1"
if errorlevel 1 (
  echo Ошибка подготовки AD. Откройте .run\ad-lab-setup.log
  pause
  exit /b 1
)
echo Тестовый AD и свежий скан готовы.
pause
