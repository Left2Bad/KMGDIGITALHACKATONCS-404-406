@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Demo.ps1"
if errorlevel 1 (
  echo.
  echo Ошибка запуска. Прочитайте сообщение выше или откройте .run\*.err.log
  pause
  exit /b 1
)
start "" "http://127.0.0.1:5207/"
start "" "http://127.0.0.1:8000/"
echo Открыты оба проекта. Это окно можно закрыть.
pause
