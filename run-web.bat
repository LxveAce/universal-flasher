@echo off
cd /d "%~dp0"
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe web\app.py %*
) else (
    python web\app.py %*
)
