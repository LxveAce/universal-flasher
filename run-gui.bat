@echo off
cd /d "%~dp0"
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe gui\app.py %*
) else (
    python gui\app.py %*
)
