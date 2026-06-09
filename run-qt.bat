@echo off
cd /d "%~dp0"
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe gui_qt\app.py %*
) else (
    python gui_qt\app.py %*
)
