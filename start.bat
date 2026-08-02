@echo off
chcp 65001 >nul
title RE-Nexus / YAZAN Elite System - 29 Engine
cd /d "%~dp0"

echo ============================================
echo   RE-Nexus / YAZAN Elite System (29 engines)
echo   http://127.0.0.1:8787/
echo   اضغط Ctrl+C للإيقاف
echo ============================================

where python >nul 2>nul
if errorlevel 1 (
    echo [خطأ] Python غير مثبت أو غير موجود في PATH.
    echo [Error] Python not found. Install Python 3.9+ and retry.
    pause
    exit /b 1
)

python -c "import flask, werkzeug, psutil, cryptography" >nul 2>nul
if errorlevel 1 (
    echo [تنبيه] المكتبات غير مثبتة — جاري التثبيت...
    echo [Info] Installing dependencies from requirements.txt...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [خطأ] فشل تثبيت المكتبات. شغّل يدوياً: pip install -r requirements.txt
        pause
        exit /b 1
    )
)

set HOST=127.0.0.1
set PORT=8787
python -m app.server
pause
