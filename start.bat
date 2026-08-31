@echo off
REM =====================================================
REM  Nuclei GUI  Windows 本地启动脚本（开发 / 测试用）
REM =====================================================
cd /d "%~dp0"
echo [*] Nuclei GUI  (Windows)
echo [*] 访问地址: http://127.0.0.1:8333/
python app.py %*
if errorlevel 1 pause
