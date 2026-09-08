@echo off
rem CtYun keepalive daemon: restart 10s after crash, log to keepalive.log
cd /d "%~dp0"
:loop
echo [%date% %time%] keepalive.py start >> keepalive.log
"C:\Users\Administrator\AppData\Roaming\kimi-desktop\daimon-share\daimon\runtime\python\.venv\Scripts\python.exe" keepalive.py >> keepalive.log 2>&1
echo [%date% %time%] keepalive.py exit code %errorlevel%, restart in 10s >> keepalive.log
"C:\Users\Administrator\AppData\Roaming\kimi-desktop\daimon-share\daimon\runtime\python\.venv\Scripts\python.exe" -c "import time;time.sleep(10)"
goto loop
