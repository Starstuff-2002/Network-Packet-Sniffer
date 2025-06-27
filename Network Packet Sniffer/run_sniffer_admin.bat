@echo off
msg * "The sniffer requires admin privileges. Please allow the popup to continue."
set "SCRIPT_PATH=%~dp0Network Packet Sniffing.py"
set "PYTHON_PATH=%LocalAppData%\Programs\Python\Python312\python.exe"

powershell -Command "Start-Process '%PYTHON_PATH%' -ArgumentList '%SCRIPT_PATH%' -Verb RunAs"
pause
