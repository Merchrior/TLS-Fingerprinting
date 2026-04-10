@echo off
cd /d %~dp0

echo Starting Docker app...
docker compose up -d --build

echo Starting host capture agent...
start "TLS Host Capture Agent" cmd /k python host_capture_agent.py

echo Opening dashboard...
start http://localhost:8501

pause