@echo off
cd /d "C:\Users\gelly\Downloads\phishguard\phishguard"
start /b py app.py
start /b cloudflared tunnel --url http://localhost:5000