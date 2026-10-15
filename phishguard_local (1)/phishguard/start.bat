@echo off
cd /d "%~dp0"
if not exist .venv (
  echo First run: setting up, this takes a minute...
  python -m venv .venv
  .venv\Scripts\python -m pip install -q -r requirements.txt -r requirements-agent.txt
)
.venv\Scripts\python run_local.py --agent
