#!/bin/sh
cd "$(dirname "$0")"
[ -d .venv ] || { python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt -r requirements-agent.txt; }
.venv/bin/python run_local.py --agent
