# PhishGuard
AI-based phishing, scam message and malicious URL detection (IEEE-IGNITE SKIT025).
## Run on your own device (private, nothing leaves your computer)
Windows: double-click `start.bat`. Mac/Linux: `./start.sh`. First run installs everything.
Paste a message into the page, or copy any message anywhere and the clipboard agent pops up a warning.
Each result gives a verdict (malicious or not), how far the risk reaches, and what to do now, plus what to do if you already clicked, shared an OTP or paid.
Manual: `pip install -r requirements.txt` then `python run_local.py`.
## Browser extension (pre-click warnings)
Chrome > chrome://extensions > Developer mode > Load unpacked > select `extension/`. Keep the server running.
## Improve the ML model
Add more labeled rows to `data/seed.csv`, or drop the SMS Spam Collection as `data/train.csv` (label,text), then restart.
## API
POST /api/analyze {text, deep} · GET /api/check?url= · GET /api/history?q=&level= · GET /api/stats
