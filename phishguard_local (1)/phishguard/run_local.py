"""Start PhishGuard on THIS device only. Nothing is uploaded; the server listens on 127.0.0.1.
    python run_local.py            start the web app and open it in your browser
    python run_local.py --agent    also watch your clipboard (popup warnings)
"""
import argparse, socket, subprocess, sys, threading, time, webbrowser

def free_port(start=8000):
    for p in range(start, start + 20):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", p)) != 0: return p
    return start

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--agent", action="store_true"); ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args(); port = free_port()
    if port != 8000: print(f"Port 8000 busy, using {port}. (The browser extension expects 8000.)")
    if a.agent: subprocess.Popen([sys.executable, "agent.py", "--clipboard", "--no-save"])
    if not a.no_browser: threading.Timer(2, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=port, log_level="warning")
