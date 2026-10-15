"""PhishGuard local agent: watches your clipboard and/or an email inbox and warns you about scams.
Everything runs on THIS device. Nothing is sent anywhere. Reuses the same ML + rules + URL engine as the web app.

  python agent.py --clipboard              copy any message (WhatsApp Web, SMS mirror, Telegram...) to check it
  python agent.py --email                  watch your inbox (set IMAP_USER and IMAP_PASS first)
  python agent.py --clipboard --email      both
Suspicious items are saved to cases.db, so they show up in the web app's History and Dashboard.
"""
import argparse, email, html, imaplib, json, os, re, sys, threading, time
from email import policy
import app  # same engine as the web app, no server needed

LEVELS = ["Safe", "Low", "Medium", "High", "Critical"]

def notify(title, msg):
    try:
        from plyer import notification
        notification.notify(title=title, message=msg[:250], app_name="PhishGuard", timeout=12)
    except Exception:
        print(f"\a[ALERT] {title}: {msg}")

NO_SAVE = False

def handle(text, source, min_level):
    res = app.analyze(text)
    print(f"[{source}] {res['level']} ({res['score']}) {text[:60]!r}")
    if res["level"] == "Safe":
        return res  # privacy: safe items are never stored
    st = (res["scam_type"] or {}).get("name", "")
    with app.db() as c:
        if not NO_SAVE: c.execute("INSERT INTO cases(ts,type,text,score,level,factors,urls,stype) VALUES(?,?,?,?,?,?,?,?)",
                  (time.strftime("%Y-%m-%d %H:%M:%S"), source, text[:300], res["score"], res["level"],
                   json.dumps(res["factors"]), json.dumps([u["domain"] for u in res["urls"]]), st))
    if LEVELS.index(res["level"]) >= LEVELS.index(min_level):
        why = "; ".join(f["label"] for f in res["factors"][:2])
        notify(f"PhishGuard: {res['verdict']['label']} - {res['level']} risk ({res['score']}/100)",
               f"{st or 'Suspicious message'}. {why}. Do now: {res['actions']['en'][0]}")
    return res

def email_text(raw):
    m = email.message_from_bytes(raw, policy=policy.default)
    head = f"From: {m.get('From', '')}\n" + (f"Reply-To: {m['Reply-To']}\n" if m.get("Reply-To") else "") + f"Subject: {m.get('Subject', '')}\n\n"
    part, body = m.get_body(preferencelist=("plain", "html")), ""
    if part:
        body = part.get_content()
        if part.get_content_type() == "text/html":
            links = re.findall(r"href=[\"'](https?://[^\"']+)", body)
            body = html.unescape(re.sub(r"<[^>]+>", " ", body)) + "\n" + "\n".join(links)
    return head + body

def watch_clipboard(min_level):
    import pyperclip
    last = pyperclip.paste()
    print("Watching clipboard. Copy any message to check it. Ctrl+C to stop.")
    while True:
        try: cur = pyperclip.paste()
        except Exception: cur = last
        t = cur.strip()
        if cur != last and len(t) >= 12 and (" " in t or "http" in t):  # skips passwords/single tokens
            handle(t, "agent-clipboard", min_level)
        last = cur; time.sleep(1)

def watch_email(min_level, every):
    host, user, pw = os.getenv("IMAP_HOST", "imap.gmail.com"), os.getenv("IMAP_USER"), os.getenv("IMAP_PASS")
    if not (user and pw): sys.exit("Set IMAP_USER and IMAP_PASS first (use an app password, not your main password).")
    seen = set(); print(f"Watching inbox of {user} every {every}s (read-only; mail stays unread).")
    while True:
        try:
            M = imaplib.IMAP4_SSL(host); M.login(user, pw); M.select("INBOX", readonly=True)
            _, d = M.uid("search", None, "UNSEEN")
            for uid in d[0].split()[-20:]:
                if uid in seen: continue
                seen.add(uid)
                _, data = M.uid("fetch", uid, "(BODY.PEEK[])")
                handle(email_text(data[0][1]), "agent-email", min_level)
            M.logout()
        except Exception as e: print("Email check failed:", e)
        time.sleep(every)

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="PhishGuard local agent")
    p.add_argument("--clipboard", action="store_true"); p.add_argument("--email", action="store_true")
    p.add_argument("--min-level", default="Medium", choices=LEVELS[1:], help="lowest level that triggers a popup")
    p.add_argument("--interval", type=int, default=60, help="email check interval in seconds")
    p.add_argument("--no-save", action="store_true", help="never store checked text in cases.db")
    a = p.parse_args(); NO_SAVE = a.no_save
    if not (a.clipboard or a.email): a.clipboard = True
    try:
        if a.email: threading.Thread(target=watch_email, args=(a.min_level, a.interval), daemon=True).start()
        if a.clipboard: watch_clipboard(a.min_level)
        else:
            while True: time.sleep(3600)
    except KeyboardInterrupt: print("Stopped.")
