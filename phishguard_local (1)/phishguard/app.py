import os, re, json, sqlite3, difflib, time, socket, ipaddress
from collections import Counter
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import tldextract

BASE = Path(__file__).parent
DB = Path(os.getenv("PHISHGUARD_DB", BASE / "cases.db"))  # history never leaves this device
app = FastAPI(title="PhishGuard")
# Local-only: just this device's own pages and the browser extension may call the API.
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
                   allow_origin_regex=r"chrome-extension://.*", allow_methods=["GET", "POST"], allow_headers=["*"])
ext_ = tldextract.TLDExtract(suffix_list_urls=())  # bundled suffix list, works offline
F = lambda c, l, p: {"category": c, "label": l, "points": p}

BRANDS = {"sbi": "sbi", "hdfc": "hdfcbank", "icici": "icicibank", "paytm": "paytm", "amazon": "amazon",
          "flipkart": "flipkart", "paypal": "paypal", "google": "google", "microsoft": "microsoft",
          "netflix": "netflix", "apple": "apple", "fedex": "fedex", "irctc": "irctc", "phonepe": "phonepe"}
TRUSTED = {"com", "in", "co.in", "org", "net", "gov.in"}
BAD_TLDS = {"xyz", "top", "tk", "click", "icu", "buzz", "gq", "ml", "cf", "ga", "work", "rest", "site", "online"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly", "is.gd", "shorturl.at"}
LEET = str.maketrans("10534", "loset")
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|rb\.gy|cutt\.ly|is\.gd)/\S+", re.I)

RULES = [  # (category, regex, points, explanation)
    ("urgency", r"\b(urgent(ly)?|immediately|within \d+ (hours?|hrs|minutes?)|expires?|expired|last chance|act now|suspended|blocked|disconnected?|today only)\b", 20, "Urgency / time-pressure language"),
    ("credentials", r"\b(kyc|verify your (account|identity|details)|update your (pan|aadhaar|account|details)|(share|send|enter|confirm) (your )?(otp|password|pin|cvv))\b", 22, "Asks for credentials, KYC or OTP"),
    ("reward", r"\b(you('ve| have)? won|lottery|congratulations|prize|cashback|reward|kbc|lucky draw)\b", 20, "Unrealistic reward / prize bait"),
    ("money", r"(processing fee|registration fee|send (rs\.?|₹)\s?\d|gift card|bitcoin|crypto|pay (the )?pending|\bupi\b.*\b(send|pay)\b)", 15, "Requests money or payment"),
    ("threat", r"\b(legal action|arrest|police|penalty|fir\b|court notice|account (will be )?(closed|frozen))\b", 15, "Threat / fear tactic"),
    ("job", r"(part[- ]time job|work from home|earn (rs\.?|₹)\s?[\d,]+\s*(/|per) ?day|like youtube videos|telegram group)", 18, "Too-good-to-be-true job offer"),
    ("friend", r"(are you free\??|emergency|urgent(ly)? need (rs\.?|₹|money))", 12, "Emergency / friend-impersonation pattern"),
    ("generic", r"\b(dear (customer|user|sir/madam|account holder))\b", 6, "Generic greeting (mass-sent)"),
    ("remote", r"\b(anydesk|teamviewer|quick ?support|rustdesk|ammyy)\b|screen ?shar(e|ing)", 28, "Asks you to install a remote-access app (lets scammers control your phone/PC)"),
    ("money", r"(advance (rs\.?|₹)?\s?\d*|pehle .{0,25}(bhej|send|jama|receive)|qr (code )?(se|scan)|collect request|scan (this|the) qr|receive karo|accept kar)", 18, "Advance / QR-code payment trick (you never need to scan or accept to RECEIVE money)"),
    ("threat", r"(viral kar|sabko bhej dunga|private video|leak (kar|your)|expose|blackmail)", 22, "Blackmail / sextortion pattern"),
    ("money", r"(registration fee|रजिस्ट्रेशन फीस|फीस जमा|पैसे भेज|भेजो|जमा करें|bhejo|jama kar)", 15, "Requests money (fee/deposit)"),
    ("job", r"(घर बैठे|रोज़ ₹|कमाएं|kamaye|ghar baithe)", 18, "Too-good-to-be-true job offer (Hindi/Hinglish)"),
    ("urgency", r"(ghante me|ghante mein|band ho jayega|band ho jaega|turant|तुरंत|बंद हो जाएगा|घंटे में)", 20, "Urgency / time-pressure language (Hinglish/Hindi)"),
    ("reward", r"(badhai ho|jeeta hai|inaam|बधाई|इनाम|जीता)", 20, "Prize bait (Hinglish/Hindi)"),
    ("money", r"(bhejein|upi kar|transfer kar|shulk|भेजें|शुल्क|ट्रांसफर)", 15, "Requests money (Hinglish/Hindi)"),
]

MODEL = None
def mask(t):
    """Hide URLs and numbers so the ML learns wording only (URLs are scored by the URL engine)."""
    return re.sub(r"\d+", "0", re.sub(r"(?:https?://|www\.)\S+|\b(?:bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly|is\.gd)/\S+", " URL ", t))

def load_model():
    """Trains on data/seed.csv + data/train.csv (any column order; columns named text,label or label,text)."""
    global MODEL
    try:
        import pandas as pd
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        parts = []
        for n in ("seed.csv", "train.csv"):
            f = BASE / "data" / n
            if not f.exists(): continue
            d = pd.read_csv(f, encoding="utf-8", encoding_errors="replace")
            if {"text", "label"} <= set(d.columns): d = d[["label", "text"]]
            else: d = d.iloc[:, :2]; d.columns = ["label", "text"]
            parts.append(d)
        d = pd.concat(parts).dropna()
        y = d.label.astype(str).str.lower().isin(["spam", "1", "phishing", "scam"])
        MODEL = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True),
                              LogisticRegression(max_iter=1000, class_weight="balanced", C=3)).fit(d.text.astype(str).map(mask), y)
        print("ML model trained on", len(d), "rows")
    except Exception as e:
        print("ML model skipped:", e)
load_model()

def domain_age_days(domain):
    try:
        import whois
        c = whois.whois(domain).creation_date
        c = c[0] if isinstance(c, list) else c
        return (time.time() - c.timestamp()) / 86400
    except Exception:
        return None

def _public(host):
    try: return all(ipaddress.ip_address(a[4][0]).is_global for a in socket.getaddrinfo(host, None))
    except Exception: return False

def unmask(url, hops=5):
    """Follow redirects safely (public hosts only, no body download) and return the chain."""
    chain = [url]
    try:
        import httpx
        with httpx.Client(timeout=4, follow_redirects=False, headers={"User-Agent": "Mozilla/5.0"}) as c:
            for _ in range(hops):
                if not _public(urlparse(chain[-1]).hostname or ""): break
                with c.stream("GET", chain[-1]) as r:
                    loc = r.headers.get("location")
                    if r.status_code in (301, 302, 303, 307, 308) and loc: chain.append(str(httpx.URL(chain[-1]).join(loc)))
                    else: break
    except Exception: pass
    return chain

def analyze_url(u, deep=False):
    f = []
    url = u if u.lower().startswith("http") else "http://" + u
    p = urlparse(url); host = (p.hostname or "").lower(); e = ext_(host)
    raw, norm = e.domain, e.domain.translate(LEET)
    if p.scheme != "https": f.append(F("url", "Link does not use HTTPS", 8))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): f.append(F("url", "Uses a raw IP address instead of a domain", 25))
    if "@" in p.netloc: f.append(F("url", "Contains '@' trick that hides the real destination", 25))
    if e.registered_domain in SHORTENERS: f.append(F("url", f"URL shortener ({e.registered_domain}) hides the destination", 15))
    if e.suffix in BAD_TLDS: f.append(F("url", f"Frequently abused TLD (.{e.suffix})", 10))
    if host.startswith("xn--") or ".xn--" in host: f.append(F("url", "Punycode (possible look-alike characters)", 20))
    if e.subdomain.count(".") >= 2: f.append(F("url", "Excessive subdomains", 10))
    if raw.count("-") >= 2: f.append(F("url", "Many hyphens in domain", 8))
    if len(url) > 75: f.append(F("url", "Unusually long URL", 5))
    if re.search(r"(login|verify|secure|update|kyc|account)", p.path.lower()) and e.registered_domain not in SHORTENERS:
        f.append(F("url", "Sensitive keyword in URL path", 6))
    genuine = any(raw == off and e.suffix in TRUSTED for off in BRANDS.values())
    if not genuine:
        for k, off in BRANDS.items():
            if norm == off and raw != off: f.append(F("url", f"Look-alike of '{off}' using character swaps", 35)); break
            elif k in norm and k not in raw: f.append(F("url", f"Look-alike of brand '{k}' using character swaps (e.g. 1 for l)", 35)); break
            elif k in raw or k in e.subdomain: f.append(F("url", f"Uses brand '{k}' in a domain the brand doesn't own", 32)); break
            elif raw != off and difflib.SequenceMatcher(None, raw, off).ratio() >= 0.85: f.append(F("url", f"Typosquat of '{off}'", 30)); break
    meta = {}
    if deep and e.registered_domain:
        age = domain_age_days(e.registered_domain)
        if age is not None:
            meta["domain_age_days"] = int(age)
            if age < 30: f.append(F("metadata", f"Domain registered only {int(age)} days ago", 30))
            elif age < 180: f.append(F("metadata", f"Young domain ({int(age)} days old)", 15))
    if deep and host:
        ch = unmask(url)
        if len(ch) > 1:
            meta["chain"] = ch
            if ext_(urlparse(ch[-1]).hostname or "").registered_domain != e.registered_domain:
                fin = analyze_url(ch[-1], False)
                f.append(F("redirect", f"Redirects to {fin['domain']}", 12 + min(25, sum(x["points"] for x in fin["factors"]) // 2)))
    return {"url": u, "domain": e.registered_domain or host, "label": raw, "factors": f, "meta": meta}

def check_headers(msg):
    f = []; name, addr = parseaddr(msg.get("From", "")); d = ext_(addr.split("@")[-1])
    for k, off in BRANDS.items():
        if k in name.lower() and d.domain != off:
            f.append(F("header", f"Sender name says '{name}' but address is from {d.registered_domain}", 30)); break
    _, ra = parseaddr(msg.get("Reply-To", ""))
    if ra and ext_(ra.split("@")[-1]).registered_domain != d.registered_domain:
        f.append(F("header", "Reply-To domain differs from sender domain", 15))
    return f

SCAM_TYPES = [  # name, Hindi name, regex, tip, Hindi tip
 ("Bank / KYC phishing", "बैंक / KYC फ़िशिंग", r"kyc|verify your|\botp\b|\bpin\b|bank|net ?banking|account (is )?(blocked|suspended)", "Banks never ask for OTP, PIN or KYC through links or SMS. Call the number printed on your card.", "बैंक कभी लिंक या SMS पर OTP, PIN, KYC नहीं मांगता। कार्ड पर छपे नंबर पर कॉल करें।"),
 ("Lottery / prize scam", "लॉटरी / इनाम ठगी", r"lottery|prize|\bwon\b|kbc|cashback|reward|lucky", "You cannot win a contest you never entered, and real prizes never need a fee.", "जिस प्रतियोगिता में भाग नहीं लिया उसमें इनाम नहीं मिलता, और असली इनाम के लिए फीस नहीं लगती।"),
 ("Utility disconnection scam", "बिजली / बिल ठगी", r"electricity|disconnect|power cut|\bgas\b|water|\bbill\b", "Check dues only in the official provider app or website, never via the number in the message.", "बिल सिर्फ आधिकारिक ऐप/वेबसाइट पर जांचें, मैसेज में दिए नंबर पर नहीं।"),
 ("Parcel / courier scam", "पार्सल / कूरियर ठगी", r"parcel|courier|customs|delivery fee|package|fedex|india post", "Track parcels only on the courier's official site. Never pay a 'release fee' from a message.", "पार्सल सिर्फ कूरियर की आधिकारिक साइट पर ट्रैक करें। मैसेज से 'रिलीज़ फीस' न दें।"),
 ("Fake job / task scam", "फ़र्ज़ी जॉब / टास्क ठगी", r"\bjob\b|work from home|earn|telegram|youtube", "Genuine employers never charge you or pay for liking videos. Do not join the group.", "असली कंपनियां पैसे नहीं मांगतीं और वीडियो लाइक करने के पैसे नहीं देतीं। ग्रुप से न जुड़ें।"),
 ("Friend-in-need impersonation", "दोस्त बनकर ठगी", r"are you free|emergency|send on this upi|need (money|rs|₹)", "Call the person on their known number to confirm before sending any money.", "पैसे भेजने से पहले उस व्यक्ति को उसके पुराने नंबर पर कॉल करके पुष्टि करें।"),
 ("Tax-refund / government scam", "टैक्स / सरकारी ठगी", r"income tax|refund|aadhaar|pan card|police|arrest|court", "Government departments never demand payment or details over SMS, WhatsApp or calls.", "सरकारी विभाग SMS, WhatsApp या कॉल पर पैसे या जानकारी नहीं मांगते।"),
]
def classify(text, score, has_url):
    if score < 15: return None
    best, n = None, 0
    for name, hi, pat, tip, tip_hi in SCAM_TYPES:
        c = len(re.findall(pat, text))
        if c > n: best, n = {"name": name, "hi": hi, "tip": tip, "tip_hi": tip_hi}, c
    if not best and (has_url or score >= 35):
        best = {"name": "Suspicious link / phishing", "hi": "संदिग्ध लिंक / फ़िशिंग", "tip": "Do not open the link. Type the official site address yourself instead.", "tip_hi": "लिंक न खोलें। आधिकारिक साइट का पता खुद टाइप करें।"}
    return best

LEVELS = [(15, "Safe"), (35, "Low"), (60, "Medium"), (80, "High"), (101, "Critical")]
WARN = {"Safe": "No strong scam indicators found. Stay cautious with unexpected requests.",
        "Low": "A few minor warning signs. Double-check the sender before acting.",
        "Medium": "Suspicious. Do not click links or share details until you verify through an official channel.",
        "High": "Likely a scam. Do NOT click links, reply, or share OTP/PIN/payment details.",
        "Critical": "Almost certainly phishing/scam. Do not interact. Report it (cybercrime.gov.in / 1930) and delete."}

def email_body(msg):
    """Plain text of an email, including multipart and HTML-only mails (link targets are kept)."""
    try:
        part = msg.get_body(preferencelist=("plain", "html"))
        if not part: return ""
        b = part.get_content()
        if part.get_content_type() == "text/html":
            links = re.findall(r"href=[\"'](https?://[^\"']+)", b)
            b = re.sub(r"<[^>]+>", " ", b) + "\n" + "\n".join(links)
        return b
    except Exception:
        return str(msg.get_payload())

# ---------- Verdict, extent of risk and what-to-do plan ----------
VERDICT = {"Safe": ("Not malicious", "सुरक्षित"), "Low": ("Probably not malicious", "शायद सुरक्षित"),
           "Medium": ("Suspicious", "संदिग्ध"), "High": ("Malicious (likely a scam)", "हानिकारक (संभावित ठगी)"),
           "Critical": ("Malicious", "हानिकारक")}
# which kinds of harm each signal category points to: (English, Hindi)
HARM = {"credentials": ("Your account / identity (OTP, PIN, password, KYC details)", "आपका खाता / पहचान (OTP, PIN, पासवर्ड, KYC)"),
        "money": ("Your money (direct payment demanded)", "आपका पैसा (सीधे भुगतान की मांग)"),
        "reward": ("Your money (fake prize that asks for a fee)", "आपका पैसा (फीस मांगने वाला फ़र्ज़ी इनाम)"),
        "job": ("Your money and personal data (task / job scam)", "आपका पैसा और डेटा (टास्क / जॉब ठगी)"),
        "friend": ("Your money (someone pretending to be a friend or relative)", "आपका पैसा (दोस्त/रिश्तेदार बनकर ठगी)"),
        "threat": ("Your peace of mind (fear tactics to force a quick payment)", "मानसिक दबाव (डराकर जल्दी पैसे ऐंठना)"),
        "url": ("Your device and logins (the link may steal passwords or install malware)", "आपका डिवाइस और लॉगिन (लिंक पासवर्ड चुरा सकता है या मैलवेयर डाल सकता है)"),
        "redirect": ("Your device and logins (the link redirects somewhere else)", "आपका डिवाइस और लॉगिन (लिंक कहीं और भेजता है)"),
        "impersonation": ("Trust in a brand (it pretends to be a company you know)", "किसी ब्रांड के नाम पर धोखा"),
        "remote": ("Your whole device and bank apps (remote-access tools give scammers full control)", "आपका पूरा डिवाइस और बैंक ऐप (रिमोट-एक्सेस से ठग पूरा नियंत्रण पा लेते हैं)"),
        "combo": ("Your money or identity (the message follows a known scam pattern)", "आपका पैसा या पहचान (मैसेज जाने-पहचाने ठगी पैटर्न जैसा है)"),
        "header": ("Trust in the sender (the sender is faked)", "भेजने वाला नकली है")}
ACTIONS = {  # level -> (English steps, Hindi steps): do these NOW
 "Safe": (["No action needed. Still, never share OTP/PIN with anyone."], ["कोई कार्रवाई ज़रूरी नहीं। फिर भी OTP/PIN किसी से साझा न करें।"]),
 "Low": (["Do not click anything yet. Confirm the sender through an official app, website or known number.", "If you were not expecting it, ignore it."],
         ["अभी कुछ क्लिक न करें। आधिकारिक ऐप, वेबसाइट या जाने-पहचाने नंबर से भेजने वाले की पुष्टि करें।", "अगर आप इसकी उम्मीद नहीं कर रहे थे तो अनदेखा करें।"]),
 "Medium": (["Do not click links, open attachments or reply.", "Verify by opening the official app/website yourself (type the address, do not use the message).", "If it is from a bank, call the number printed on your card.", "If still unsure, ask a family member or ignore it."],
            ["लिंक/अटैचमेंट न खोलें और जवाब न दें।", "आधिकारिक ऐप/वेबसाइट खुद खोलकर जांचें (पता खुद टाइप करें, मैसेज वाला लिंक नहीं)।", "बैंक का मैसेज हो तो कार्ड पर छपे नंबर पर कॉल करें।", "फिर भी शक हो तो परिवार के किसी सदस्य से पूछें या अनदेखा करें।"]),
 "High": (["Do NOT click, reply, or share any OTP/PIN/password/payment.", "Block the sender and delete the message.", "Report the number/email: Sanchar Saathi (Chakshu) and cybercrime.gov.in.", "Warn family or friends who may have received the same message."],
          ["क्लिक, जवाब या OTP/PIN/पासवर्ड/भुगतान बिल्कुल न दें।", "भेजने वाले को ब्लॉक करें और मैसेज डिलीट करें।", "नंबर/ईमेल रिपोर्ट करें: संचार साथी (चक्षु) और cybercrime.gov.in।", "परिवार और दोस्तों को भी सावधान करें।"]),
 "Critical": (["Do NOT interact with it in any way. Do not click, reply or call back.", "Block the sender, then delete the message.", "Report it: call 1930 or visit cybercrime.gov.in, and report the number on Sanchar Saathi (Chakshu).", "Warn others: this looks like a mass-sent scam."],
              ["किसी भी तरह जवाब न दें: क्लिक, रिप्लाई या कॉलबैक न करें।", "भेजने वाले को ब्लॉक करें, फिर मैसेज डिलीट करें।", "रिपोर्ट करें: 1930 पर कॉल करें या cybercrime.gov.in पर जाएं, और नंबर संचार साथी (चक्षु) पर रिपोर्ट करें।", "दूसरों को सावधान करें: यह बड़े पैमाने पर भेजी गई ठगी लगती है।"])}
IF_ACTED = {  # what you already did -> (English steps, Hindi steps)
 "clicked": (["Close the page immediately. Do not enter anything on it.", "If you typed a password anywhere, change it now (and on any site where you reuse it), then turn on 2-step verification.", "If you downloaded or installed anything, disconnect from the internet, uninstall it and run a full antivirus scan.", "Check your bank/UPI for unknown activity."],
             ["पेज तुरंत बंद करें। उसमें कुछ भी न भरें।", "अगर कहीं पासवर्ड डाला है तो तुरंत बदलें (और जहां वही पासवर्ड इस्तेमाल है वहां भी), फिर 2-स्टेप वेरिफिकेशन चालू करें।", "अगर कुछ डाउनलोड/इंस्टॉल हुआ है तो इंटरनेट बंद करें, उसे हटाएं और पूरा एंटीवायरस स्कैन करें।", "अपने बैंक/UPI में अनजान लेन-देन जांचें।"]),
 "shared_otp": (["Call your bank's official number NOW and ask them to block the card / UPI / net banking.", "Change your net banking and UPI PIN.", "Report at 1930 or cybercrime.gov.in as soon as possible. Money reported quickly can often be frozen."],
                ["अभी बैंक के आधिकारिक नंबर पर कॉल करके कार्ड/UPI/नेटबैंकिंग ब्लॉक करवाएं।", "नेटबैंकिंग और UPI PIN बदलें।", "जल्द से जल्द 1930 या cybercrime.gov.in पर रिपोर्ट करें। जल्दी रिपोर्ट करने पर पैसा अक्सर रोका जा सकता है।"]),
 "paid": (["Call your bank immediately and report a fraudulent transaction.", "Call 1930 right away (the faster, the higher the chance of freezing the money) and file at cybercrime.gov.in.", "Keep screenshots, transaction IDs and the message as evidence. Do not send any more money, even for a 'refund'."],
          ["तुरंत बैंक को कॉल करके धोखाधड़ी की सूचना दें।", "अभी 1930 पर कॉल करें (जितनी जल्दी, पैसा रुकने की संभावना उतनी ज़्यादा) और cybercrime.gov.in पर शिकायत करें।", "स्क्रीनशॉट, ट्रांज़ेक्शन ID और मैसेज सबूत के तौर पर रखें। 'रिफंड' के नाम पर भी और पैसे न भेजें।"])}

def assess(level, score, factors, scam_type, has_url):
    """Turn raw signals into: a verdict, how far the risk reaches, and what the user should do."""
    cats = {f["category"] for f in factors}
    harms = [{"en": HARM[c][0], "hi": HARM[c][1]} for c in HARM if c in cats]
    rule_cats = cats & {"remote", "urgency", "credentials", "reward", "money", "threat", "job", "friend", "generic"}
    indep = sum([bool(rule_cats), bool(cats & {"url", "redirect", "metadata"}), bool(cats & {"header", "impersonation"}), "ml" in cats])
    conf = "n/a" if level == "Safe" else "High" if indep >= 3 or score >= 80 else "Medium" if indep == 2 or score >= 35 else "Low"
    extent = {"severity": level, "score": score, "confidence": conf, "independent_checks_flagged": indep,
              "at_risk": harms if level != "Safe" else [],
              "summary": {"Safe": "No meaningful harm expected.",
                          "Low": "Limited risk if you do nothing. Harm is only possible if you act on it.",
                          "Medium": "Real risk if you click, reply or share details. Nothing happens if you don't.",
                          "High": "High risk: acting on this message could lead to financial loss or account takeover.",
                          "Critical": "Severe risk: this has the hallmarks of an active scam. Acting on it can cause serious loss."}[level]}
    bad = level in ("Medium", "High", "Critical")
    now_en, now_hi = ACTIONS[level]
    steps = {"en": list(now_en), "hi": list(now_hi)}
    if scam_type and bad: steps["en"].insert(1, scam_type["tip"]); steps["hi"].insert(1, scam_type["tip_hi"])
    acted = {}
    if bad:
        keys = ["clicked"] if has_url else []
        keys += ["shared_otp"] if cats & {"credentials", "header", "impersonation"} else []
        keys += ["paid"] if cats & {"money", "reward", "job", "friend", "threat"} else []
        if not keys: keys = ["clicked", "shared_otp", "paid"]
        titles = {"clicked": ("If you already clicked the link", "अगर आप लिंक खोल चुके हैं"),
                  "shared_otp": ("If you already shared an OTP, PIN or password", "अगर आप OTP, PIN या पासवर्ड दे चुके हैं"),
                  "paid": ("If you already sent money", "अगर आप पैसे भेज चुके हैं")}
        acted = {k: {"title": {"en": titles[k][0], "hi": titles[k][1]}, "en": IF_ACTED[k][0], "hi": IF_ACTED[k][1]} for k in keys}
    return {"verdict": {"label": VERDICT[level][0], "hi": VERDICT[level][1], "malicious": level in ("High", "Critical"),
                        "suspicious": bad}, "extent": extent, "actions": steps, "if_already_acted": acted}

def analyze(text, deep=False):
    msg, body = None, text
    if re.match(r"\s*(from|subject|reply-to|to|date):", text, re.I):
        msg = Parser(policy=policy.default).parsestr(text.strip())
        body = msg.get("subject", "") + "\n" + email_body(msg)
    factors, spans = [], []
    if msg: factors += check_headers(msg)
    for cat, pat, pts, label in RULES:
        ms = [m.group(0) for m in re.finditer(pat, body, re.I)]
        if ms: factors.append(F(cat, label, pts)); spans += ms
    cats_now = {x["category"] for x in factors}
    if cats_now & {"money", "credentials"} and len(cats_now & {"urgency", "reward", "threat", "job", "friend", "money", "credentials", "remote"}) >= 2:
        factors.append(F("combo", "Classic scam combination: pressure/bait together with a demand for money or credentials", 15))
    urls = [analyze_url(u.rstrip(".,);"), deep) for u in dict.fromkeys(URL_RE.findall(text))]
    for u in urls: factors += u["factors"]
    low = body.lower()
    for k, off in BRANDS.items():
        if re.search(rf"\b{k}\b", low) and urls and not any(u["label"] == off for u in urls):
            factors.append(F("impersonation", f"Mentions '{k.upper()}' but links point elsewhere", 25)); spans.append(k); break
    if MODEL and len(body.strip()) > 10:
        pr = float(MODEL.predict_proba([mask(body)])[0][1])
        if pr > 0.55: factors.append(F("ml", f"ML classifier: {int(pr*100)}% scam-like wording", int(pr * 30)))
    score = min(100, sum(x["points"] for x in factors))
    level = next(n for t, n in LEVELS if score < t)
    kind = "email" if msg else ("url" if urls and len(text.split()) == 1 else "message")
    st = classify(low + " " + " ".join(u["url"].lower() for u in urls), score, bool(urls))
    return {"type": kind, "score": score, "level": level, "warning": WARN[level],
            "factors": sorted(factors, key=lambda x: -x["points"]), "highlights": list(dict.fromkeys(spans)), "urls": urls,
            "scam_type": st, **assess(level, score, factors, st, bool(urls))}

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, ts TEXT, type TEXT, text TEXT, score INT, level TEXT, factors TEXT, urls TEXT, stype TEXT)")
    try: c.execute("ALTER TABLE cases ADD COLUMN stype TEXT")
    except sqlite3.OperationalError: pass
    return c

class Req(BaseModel):
    text: str
    deep: bool = False

@app.post("/api/analyze")
def api_analyze(r: Req):
    res = analyze(r.text, r.deep)
    with db() as c:
        cur = c.execute("INSERT INTO cases(ts,type,text,score,level,factors,urls,stype) VALUES(?,?,?,?,?,?,?,?)",
                        (time.strftime("%Y-%m-%d %H:%M:%S"), res["type"], r.text[:1000], res["score"], res["level"],
                         json.dumps(res["factors"]), json.dumps([u["domain"] for u in res["urls"]]), (res["scam_type"] or {}).get("name", "")))
    return {**res, "id": cur.lastrowid}

@app.get("/api/check")  # lightweight endpoint for a future browser extension
def api_check(url: str):
    r = analyze(url); return {"level": r["level"], "score": r["score"], "warning": r["warning"], "verdict": r["verdict"]["label"]}

@app.get("/api/history")
def history(q: str = "", level: str = ""):
    sql, a = "SELECT * FROM cases WHERE 1=1", []
    if q: sql += " AND (text LIKE ? OR urls LIKE ?)"; a += [f"%{q}%"] * 2
    if level: sql += " AND level=?"; a.append(level)
    with db() as c:
        rows = c.execute(sql + " ORDER BY id DESC LIMIT 200", a).fetchall()
    return [{**dict(r), "factors": json.loads(r["factors"]), "urls": json.loads(r["urls"])} for r in rows]

@app.get("/api/stats")
def stats():
    with db() as c: rows = c.execute("SELECT ts,level,urls,type,stype FROM cases").fetchall()
    alld = Counter(d for r in rows if r["level"] != "Safe" for d in json.loads(r["urls"]))
    doms = Counter(d for r in rows if r["level"] in ("Medium", "High", "Critical") for d in json.loads(r["urls"]))
    return {"total": len(rows), "levels": Counter(r["level"] for r in rows), "types": Counter(r["type"] for r in rows),
            "daily": sorted(Counter(r["ts"][:10] for r in rows).items())[-7:], "top_domains": doms.most_common(5),
            "scam_types": Counter(r["stype"] for r in rows if r["stype"]).most_common(),
            "campaigns": [(d, n) for d, n in alld.most_common(5) if n >= 2]}

NEXT = {"Critical": "Delete it, block the sender, and report it (1930 / cybercrime.gov.in). Do not click or reply.",
        "High": "Do not click or reply. Block the sender and report it.",
        "Medium": "Verify through the official app, website or number on your card before acting.",
        "Low": "Double-check the sender before acting.",
        "Safe": "No action needed."}
TIPS = {t[0]: t[3] for t in SCAM_TYPES}

class Bulk(BaseModel):
    messages: list[str]

@app.post("/api/bulk")
def api_bulk(r: Bulk):
    msgs = [m.strip() for m in r.messages if m and m.strip()][:200]
    out = []
    with db() as c:
        for t in msgs:
            res = analyze(t)
            st = (res["scam_type"] or {}).get("name", "")
            c.execute("INSERT INTO cases(ts,type,text,score,level,factors,urls,stype) VALUES(?,?,?,?,?,?,?,?)",
                      (time.strftime("%Y-%m-%d %H:%M:%S"), res["type"], t[:1000], res["score"], res["level"],
                       json.dumps(res["factors"]), json.dumps([u["domain"] for u in res["urls"]]), st))
            out.append({"text": t[:300], "score": res["score"], "level": res["level"], "scam_type": st,
                        "reasons": [f["label"] for f in res["factors"][:3]], "next": NEXT[res["level"]],
                        "domains": [u["domain"] for u in res["urls"]]})
    out.sort(key=lambda x: -x["score"])
    lv = Counter(x["level"] for x in out)
    types = Counter(x["scam_type"] for x in out if x["scam_type"] and x["level"] != "Safe")
    doms = Counter(d for x in out if x["level"] != "Safe" for d in set(x["domains"]))
    camp = [(d, n) for d, n in doms.most_common(5) if n >= 2]
    hi, med = lv["Critical"] + lv["High"], lv["Medium"]
    recs = []
    if hi: recs.append(f"{hi} message(s) are High/Critical risk. Do not click links or reply; delete them and block the senders.")
    if hi: recs.append("If you already clicked a link or shared an OTP/PIN/password: change your passwords, call your bank to block cards/UPI, and report at 1930 or cybercrime.gov.in right away.")
    if med: recs.append(f"{med} message(s) are Medium risk. Verify through the official app, website or the number printed on your card before acting.")
    if camp: recs.append("Repeated domains found (" + ", ".join(f"{d} x{n}" for d, n in camp) + "). This looks like one campaign: report each domain once with all the examples as evidence.")
    if types:
        top = types.most_common(1)[0][0]; recs.append(f"Most common scam type: {top}. {TIPS.get(top, '')}")
    if hi or med: recs.append("Report suspicious SMS, calls and WhatsApp numbers on the Sanchar Saathi portal (Chakshu) so they can be blocked.")
    if out and not (hi or med): recs.append("No serious threats found. Stay alert for unexpected requests for money, OTPs or links.")
    return {"summary": {"total": len(out), "levels": lv, "campaigns": camp}, "recommendations": recs, "results": out}

@app.get("/")
def index(): return FileResponse(BASE / "static" / "index.html")
