const cache = new Map(), RISKY = ["Medium", "High", "Critical"];
const check = url => cache.has(url) ? Promise.resolve(cache.get(url)) :
  new Promise(res => chrome.runtime.sendMessage({ url }, r => { cache.set(url, r); res(r); }));
function el(tag, css, text) { const e = document.createElement(tag); if (css) e.style.cssText = css; if (text) e.textContent = text; return e; }
function overlay(a, r) {
  const o = el("div", "position:fixed;inset:0;background:#000c;z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:system-ui");
  const box = el("div", "background:#1e293b;color:#e2e8f0;padding:28px;border-radius:14px;max-width:460px;border-top:6px solid #ef4444");
  box.append(el("h2", "margin:0 0 8px", "⚠️ PhishGuard warning"),
    el("b", "", `${r.verdict || "Suspicious"} · ${r.level} risk (${r.score}/100)`),
    el("p", "", r.warning),
    el("p", "word-break:break-all;color:#94a3b8;font-size:13px", a.href));
  const back = el("button", "background:#38bdf8;border:0;padding:10px 16px;border-radius:8px;font-weight:600;cursor:pointer", "Go back to safety");
  const go = el("button", "background:none;border:1px solid #475569;color:#94a3b8;padding:10px 16px;border-radius:8px;margin-left:8px;cursor:pointer", "Proceed anyway");
  back.onclick = () => o.remove();
  go.onclick = () => { o.remove(); a.dataset.pgOk = 1; a.click(); };
  box.append(back, go); o.append(box); document.body.appendChild(o);
}
document.addEventListener("click", async e => {
  const a = e.target.closest("a[href^='http']");
  if (!a || a.dataset.pgOk || new URL(a.href).host === location.host) return;
  e.preventDefault(); e.stopPropagation();
  const r = await check(a.href);
  if (RISKY.includes(r.level)) return overlay(a, r);
  a.dataset.pgOk = 1; a.click();
}, true);
