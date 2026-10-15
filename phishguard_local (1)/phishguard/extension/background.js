const API = "http://127.0.0.1:8000/api/check?url=";
chrome.runtime.onMessage.addListener((m, _s, send) => {
  fetch(API + encodeURIComponent(m.url)).then(r => r.json()).then(send).catch(() => send({ level: "Safe", error: true }));
  return true;
});
