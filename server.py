#!/usr/bin/env python3
"""
درع - موقع ذكاء اصطناعي مستقل لشرح الأمن السيبراني وكتابة الكود،
يشتغل بمزودات خارجية (مفاتيحك أنت) لا علاقة له بـ Claude/Anthropic.

التشغيل:
    pip install -r requirements.txt
    python server.py setup     # يولّد باسورد الأدمن الطويل (يظهر مرة وحدة)
    python server.py           # يفتح على http://127.0.0.1:8000

متغيرات البيئة (للنشر على استضافة):
    HOST, PORT
    HUB_ADMIN_SALT, HUB_ADMIN_HASH   (يطبعها setup)
    HUB_KEY_<NAME>                    مفتاح مزود، مثل HUB_KEY_GEMINI
    HUB_BEHIND_PROXY=1                اقرأ الـIP من X-Forwarded-For (خلف Cloudflare/Render)
    HUB_SESSION_HOURS                 مدة الجلسة (افتراضي 24)
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

BASE = Path(__file__).parent
UI = BASE / "ui"
CFG_FILE = Path(os.getenv("HUB_CONFIG", str(BASE / "diraa_config.json")))

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))
BEHIND_PROXY = os.getenv("HUB_BEHIND_PROXY") == "1"
SESSION_SECS = int(float(os.getenv("HUB_SESSION_HOURS", "24")) * 3600)
NAME_RE = re.compile(r"[a-z0-9_-]{1,24}")

# شخصية "درع": تُضاف تلقائيًا أمام كل محادثة، المستخدم ما يشوفها
RULES = (
    'أنت "درع"، مساعد خبير في الأمن السيبراني والبرمجة يتحدث العربية. '
    "اشرح المفاهيم بوضوح وبأمثلة عملية، وركّز على الفهم الدفاعي والممارسات الآمنة "
    "والجانب القانوني والأخلاقي. اكتب كودًا كاملاً وقابلاً للتشغيل بأي لغة يطلبها "
    "المستخدم مع شرح مختصر لما يفعله. استخدم عناوين فرعية ومقاطع كود عند الحاجة، "
    "وكن دقيقًا ومباشرًا."
)

# أسماء الموديلات تتغير مع الوقت: عدّلها من الإعدادات لو طلع خطأ
DEFAULTS = {
    "gemini": {"type": "openai", "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
               "model": "gemini-2.5-flash", "key": "", "enabled": True},
    "groq": {"type": "openai", "base_url": "https://api.groq.com/openai/v1",
             "model": "llama-3.3-70b-versatile", "key": "", "enabled": True},
    "openrouter": {"type": "openai", "base_url": "https://openrouter.ai/api/v1",
                   "model": "meta-llama/llama-3.3-70b-instruct:free", "key": "", "enabled": True},
    "mistral": {"type": "openai", "base_url": "https://api.mistral.ai/v1",
                "model": "mistral-small-latest", "key": "", "enabled": True},
    "ollama": {"type": "openai", "base_url": "http://localhost:11434/v1",
               "model": "llama3.2", "key": "", "enabled": False, "nokey": True},
}


# ---------------- الإعدادات والباسورد ----------------
def load():
    if CFG_FILE.exists():
        c = json.loads(CFG_FILE.read_text(encoding="utf-8"))
    else:
        c = {"admin": None, "default": "gemini", "providers": json.loads(json.dumps(DEFAULTS))}
    if os.getenv("HUB_ADMIN_SALT") and os.getenv("HUB_ADMIN_HASH"):
        c["admin"] = {"salt": os.environ["HUB_ADMIN_SALT"], "hash": os.environ["HUB_ADMIN_HASH"]}
    return c


def save(c):
    try:
        CFG_FILE.write_text(json.dumps(c, indent=2, ensure_ascii=False), encoding="utf-8")
        os.chmod(CFG_FILE, 0o600)
    except OSError:
        pass  # استضافة بقرص للقراءة فقط: التغييرات تبقى بالذاكرة لين إعادة التشغيل


cfg = load()


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return salt.hex(), h.hex()


def check_pw(pw):
    a = cfg.get("admin")
    if not a:
        return False
    _, h = hash_pw(pw, bytes.fromhex(a["salt"]))
    return hmac.compare_digest(h, a["hash"])


def setup():
    pw = secrets.token_urlsafe(48)
    salt, h = hash_pw(pw)
    cfg["admin"] = {"salt": salt, "hash": h}
    save(cfg)
    print("\nباسورد الدخول (انسخه الحين، ما يظهر مرة ثانية):\n")
    print(pw)
    print("\nلو بتنشر على استضافة حط هذي في متغيرات البيئة بدل الملف:\n")
    print(f"HUB_ADMIN_SALT={salt}")
    print(f"HUB_ADMIN_HASH={h}\n")


def key_of(name, p):
    return p.get("key") or os.getenv("HUB_KEY_" + name.upper().replace("-", "_"), "")


def usable(name, p):
    return bool(p.get("enabled") and (p.get("nokey") or key_of(name, p)))


def pub(name, p):
    return {"name": name, "type": p["type"], "model": p["model"], "base_url": p["base_url"],
            "enabled": bool(p.get("enabled")), "has_key": bool(key_of(name, p) or p.get("nokey")),
            "usable": usable(name, p), "default": name == cfg["default"]}


# ---------------- الاتصال بالمزودات ----------------
async def ask(name, p, msgs):
    key = key_of(name, p)
    base = p["base_url"].rstrip("/")
    async with httpx.AsyncClient(timeout=90) as c:
        if p["type"] == "anthropic":
            r = await c.post(base + "/messages",
                             headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                             json={"model": p["model"], "max_tokens": 2048, "messages": msgs})
            r.raise_for_status()
            return "".join(b.get("text", "") for b in r.json()["content"])
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        r = await c.post(base + "/chat/completions", headers=headers,
                         json={"model": p["model"], "messages": msgs})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


def err_text(e):
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        hint = {401: "المفتاح مرفوض", 403: "المفتاح مرفوض", 404: "الموديل أو الرابط غلط",
                429: "وصلت حد الطلبات"}.get(code, "خطأ من المزود")
        return f"{hint} ({code})"
    if isinstance(e, httpx.TimeoutException):
        return "انتهت المهلة"
    if isinstance(e, httpx.ConnectError):
        return "ما قدرت أتصل بالمزود"
    return e.__class__.__name__


def clean_history(h):
    out = []
    for m in (h or [])[-12:]:
        if isinstance(m, dict) and m.get("role") in ("user", "assistant"):
            out.append({"role": m["role"], "content": str(m.get("content", ""))[:8000]})
    return out


async def route(text, hist):
    """يسأل الأساسي، ولو فشل ينتقل تلقائيًا للمزود التالي (مفيد مع حدود الطبقة المجانية)."""
    P = cfg["providers"]
    order = [cfg["default"]] + [n for n in P if n != cfg["default"]]
    msgs = [{"role": "user", "content": RULES}] + hist + [{"role": "user", "content": text}]
    errs = []
    for n in order:
        p = P.get(n)
        if not p or not usable(n, p):
            continue
        try:
            return n, await ask(n, p, msgs), errs
        except Exception as e:
            errs.append(f"{n}: {err_text(e)}")
    return None, "ما قدرت أوصل لأي نموذج. " + (" | ".join(errs) if errs else "أضف مفتاح من الإعدادات."), errs


# ---------------- السيرفر ----------------
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
SESSIONS = {}
FAILS = {}


def client_ip(req):
    if BEHIND_PROXY:
        xff = req.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[0].strip()
    return req.client.host if req.client else "?"


def auth(req):
    tok = req.headers.get("authorization", "")[7:]
    if SESSIONS.get(tok, 0) <= time.time():
        raise HTTPException(401, "login")
    return tok


@app.post("/api/login")
async def login(req: Request):
    b = await req.json()
    pw = str(b.get("password", ""))[:512]
    ip, now = client_ip(req), time.time()
    for k, lim in ((ip, 5), ("*", 25)):
        n, until = FAILS.get(k, [0, 0])
        if until and until <= now:
            FAILS.pop(k, None)
        elif until > now:
            return JSONResponse({"error": "محاولات فاشلة كثيرة. جرّب بعد 15 دقيقة."}, 429)
    if check_pw(pw):
        FAILS.pop(ip, None)
        for t in [t for t, e in SESSIONS.items() if e <= now]:
            del SESSIONS[t]
        t = secrets.token_urlsafe(32)
        SESSIONS[t] = now + SESSION_SECS
        return {"token": t}
    for k, lim in ((ip, 5), ("*", 25)):
        n, _ = FAILS.get(k, [0, 0])
        n += 1
        FAILS[k] = [n, now + 900 if n >= lim else 0]
    return JSONResponse({"error": "الباسورد غلط."}, 401)


@app.get("/api/state")
async def state(req: Request):
    auth(req)
    return {"providers": [pub(n, p) for n, p in cfg["providers"].items()]}


@app.post("/api/providers")
async def add_provider(req: Request):
    auth(req)
    b = await req.json()
    n = str(b.get("name", "")).strip().lower()
    t = b.get("type")
    if not NAME_RE.fullmatch(n or ""):
        return JSONResponse({"error": "الاسم: حروف إنجليزية صغيرة وأرقام و - _ فقط."}, 400)
    if n in cfg["providers"]:
        return JSONResponse({"error": "الاسم مستخدم."}, 400)
    if t not in ("openai", "anthropic"):
        return JSONResponse({"error": "النوع لازم openai أو anthropic."}, 400)
    if not b.get("base_url") or not b.get("model"):
        return JSONResponse({"error": "عبّي الرابط والموديل."}, 400)
    cfg["providers"][n] = {"type": t, "base_url": b["base_url"], "model": b["model"],
                            "key": b.get("key", ""), "enabled": True}
    save(cfg)
    return pub(n, cfg["providers"][n])


@app.patch("/api/providers/{name}")
async def edit_provider(name: str, req: Request):
    auth(req)
    p = cfg["providers"].get(name)
    if not p:
        raise HTTPException(404, "غير موجود")
    b = await req.json()
    for f in ("key", "model", "base_url"):
        if f in b and str(b[f]).strip():
            p[f] = str(b[f]).strip()
    if "enabled" in b:
        p["enabled"] = bool(b["enabled"])
    if b.get("make_default"):
        cfg["default"] = name
    save(cfg)
    return pub(name, p)


@app.delete("/api/providers/{name}")
async def remove_provider(name: str, req: Request):
    auth(req)
    if name not in cfg["providers"]:
        raise HTTPException(404, "غير موجود")
    del cfg["providers"][name]
    if cfg["default"] == name:
        cfg["default"] = next(iter(cfg["providers"]), "")
    save(cfg)
    return {"ok": True}


@app.post("/api/providers/{name}/test")
async def test_provider(name: str, req: Request):
    auth(req)
    p = cfg["providers"].get(name)
    if not p:
        raise HTTPException(404, "غير موجود")
    t0 = time.time()
    try:
        await ask(name, p, [{"role": "user", "content": "رد بكلمة وحدة: تمام"}])
        return {"ok": True, "seconds": round(time.time() - t0, 1)}
    except Exception as e:
        return {"ok": False, "error": err_text(e)}


@app.post("/api/chat")
async def chat(req: Request):
    auth(req)
    b = await req.json()
    msg = str(b.get("message", "")).strip()[:8000]
    if not msg:
        return {"reply": ""}
    by, text, _ = await route(msg, clean_history(b.get("history")))
    return {"reply": text, "by": by}


@app.post("/api/logout")
async def logout(req: Request):
    tok = req.headers.get("authorization", "")[7:]
    SESSIONS.pop(tok, None)
    return {"ok": True}


STATIC = {"icon.svg": "image/svg+xml", "manifest.webmanifest": "application/manifest+json",
          "sw.js": "application/javascript"}


@app.get("/")
def home():
    return FileResponse(UI / "index.html", media_type="text/html")


@app.get("/{name}")
def static(name: str):
    if name in STATIC and (UI / name).exists():
        return FileResponse(UI / name, media_type=STATIC[name])
    raise HTTPException(404)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        setup()
    else:
        if not cfg.get("admin"):
            print("شغّل أول: python server.py setup")
            sys.exit(1)
        if not CFG_FILE.exists():
            save(cfg)
        print(f"درع شغّال على http://{HOST}:{PORT}")
        uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
