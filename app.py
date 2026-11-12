import os, re, json, time, secrets, threading, datetime, hashlib, shutil, functools
from html import escape
from flask import Flask, request, jsonify, Response
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import markdown, bleach

DATA = os.environ.get("DATA_DIR", "/data")
FILE = os.path.join(DATA, "journal.enc")
VER = os.path.join(DATA, "versions")
LAST = os.path.join(DATA, "last_access.txt")
LOCK_AFTER = 600   # idle seconds per session
SNAP_EVERY = 900   # at most one version snapshot per 15 min
KEEP = 20          # versions kept
M1, M2 = b"BJ1", b"BJ2"
COST = (17, 8, 1)  # log2(n), r, p for new containers (stored in the file header)
HERE = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024
S = {"key": None, "salt": None, "params": None, "sess": {}}
L = threading.RLock()


# ---------- crypto / container (BJ2) ----------
def derive(pw, salt, params):
    return Scrypt(salt=salt, length=32, n=2 ** params[0], r=params[1], p=params[2]).derive(pw.encode())


def pack(key, salt, params, data):
    head = M2 + bytes(params) + salt
    nonce = os.urandom(12)
    return head + nonce + AESGCM(key).encrypt(nonce, json.dumps(data, ensure_ascii=False).encode(), head)


def parse(blob):
    if blob[:3] != M2 or len(blob) < 50 or blob[3] > 20:
        raise ValueError("format")
    return (blob[3], blob[4], blob[5]), blob[6:22], blob[22:34], blob[34:], blob[:22]


def unpack(key, blob):
    _, _, nonce, ct, head = parse(blob)
    return json.loads(AESGCM(key).decrypt(nonce, ct, head))


def write_file(blob, path=FILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def snapshot(force=False):
    if not os.path.exists(FILE):
        return
    os.makedirs(VER, exist_ok=True)
    names = sorted(n for n in os.listdir(VER) if n.endswith(".enc"))
    if names and not force and time.time() - os.path.getmtime(os.path.join(VER, names[-1])) < SNAP_EVERY:
        return
    stamp = datetime.datetime.fromtimestamp(os.path.getmtime(FILE), datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dst = os.path.join(VER, stamp + ".enc")
    if not os.path.exists(dst):
        shutil.copyfile(FILE, dst)
    for n in sorted(n for n in os.listdir(VER) if n.endswith(".enc"))[:-KEEP]:
        os.remove(os.path.join(VER, n))


def load():
    return unpack(S["key"], open(FILE, "rb").read())


def commit(d):
    snapshot()
    write_file(pack(S["key"], S["salt"], S["params"], d))


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def last_access():
    try:
        return open(LAST).read().strip() or None
    except OSError:
        return None


def err(msg, code):
    return jsonify(error=msg), code


def lock():
    S.update(key=None, salt=None, params=None, sess={})


def watchdog():
    while True:
        time.sleep(15)
        with L:
            t = time.time()
            for k in [k for k, v in S["sess"].items() if t - v["seen"] > LOCK_AFTER]:
                del S["sess"][k]
            if S["key"] and not S["sess"]:
                lock()


threading.Thread(target=watchdog, daemon=True).start()


def authed():
    tok = request.cookies.get("bj")
    with L:
        s = S["sess"].get(tok) if tok else None
        if S["key"] and s and time.time() - s["seen"] <= LOCK_AFTER:
            s["seen"] = time.time()
            return tok
        if s:
            del S["sess"][tok]
        if not S["sess"]:
            lock()
    return None


def guard(f):
    @functools.wraps(f)
    def w(*a, **k):
        tok = authed()
        if not tok:
            return err("locked", 401)
        with L:
            if not S["key"]:
                return err("locked", 401)
            try:
                return f(tok, *a, **k)
            except (InvalidTag, ValueError, OSError):
                lock()
                return err("locked", 401)
    return w


@app.after_request
def headers(r):
    r.headers.setdefault("Cache-Control", "no-store")
    r.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data: https:")
    return r


# ---------- auth ----------
@app.get("/api/state")
def state():
    return jsonify(exists=os.path.exists(FILE), unlocked=bool(authed()))


@app.post("/api/unlock")
def unlock():
    pw = request.get_json(force=True).get("password", "")
    with L:
        try:
            if not os.path.exists(FILE):
                if len(pw) < 8:
                    return err("Use at least 8 characters.", 400)
                salt, params = os.urandom(16), COST
                key = derive(pw, salt, params)
                write_file(pack(key, salt, params, {"entries": []}))
            else:
                blob = open(FILE, "rb").read()
                if blob[:3] == M1:  # one-time migration of the single-document format
                    k1 = derive(pw, blob[3:19], (15, 8, 1))
                    text = AESGCM(k1).decrypt(blob[19:31], blob[31:], M1).decode()
                    salt, params = os.urandom(16), COST
                    key = derive(pw, salt, params)
                    t = now()
                    shutil.copyfile(FILE, FILE + ".bj1.bak")
                    write_file(pack(key, salt, params, {"entries": [
                        {"id": secrets.token_hex(4), "title": "Journal", "text": text,
                         "created": t, "updated": t, "rev": 1}]}))
                else:
                    params, salt, *_ = parse(blob)
                    key = derive(pw, salt, params)
                    unpack(key, blob)
        except (InvalidTag, ValueError):
            time.sleep(1)
            return err("Wrong password.", 401)
        tok = secrets.token_urlsafe(32)
        S.update(key=key, salt=salt, params=params)
        S["sess"][tok] = {"seen": time.time(), "prev": last_access()}
        with open(LAST, "w") as f:
            f.write(now())
    r = jsonify(ok=True)
    r.set_cookie("bj", tok, httponly=True, samesite="Strict", secure=request.is_secure)
    return r


@app.post("/api/ping")
@guard
def ping(tok):
    return jsonify(ok=True)


@app.post("/api/lock")
def do_lock():
    with L:
        S["sess"].pop(request.cookies.get("bj"), None)
        if not S["sess"]:
            lock()
    return jsonify(ok=True)


# ---------- entries ----------
def find(d, eid):
    return next((e for e in d["entries"] if e["id"] == eid), None)


def clean_title(t):
    return str(t).strip()[:120] or "Untitled"


def full(e):
    return {k: e[k] for k in ("id", "title", "text", "rev", "created", "updated")}


@app.get("/api/entries")
@guard
def list_entries(tok):
    d = load()
    return jsonify(entries=[{k: e[k] for k in ("id", "title", "created", "updated")} for e in d["entries"]],
                   last=S["sess"][tok]["prev"])


@app.post("/api/entries")
@guard
def new_entry(tok):
    d = load()
    t = now()
    e = {"id": secrets.token_hex(4), "title": clean_title(request.get_json(force=True).get("title") or ""),
         "text": "", "created": t, "updated": t, "rev": 1}
    d["entries"].append(e)
    commit(d)
    return jsonify(full(e))


@app.get("/api/entries/<eid>")
@guard
def get_entry(tok, eid):
    e = find(load(), eid)
    return jsonify(full(e)) if e else err("Not found", 404)


@app.put("/api/entries/<eid>")
@guard
def put_entry(tok, eid):
    d = load()
    e = find(d, eid)
    if not e:
        return err("Not found", 404)
    im = request.headers.get("If-Match")
    if im is not None and im != str(e["rev"]):
        return jsonify(error="conflict", rev=e["rev"], text=e["text"], title=e["title"]), 409
    b = request.get_json(force=True)
    if "text" in b:
        e["text"] = b["text"]
    if "title" in b:
        e["title"] = clean_title(b["title"])
    e["rev"] += 1
    e["updated"] = now()
    commit(d)
    return jsonify(rev=e["rev"], updated=e["updated"], title=e["title"])


@app.delete("/api/entries/<eid>")
@guard
def del_entry(tok, eid):
    d = load()
    d["entries"] = [e for e in d["entries"] if e["id"] != eid]
    commit(d)
    return jsonify(ok=True)


@app.get("/api/search")
@guard
def search(tok):
    q = request.args.get("q", "").strip().lower()
    out = []
    if q:
        for e in sorted(load()["entries"], key=lambda e: e["created"], reverse=True):
            i = e["text"].lower().find(q)
            if i >= 0 or q in e["title"].lower():
                s = e["text"][max(0, i - 30): i + len(q) + 50].replace("\n", " ") if i >= 0 else ""
                out.append({"id": e["id"], "title": e["title"], "idx": i, "snippet": s})
            if len(out) >= 50:
                break
    return jsonify(results=out)


# ---------- rendering ----------
TAGS = set(bleach.sanitizer.ALLOWED_TAGS) | {
    "p", "pre", "br", "hr", "img", "h1", "h2", "h3", "h4", "h5", "h6", "table",
    "thead", "tbody", "tr", "th", "td", "del", "div", "span"}
ATTRS = {"a": ["href", "title"], "img": ["src", "alt", "title"], "*": ["class"]}
FOLD = re.compile(r"^[ \t]*<!--\s*(/?)fold:?\s*(.*?)\s*-->[ \t]*$", re.M)
BM = re.compile(r"^[ \t]*<!--\s*bm:\s*(.*?)\s*-->[ \t]*$", re.M)


def render(text, plain=False):
    n = [0]

    def tok(m):
        n[0] += 1
        return f"\n\nBJBMARK{n[0] - 1}X\n\n"

    text = BM.sub(tok, text)
    titles, depth = [], [0]

    def fold(m):
        if m.group(1):
            if not depth[0]:
                return ""
            depth[0] -= 1
            return "\n\nBJENDFOLDX\n\n"
        depth[0] += 1
        titles.append(m.group(2) or "Section")
        return f"\n\nBJFOLD{len(titles) - 1}X\n\n"

    text = FOLD.sub(fold, text) + "\n\nBJENDFOLDX\n\n" * depth[0]
    html = markdown.markdown(text, extensions=["extra", "sane_lists", "nl2br"])
    html = bleach.clean(html, tags=TAGS, attributes=ATTRS, protocols=["http", "https", "mailto"])
    html = re.sub(r"<p>BJBMARK(\d+)X</p>", r'<span class="bm" id="bm-\1"></span>', html)
    html = re.sub(r"BJBMARK\d+X", "", html)
    html = re.sub(r"<p>BJFOLD(\d+)X</p>",
                  lambda m: f"<details{' open' if plain else ''}><summary>{escape(titles[int(m.group(1))])}</summary>", html)
    html = html.replace("<p>BJENDFOLDX</p>", "</details>")
    t = [0]

    def task(m):
        i, on = t[0], m.group(2) in "xX"
        t[0] += 1
        box = ("☑ " if on else "☐ ") if plain else f'<input type="checkbox" data-t="{i}"{" checked" if on else ""}> '
        return f'<li class="task">{m.group(1) or ""}{box}'

    return re.sub(r"<li>(\s*<p>)?\[( |x|X)\]\s", task, html)


@app.post("/api/render")
@guard
def api_render(tok):
    return jsonify(html=render(request.get_json(force=True).get("text", "")))


PDF_CSS = """
@page { size: A4; margin: 22mm 20mm; }
body { font-family: 'DejaVu Sans', sans-serif; font-size: 10.5pt; line-height: 1.6; color: #111; }
h1,h2,h3 { line-height: 1.25; } pre,code { font-family: 'DejaVu Sans Mono', monospace; background: #f3f3f5; }
pre { padding: 8px; white-space: pre-wrap; } blockquote { border-left: 3px solid #8b5cf6; margin-left: 0; padding-left: 12px; color: #444; }
table { border-collapse: collapse; } td,th { border: 1px solid #ccc; padding: 4px 8px; } img { max-width: 100%; }
li.task { list-style: none; margin-left: -1.2em; }
details { border: 1px solid #ccc; border-radius: 6px; padding: 6px 12px; margin: 10px 0; } summary { font-weight: bold; }
"""


@app.post("/api/pdf")
@guard
def api_pdf(tok):
    from weasyprint import HTML
    b = request.get_json(force=True)
    title = clean_title(b.get("title") or "")
    body = f"<h1>{escape(title)}</h1>" + render(b.get("text", ""), plain=True)
    pdf = HTML(string=f"<html><head><meta charset='utf-8'><style>{PDF_CSS}</style></head><body>{body}</body></html>").write_pdf()
    name = "journal-" + (re.sub(r"[^A-Za-z0-9._-]+", "-", title, flags=re.A).strip("-") or "entry") + ".pdf"
    return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ---------- backup / restore / password / versions ----------
@app.get("/api/backup")
@guard
def backup(tok):
    name = f"bunny-journal-{datetime.date.today().isoformat()}.enc"
    return Response(open(FILE, "rb").read(), mimetype="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.post("/api/restore")
@guard
def restore(tok):
    blob = request.get_data()
    try:
        if blob[:3] == M2:
            parse(blob)
        elif blob[:3] != M1 or len(blob) < 32:
            raise ValueError
    except ValueError:
        return err("Not a Bunny Journal file.", 400)
    shutil.copyfile(FILE, FILE + ".pre-restore")
    write_file(blob)
    lock()
    r = jsonify(ok=True)
    r.delete_cookie("bj")
    return r


@app.post("/api/password")
@guard
def change_password(tok):
    b = request.get_json(force=True)
    old, new = b.get("old", ""), b.get("new", "")
    if not secrets.compare_digest(derive(old, S["salt"], S["params"]), S["key"]):
        time.sleep(1)
        return err("Current password is wrong.", 403)
    if len(new) < 8:
        return err("Use at least 8 characters.", 400)
    d = load()
    oldkey, nsalt = S["key"], os.urandom(16)
    nkey = derive(new, nsalt, COST)
    if os.path.isdir(VER):  # versions are protected by the old password, so re-encrypt them
        for n in os.listdir(VER):
            p = os.path.join(VER, n)
            try:
                write_file(pack(nkey, nsalt, COST, unpack(oldkey, open(p, "rb").read())), p)
            except Exception:
                os.remove(p)
    write_file(pack(nkey, nsalt, COST, d))
    S.update(key=nkey, salt=nsalt, params=COST)
    return jsonify(ok=True)


@app.get("/api/versions")
@guard
def versions(tok):
    out = []
    for n in sorted(os.listdir(VER), reverse=True) if os.path.isdir(VER) else []:
        if n.endswith(".enc"):
            try:
                if parse(open(os.path.join(VER, n), "rb").read())[1] == S["salt"]:
                    out.append(n[:-4])
            except ValueError:
                pass
    return jsonify(versions=out)


@app.post("/api/versions/restore")
@guard
def version_restore(tok):
    n = request.get_json(force=True).get("name", "")
    if not re.fullmatch(r"\d{8}T\d{6}Z", n):
        return err("Bad name", 400)
    try:
        blob = open(os.path.join(VER, n + ".enc"), "rb").read()
        unpack(S["key"], blob)
    except (InvalidTag, ValueError, OSError):
        return err("Version can't be opened.", 400)
    snapshot(force=True)
    write_file(blob)
    return jsonify(ok=True)


# ---------- PWA ----------
ICON_FILES = {"icon-192.png": "image/png", "icon-512.png": "image/png", "icon-maskable.png": "image/png",
              "apple-touch-icon.png": "image/png", "favicon-32.png": "image/png", "favicon.ico": "image/x-icon"}
ICON_HASH = hashlib.sha1(b"".join(open(os.path.join(HERE, "icons", n), "rb").read()
                                  for n in sorted(ICON_FILES))).hexdigest()[:10]
V = "?v=" + ICON_HASH

MANIFEST = {
    "id": "/", "name": "Bunny Journal", "short_name": "Journal", "start_url": "/", "scope": "/",
    "display": "standalone", "background_color": "#09090b", "theme_color": "#09090b",
    "icons": [
        {"src": "/icons/icon-192.png" + V, "sizes": "192x192", "type": "image/png", "purpose": "any"},
        {"src": "/icons/icon-512.png" + V, "sizes": "512x512", "type": "image/png", "purpose": "any"},
        {"src": "/icons/icon-maskable.png" + V, "sizes": "512x512", "type": "image/png", "purpose": "maskable"}]}

SW = """const C='bj-shell-__H__',OFF='/offline',A=[OFF,'/manifest.webmanifest'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(A)));self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))));self.clients.claim()});
self.addEventListener('fetch',e=>{const r=e.request,u=new URL(r.url);
 if(r.method!=='GET'||u.origin!==location.origin||u.pathname.startsWith('/api/'))return;
 if(r.mode==='navigate'){e.respondWith(fetch(r).catch(()=>caches.match(OFF)));return}
 e.respondWith(fetch(r).then(x=>{if(x.ok){const y=x.clone();caches.open(C).then(c=>c.put(r,y))}return x}).catch(()=>caches.match(r)))});
""".replace("__H__", ICON_HASH)

OFFLINE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#09090b"><title>Bunny Journal</title>
<style>*{box-sizing:border-box}html,body{height:100%;margin:0;background:#09090b;color:#e4e4e7;font:15px/1.5 Inter,system-ui,-apple-system,sans-serif}
body{display:grid;place-items:center;padding:16px;background-image:radial-gradient(600px 300px at 50% -10%,#8b5cf633,transparent)}
.c{width:100%;max-width:360px;background:#111113;border:1px solid #1f1f23;border-radius:16px;padding:24px}
h1{font-size:22px;margin:0 0 8px;font-weight:600}p{margin:0 0 16px;color:#71717a;font-size:13px}
button{width:100%;height:44px;border:0;border-radius:10px;background:#8b5cf6;color:#fff;font:inherit;font-weight:500;cursor:pointer}
button:hover{filter:brightness(1.15)}</style></head><body><div class="c"><h1>You’re offline</h1>
<p>Bunny Journal needs to reach your server to open the journal. Check your connection and try again.</p>
<button onclick="location.href='/'">Try again</button></div></body></html>"""


def nocache(r):
    r.headers["Cache-Control"] = "no-cache"
    return r


@app.get("/manifest.webmanifest")
def manifest():
    return nocache(Response(json.dumps(MANIFEST), mimetype="application/manifest+json"))


@app.get("/sw.js")
def sw():
    return nocache(Response(SW, mimetype="text/javascript"))


@app.get("/offline")
def offline():
    return nocache(Response(OFFLINE, mimetype="text/html"))


@app.get("/icons/<name>")
def icon(name):
    if name not in ICON_FILES:
        return "", 404
    r = nocache(Response(open(os.path.join(HERE, "icons", name), "rb").read(), mimetype=ICON_FILES[name]))
    r.add_etag()
    return r.make_conditional(request)


PAGE = open(os.path.join(HERE, "index.html"), encoding="utf-8").read().replace("__V__", ICON_HASH)


@app.get("/")
def index():
    return PAGE
