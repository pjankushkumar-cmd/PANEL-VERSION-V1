import os, re, sqlite3, hashlib, secrets, hmac, time, json
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, abort
import requests

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = "/var/data/hackii.sqlite3"
ADMIN_MASTER_KEY = os.environ.get("ADMIN_MASTER_KEY", "")
API_URL = "https://draw.ar-lottery01.com/WinGo/WinGo_1M/GetHistoryIssuePage.json?pageNo=1"
app = Flask(__name__, static_folder=None)

os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
def db():
    c=sqlite3.connect(DB_PATH, timeout=20)
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS access_keys(
          id INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT UNIQUE NOT NULL,
          key_hint TEXT NOT NULL, note TEXT DEFAULT '', created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL, max_devices INTEGER NOT NULL DEFAULT 1,
          revoked INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sessions(
          id INTEGER PRIMARY KEY AUTOINCREMENT, key_id INTEGER NOT NULL,
          token_hash TEXT UNIQUE NOT NULL, browser_id TEXT NOT NULL,
          created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL,
          revoked INTEGER NOT NULL DEFAULT 0,
          FOREIGN KEY(key_id) REFERENCES access_keys(id)
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_key ON sessions(key_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_seen ON sessions(last_seen);
        ''')
init_db()
with db() as _c:
    _cols = [r[1] for r in _c.execute("PRAGMA table_info(sessions)").fetchall()]
    if "browser_id" not in _cols:
        _c.execute("ALTER TABLE sessions ADD COLUMN browser_id TEXT DEFAULT ''")

def now(): return int(time.time())
def hash_value(v): return hashlib.sha256(v.encode()).hexdigest()
def bearer():
    v=request.headers.get("Authorization", "")
    return v[7:].strip() if v.lower().startswith("bearer ") else ""
def current_session():
    token=bearer()
    if not token: return None
    with db() as c:
        return c.execute('''SELECT s.*, k.expires_at, k.revoked AS key_revoked, k.key_hint
          FROM sessions s JOIN access_keys k ON k.id=s.key_id
          WHERE s.token_hash=? AND s.revoked=0''',(hash_value(token),)).fetchone()
def user_required(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        s=current_session()
        if not s or s['key_revoked'] or s['expires_at']<=now(): return jsonify(error="Session expired. Please login again."),401
        return fn(s,*a,**kw)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        supplied=request.headers.get("X-Admin-Key", "")
        if not ADMIN_MASTER_KEY:
            return jsonify(error="ADMIN_MASTER_KEY is not configured on the server."),503
        if not hmac.compare_digest(supplied, ADMIN_MASTER_KEY): return jsonify(error="Invalid admin key"),401
        return fn(*a,**kw)
    return wrapped

@app.get("/")
def index(): return send_from_directory(BASE,"index.html")
@app.get("/admin")
def admin_page(): return send_from_directory(BASE,"admin.html")
@app.get("/health")
def health(): return jsonify(status="ok", service="HACKII PREDICT")

@app.post("/api/login")
def login():
    data=request.get_json(silent=True) or {}; raw=str(data.get("key","")).strip()
    if not raw or len(raw)>160: return jsonify(error="Valid login key daalein."),400
    t=now()
    with db() as c:
        k=c.execute("SELECT * FROM access_keys WHERE key_hash=?",(hash_value(raw),)).fetchone()
        if not k or k['revoked'] or k['expires_at']<=t: return jsonify(error="Invalid, revoked or expired key."),401
        browser_id=str(data.get('browser_id','')).strip()
        if not re.fullmatch(r'BR-[A-F0-9]{16}', browser_id):
            return jsonify(error="Browser ID missing or invalid. Refresh the page and try again."),400
        c.execute("UPDATE sessions SET revoked=1 WHERE key_id=? AND browser_id=? AND revoked=0",(k['id'],browser_id))
        online=c.execute("SELECT COUNT(DISTINCT browser_id) n FROM sessions WHERE key_id=? AND revoked=0 AND last_seen>?",(k['id'],t-90)).fetchone()['n']
        if online>=k['max_devices']: return jsonify(error="This key has reached its active browser limit."),403
        token=secrets.token_urlsafe(36)
        c.execute("INSERT INTO sessions(key_id,token_hash,browser_id,created_at,last_seen) VALUES(?,?,?,?,?)",(k['id'],hash_value(token),browser_id,t,t))
    return jsonify(token=token, expires_at=k['expires_at'], key_hint=k['key_hint'])

@app.post("/api/heartbeat")
@user_required
def heartbeat(s):
    with db() as c: c.execute("UPDATE sessions SET last_seen=? WHERE id=?",(now(),s['id']))
    return jsonify(ok=True, server_time=now())

@app.post("/api/logout")
@user_required
def logout(s):
    with db() as c: c.execute("UPDATE sessions SET revoked=1 WHERE id=?",(s['id'],))
    return jsonify(ok=True)

@app.get("/api/win-go")
@user_required
def win_go(s):
    with db() as c: c.execute("UPDATE sessions SET last_seen=? WHERE id=?",(now(),s['id']))
    try:
        r=requests.get(API_URL,timeout=12,headers={"User-Agent":"Mozilla/5.0 HACKII-PREDICT"})
        return (r.content,r.status_code,{'Content-Type':r.headers.get('Content-Type','application/json'),'Cache-Control':'no-store'})
    except requests.RequestException:
        return jsonify(error="Upstream result API unavailable"),502

@app.get("/api/admin/stats")
@admin_required
def admin_stats():
    t=now()
    with db() as c:
        total=c.execute("SELECT COUNT(*) n FROM access_keys").fetchone()['n']
        active=c.execute("SELECT COUNT(*) n FROM access_keys WHERE revoked=0 AND expires_at>?",(t,)).fetchone()['n']
        online=c.execute("SELECT COUNT(*) n FROM sessions s JOIN access_keys k ON k.id=s.key_id WHERE s.revoked=0 AND k.revoked=0 AND k.expires_at>? AND s.last_seen>?",(t,t-90)).fetchone()['n']
        return jsonify(total_keys=total,active_keys=active,online_members=online)

@app.get("/api/admin/keys")
@admin_required
def admin_keys():
    t=now()
    with db() as c:
        rows=c.execute('''SELECT k.*, (SELECT COUNT(*) FROM sessions s WHERE s.key_id=k.id AND s.revoked=0 AND s.last_seen>? AND k.revoked=0 AND k.expires_at>?) online,
          (SELECT COUNT(*) FROM sessions s WHERE s.key_id=k.id AND s.revoked=0) total_sessions
          FROM access_keys k ORDER BY k.id DESC LIMIT 250''',(t-90,t)).fetchall()
    return jsonify(keys=[dict(r) for r in rows])

@app.post("/api/admin/keys")
@admin_required
def create_key():
    data=request.get_json(silent=True) or {}
    try:
        hours=int(data.get('hours',24)); max_devices=int(data.get('max_devices',1))
    except (TypeError,ValueError): return jsonify(error="Hours and device limit must be numbers."),400
    if hours<1 or hours>87600 or max_devices<1 or max_devices>500: return jsonify(error="Expiry must be 1-87600 hours; device limit 1-500."),400
    raw="HK-"+secrets.token_urlsafe(18).replace('-','').replace('_','')
    t=now(); hint=raw[-6:]
    with db() as c:
        c.execute("INSERT INTO access_keys(key_hash,key_hint,note,created_at,expires_at,max_devices) VALUES(?,?,?,?,?,?)",(hash_value(raw),hint,str(data.get('note',''))[:100],t,t+hours*3600,max_devices))
    return jsonify(key=raw,key_hint=hint,expires_at=t+hours*3600,max_devices=max_devices)

@app.post("/api/admin/keys/<int:key_id>/revoke")
@admin_required
def revoke_key(key_id):
    with db() as c:
        c.execute("UPDATE access_keys SET revoked=1 WHERE id=?",(key_id,))
        c.execute("UPDATE sessions SET revoked=1 WHERE key_id=?",(key_id,))
    return jsonify(ok=True)

@app.get("/api/admin/sessions")
@admin_required
def admin_sessions():
    t=now()
    with db() as c:
        rows=c.execute('''SELECT s.id,s.browser_id,s.created_at,s.last_seen,s.revoked,k.key_hint,k.id key_id,
          CASE WHEN s.revoked=0 AND k.revoked=0 AND k.expires_at>? AND s.last_seen>? THEN 1 ELSE 0 END online
          FROM sessions s JOIN access_keys k ON k.id=s.key_id ORDER BY s.last_seen DESC LIMIT 500''',(t,t-90)).fetchall()
    return jsonify(sessions=[dict(r) for r in rows])

@app.post("/api/admin/sessions/<int:session_id>/revoke")
@admin_required
def revoke_session(session_id):
    with db() as c: c.execute("UPDATE sessions SET revoked=1 WHERE id=?",(session_id,))
    return jsonify(ok=True)

if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))
