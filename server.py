import base64
import hashlib
import hmac
import json
import os
import secrets
import smtplib
import ssl
import time
from email.message import EmailMessage
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import Request, urlopen

try:
    import psycopg
    from psycopg.types.json import Json
except ImportError:
    psycopg = None
    Json = None


ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))
DB_PATH = DATA_DIR / "freelab_state.json"
SESSION_PATH = DATA_DIR / "sessions.json"
DATABASE_URL = os.environ.get("DATABASE_URL", "")
SESSION_TTL = 60 * 60 * 24 * 14
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@freelabhub.com").lower()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123456")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8801").rstrip("/")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "no-reply@freelabhub.com")
SMTP_TLS = os.environ.get("SMTP_TLS", "true").lower() != "false"


def now():
    return int(time.time())


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"pbkdf2_sha256${salt}${base64.b64encode(digest).decode('ascii')}"


def password_ok(password, stored):
    if not stored:
        return False
    try:
        _, salt, encoded = stored.split("$", 2)
        expected = password_hash(password, salt).split("$", 2)[2]
        return hmac.compare_digest(expected, encoded)
    except ValueError:
        return False


def default_state():
    return {
        "sessionEmail": "",
        "activeThread": None,
        "language": "pt",
        "users": [
            {
                "id": "lab-demo",
                "role": "lab",
                "name": "Clinica Vila Nova",
                "city": "Sao Paulo - SP",
                "country": "Brasil",
                "address": "Vila Nova, Sao Paulo - SP",
                "countryCode": "+55",
                "email": "clinica@demo.com",
                "phone": "(11) 98873-7694",
                "passwordHash": password_hash("123456"),
                "verified": True,
                "blocked": False,
                "avatar": "",
                "specialties": ["E.max", "Ceramica", "Zirconia"],
                "bio": "Clinica com fluxo digital procurando parceiros para trabalhos de protese.",
                "adTitle": "Procuro freelancer para coroas E.max",
                "adSpecialty": "E.max",
                "adValue": "450,00",
                "adElements": "3",
                "adDescription": "Caso com escaneamento digital e prazo combinado por mensagem interna.",
                "album": [],
                "lat": -23.5505,
                "lng": -46.6333,
            },
            {
                "id": "freelancer-demo",
                "role": "freelancer",
                "name": "Lucas Fernandes",
                "city": "Guarulhos - SP",
                "country": "Brasil",
                "address": "Guarulhos - SP",
                "countryCode": "+55",
                "email": "freelancer@demo.com",
                "phone": "(11) 97777-0000",
                "passwordHash": password_hash("123456"),
                "verified": True,
                "blocked": False,
                "avatar": "",
                "specialties": ["Ceramica", "E.max", "Zirconia", "CAD/CAM"],
                "bio": "Protetico freelancer com foco em ceramica, zirconia e fluxo digital.",
                "adTitle": "Ceramica, E.max e zirconia sob demanda",
                "adSpecialty": "Ceramica",
                "adValue": "Sob consulta",
                "adElements": "",
                "adDescription": "Atendimento para clinicas e laboratorios com portfolio e comunicacao clara.",
                "album": [],
                "lat": -23.4543,
                "lng": -46.5337,
            },
        ],
        "classifieds": [],
        "threads": [],
        "externalConnections": [],
        "payments": [],
        "auditLog": [],
    }


def ensure_data():
    if use_postgres():
        with db_conn() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS app_state (id text PRIMARY KEY, payload jsonb NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS sessions (token text PRIMARY KEY, email text NOT NULL, role text NOT NULL, created_at bigint NOT NULL)")
            conn.execute(
                "INSERT INTO app_state (id, payload) VALUES ('main', %s) ON CONFLICT (id) DO NOTHING",
                (Json(default_state()),),
            )
            conn.commit()
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not DB_PATH.exists():
        write_json(DB_PATH, default_state())
    if not SESSION_PATH.exists():
        write_json(SESSION_PATH, {})


def use_postgres():
    return bool(DATABASE_URL and psycopg)


def db_conn():
    return psycopg.connect(DATABASE_URL)


def read_json(path, fallback=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback if fallback is not None else {}


def write_json(path, data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def read_state_store():
    ensure_data()
    if use_postgres():
        with db_conn() as conn:
            row = conn.execute("SELECT payload FROM app_state WHERE id = 'main'").fetchone()
            return row[0] if row else default_state()
    return read_json(DB_PATH, default_state())


def write_state_store(data):
    if use_postgres():
        with db_conn() as conn:
            conn.execute(
                "INSERT INTO app_state (id, payload) VALUES ('main', %s) ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload",
                (Json(data),),
            )
            conn.commit()
        return
    write_json(DB_PATH, data)


def state():
    data = read_state_store()
    data.setdefault("payments", [])
    data.setdefault("auditLog", [])
    for user in data.get("users", []):
        if user.get("password") and not user.get("passwordHash"):
            user["passwordHash"] = password_hash(user.pop("password"))
        user.setdefault("verified", False)
        user.setdefault("blocked", False)
    return data


def save_state(data):
    for user in data.get("users", []):
        if user.get("password"):
            user["passwordHash"] = password_hash(user.pop("password"))
    write_state_store(data)


def audit(data, event_type, **extra):
    data.setdefault("auditLog", []).append({"at": now(), "type": event_type, **extra})
    data["auditLog"] = data["auditLog"][-500:]


def merge_users(existing, incoming):
    by_key = {}
    for user in existing:
        by_key[user.get("id") or user.get("email", "").lower()] = dict(user)
    merged = []
    for user in incoming:
        key = user.get("id") or user.get("email", "").lower()
        current = by_key.pop(key, {})
        keep_hash = current.get("passwordHash")
        keep_verified = current.get("verified", user.get("verified", False))
        keep_blocked = current.get("blocked", user.get("blocked", False))
        next_user = {**current, **user}
        if keep_hash and not next_user.get("password") and not next_user.get("passwordHash"):
            next_user["passwordHash"] = keep_hash
        next_user["verified"] = keep_verified
        next_user["blocked"] = keep_blocked
        merged.append(next_user)
    merged.extend(by_key.values())
    return merged


def public_user(user):
    clean = dict(user)
    clean.pop("password", None)
    clean.pop("passwordHash", None)
    clean.pop("emailToken", None)
    return clean


def public_state(data, email=""):
    clean = dict(data)
    clean["users"] = [public_user(user) for user in data.get("users", []) if not user.get("blocked")]
    clean["sessionEmail"] = email or clean.get("sessionEmail", "")
    return clean


def sessions():
    ensure_data()
    cutoff = now() - SESSION_TTL
    if use_postgres():
        with db_conn() as conn:
            conn.execute("DELETE FROM sessions WHERE created_at < %s", (cutoff,))
            rows = conn.execute("SELECT token, email, role, created_at FROM sessions").fetchall()
            conn.commit()
            return {token: {"email": email, "role": role, "createdAt": created_at} for token, email, role, created_at in rows}
    items = read_json(SESSION_PATH, {})
    changed = False
    for token, item in list(items.items()):
        if item.get("createdAt", 0) < cutoff:
            items.pop(token, None)
            changed = True
    if changed:
        write_json(SESSION_PATH, items)
    return items


def create_session(email, role="user"):
    token = secrets.token_urlsafe(32)
    if use_postgres():
        ensure_data()
        with db_conn() as conn:
            conn.execute(
                "INSERT INTO sessions (token, email, role, created_at) VALUES (%s, %s, %s, %s)",
                (token, email.lower(), role, now()),
            )
            conn.commit()
        return token
    items = sessions()
    items[token] = {"email": email.lower(), "role": role, "createdAt": now()}
    write_json(SESSION_PATH, items)
    return token


def delete_session(token):
    if not token:
        return
    if use_postgres():
        ensure_data()
        with db_conn() as conn:
            conn.execute("DELETE FROM sessions WHERE token = %s", (token,))
            conn.commit()
        return
    items = sessions()
    if token in items:
        items.pop(token, None)
        write_json(SESSION_PATH, items)


def parse_cookie(header):
    result = {}
    for part in (header or "").split(";"):
        if "=" in part:
            key, value = part.strip().split("=", 1)
            result[key] = value
    return result


def geocode(address):
    if not address:
        return None
    url = "https://nominatim.openstreetmap.org/search?format=json&limit=1&q=" + quote(address)
    request = Request(url, headers={"User-Agent": "FreelaBHubPilot/1.0"})
    with urlopen(request, timeout=8) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not payload:
        return None
    return {"lat": float(payload[0]["lat"]), "lng": float(payload[0]["lon"])}


def send_email(to, subject, text):
    if not SMTP_HOST:
        return False
    message = EmailMessage()
    message["From"] = SMTP_FROM
    message["To"] = to
    message["Subject"] = subject
    message.set_content(text)
    if SMTP_TLS:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=12) as server:
            server.starttls(context=context)
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(message)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=12) as server:
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(message)
    return True


def send_verification_email(user):
    token = user.setdefault("emailToken", secrets.token_urlsafe(24))
    link = f"{APP_BASE_URL}/verify?token={quote(token)}"
    text = (
        f"Ola, {user.get('name', '')}.\n\n"
        "Confirme seu cadastro no Freela'B Hub acessando o link abaixo:\n"
        f"{link}\n\n"
        "Se voce nao fez esse cadastro, ignore este e-mail."
    )
    return send_email(user["email"], "Confirme seu cadastro no Freela'B Hub", text)


class Handler(SimpleHTTPRequestHandler):
    server_version = "FreelaBHub/1.0"

    def translate_path(self, path):
        parsed = urlparse(path)
        clean = parsed.path.strip("/") or "index.html"
        target = (ROOT / clean).resolve()
        if ROOT not in target.parents and target != ROOT:
            return str(ROOT / "index.html")
        return str(target)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()

    def json_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def send_json(self, payload, status=HTTPStatus.OK, cookie=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def current_session(self):
        token = parse_cookie(self.headers.get("Cookie")).get("freelab_session")
        if not token:
            return None
        return sessions().get(token)

    def current_admin(self):
        token = parse_cookie(self.headers.get("Cookie")).get("freelab_admin")
        if not token:
            return None
        item = sessions().get(token)
        return item if item and item.get("role") == "admin" else None

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/verify":
            token = parse_qs(parsed.query).get("token", [""])[0]
            data = state()
            user = next((u for u in data.get("users", []) if u.get("emailToken") == token and token), None)
            if not user:
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/?verified=invalid")
                self.end_headers()
                return
            user["verified"] = True
            user.pop("emailToken", None)
            session_token = create_session(user["email"])
            data["sessionEmail"] = user["email"]
            audit(data, "verify_email_link", email=user["email"])
            save_state(data)
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Set-Cookie", f"freelab_session={session_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}")
            self.send_header("Location", "/?verified=ok")
            self.end_headers()
            return
        if parsed.path == "/api/state":
            current = self.current_session()
            if not current:
                return self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return self.send_json({"state": public_state(state(), current["email"])})
        if parsed.path == "/api/admin/summary":
            if not self.current_admin():
                return self.send_json({"error": "admin_required"}, HTTPStatus.UNAUTHORIZED)
            data = state()
            users = [public_user(user) for user in data.get("users", [])]
            return self.send_json({
                "users": users,
                "classifieds": data.get("classifieds", []),
                "threads": data.get("threads", []),
                "payments": data.get("payments", []),
                "auditLog": data.get("auditLog", [])[-100:],
                "metrics": {
                    "users": len(users),
                    "labs": len([u for u in users if u.get("role") == "lab"]),
                    "freelancers": len([u for u in users if u.get("role") == "freelancer"]),
                    "blocked": len([u for u in users if u.get("blocked")]),
                    "classifieds": len(data.get("classifieds", [])),
                    "threads": len(data.get("threads", [])),
                    "payments": len(data.get("payments", [])),
                },
            })
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/login":
                body = self.json_body()
                email = body.get("email", "").strip().lower()
                data = state()
                user = next((u for u in data.get("users", []) if u.get("email", "").lower() == email), None)
                if not user or user.get("blocked") or not password_ok(body.get("password", ""), user.get("passwordHash")):
                    audit(data, "login_failed", email=email)
                    save_state(data)
                    return self.send_json({"error": "invalid_login"}, HTTPStatus.UNAUTHORIZED)
                if not user.get("verified"):
                    return self.send_json({"error": "email_not_verified"}, HTTPStatus.FORBIDDEN)
                token = create_session(email)
                data["sessionEmail"] = email
                audit(data, "login", email=email)
                save_state(data)
                cookie = f"freelab_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"
                return self.send_json({"state": public_state(data, email), "user": public_user(user)}, cookie=cookie)
            if parsed.path == "/api/register":
                body = self.json_body()
                data = state()
                email = body.get("email", "").strip().lower()
                if not email or any(u.get("email", "").lower() == email for u in data.get("users", [])):
                    return self.send_json({"error": "email_exists"}, HTTPStatus.CONFLICT)
                user = {
                    "id": body.get("id") or secrets.token_urlsafe(12),
                    "role": body.get("role", "freelancer"),
                    "name": body.get("name", "").strip(),
                    "city": body.get("city", "").strip(),
                    "country": body.get("country", "Brasil"),
                    "address": body.get("address", "").strip(),
                    "countryCode": body.get("countryCode", "+55"),
                    "email": email,
                    "phone": body.get("phone", "").strip(),
                    "passwordHash": password_hash(body.get("password", "")),
                    "verified": False,
                    "blocked": False,
                    "avatar": "",
                    "specialties": ["Ceramica"],
                    "bio": "",
                    "adTitle": "",
                    "adSpecialty": "Ceramica",
                    "adValue": "",
                    "adElements": "",
                    "adDescription": "",
                    "album": [],
                    "emailToken": secrets.token_urlsafe(24),
                }
                data.setdefault("users", []).append(user)
                audit(data, "register", email=email)
                email_sent = False
                try:
                    email_sent = send_verification_email(user)
                    audit(data, "verification_email_sent" if email_sent else "verification_email_not_configured", email=email)
                except Exception as exc:
                    audit(data, "verification_email_failed", email=email, error=str(exc)[:160])
                save_state(data)
                return self.send_json({"user": public_user(user), "state": public_state(data), "emailSent": email_sent, "emailConfigured": bool(SMTP_HOST)})
            if parsed.path == "/api/verify-email":
                body = self.json_body()
                data = state()
                token = body.get("token", "")
                user = next((u for u in data.get("users", []) if (token and u.get("emailToken") == token) or u.get("email", "").lower() == body.get("email", "").lower()), None)
                if not user:
                    return self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                user["verified"] = True
                user.pop("emailToken", None)
                token = create_session(user["email"])
                data["sessionEmail"] = user["email"]
                audit(data, "verify_email", email=user["email"])
                save_state(data)
                cookie = f"freelab_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"
                return self.send_json({"state": public_state(data, user["email"])}, cookie=cookie)
            if parsed.path == "/api/state":
                current = self.current_session()
                if not current:
                    return self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                body = self.json_body()
                incoming = body.get("state", {})
                data = state()
                if "users" in incoming:
                    data["users"] = merge_users(data.get("users", []), incoming.get("users", []))
                for key in ["classifieds", "threads", "externalConnections", "language"]:
                    if key in incoming:
                        data[key] = incoming[key]
                data["sessionEmail"] = current["email"]
                audit(data, "state_save", email=current["email"])
                save_state(data)
                return self.send_json({"ok": True, "state": public_state(data, current["email"])})
            if parsed.path == "/api/geocode":
                body = self.json_body()
                try:
                    result = geocode(", ".join([body.get("address", ""), body.get("city", ""), body.get("country", "")]))
                except Exception:
                    result = None
                return self.send_json({"location": result})
            if parsed.path == "/api/checkout":
                current = self.current_session()
                if not current:
                    return self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                body = self.json_body()
                plan = body.get("plan", "freelancer")
                env_key = "STRIPE_PAYMENT_LINK_LAB" if plan == "lab" else "STRIPE_PAYMENT_LINK_FREELANCER"
                payment_url = os.environ.get(env_key, "")
                data = state()
                data.setdefault("payments", []).append({"id": secrets.token_urlsafe(10), "at": now(), "email": current["email"], "plan": plan, "status": "pending_gateway"})
                audit(data, "checkout_attempt", email=current["email"], plan=plan)
                save_state(data)
                return self.send_json({"paymentUrl": payment_url, "status": "needs_gateway_key" if not payment_url else "ready"})
            if parsed.path == "/api/audit":
                body = self.json_body()
                current = self.current_session()
                data = state()
                audit(data, "page_event", email=(current or {}).get("email", ""), page=body.get("page", ""), action=body.get("action", "view"))
                save_state(data)
                return self.send_json({"ok": True})
            if parsed.path == "/api/logout":
                token = parse_cookie(self.headers.get("Cookie")).get("freelab_session")
                current = self.current_session()
                if current:
                    data = state()
                    audit(data, "logout", email=current.get("email", ""))
                    save_state(data)
                delete_session(token)
                cookie = "freelab_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
                return self.send_json({"ok": True}, cookie=cookie)
            if parsed.path == "/api/admin/login":
                body = self.json_body()
                if body.get("email", "").lower() != ADMIN_EMAIL or body.get("password", "") != ADMIN_PASSWORD:
                    return self.send_json({"error": "invalid_admin"}, HTTPStatus.UNAUTHORIZED)
                token = create_session(ADMIN_EMAIL, "admin")
                data = state()
                audit(data, "admin_login", email=ADMIN_EMAIL)
                save_state(data)
                cookie = f"freelab_admin={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"
                return self.send_json({"ok": True}, cookie=cookie)
            if parsed.path == "/api/admin/user":
                if not self.current_admin():
                    return self.send_json({"error": "admin_required"}, HTTPStatus.UNAUTHORIZED)
                body = self.json_body()
                data = state()
                user = next((u for u in data.get("users", []) if u.get("id") == body.get("id")), None)
                if not user:
                    return self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                if body.get("delete"):
                    data["users"] = [item for item in data.get("users", []) if item.get("id") != user.get("id")]
                    data["threads"] = [thread for thread in data.get("threads", []) if user.get("id") not in thread.get("participants", [])]
                    audit(data, "admin_user_delete", id=user["id"], email=user["email"])
                    save_state(data)
                    return self.send_json({"ok": True})
                if "verified" in body:
                    user["verified"] = bool(body["verified"])
                if "blocked" in body:
                    user["blocked"] = bool(body["blocked"])
                if "role" in body:
                    user["role"] = body["role"]
                audit(data, "admin_user_update", id=user["id"], email=user["email"])
                save_state(data)
                return self.send_json({"user": public_user(user)})
            if parsed.path == "/api/admin/content":
                if not self.current_admin():
                    return self.send_json({"error": "admin_required"}, HTTPStatus.UNAUTHORIZED)
                body = self.json_body()
                data = state()
                kind = body.get("kind")
                item_id = body.get("id")
                if kind == "classified":
                    data["classifieds"] = [item for item in data.get("classifieds", []) if item.get("id") != item_id]
                elif kind == "thread":
                    data["threads"] = [item for item in data.get("threads", []) if item.get("id") != item_id]
                elif kind == "payment":
                    for payment in data.get("payments", []):
                        if payment.get("id") == item_id:
                            payment["status"] = body.get("status", payment.get("status"))
                else:
                    return self.send_json({"error": "invalid_kind"}, HTTPStatus.BAD_REQUEST)
                audit(data, "admin_content_update", kind=kind, id=item_id)
                save_state(data)
                return self.send_json({"ok": True})
        except json.JSONDecodeError:
            return self.send_json({"error": "invalid_json"}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            return self.send_json({"error": "server_error", "detail": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)


def run():
    ensure_data()
    port = int(os.environ.get("PORT", "8801"))
    host = os.environ.get("HOST", "127.0.0.1")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Freela'B Hub backend em http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
