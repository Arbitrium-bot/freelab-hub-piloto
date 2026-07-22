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
from urllib.error import HTTPError
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
SMTP_SSL = os.environ.get("SMTP_SSL", "false").lower() == "true"
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM = os.environ.get("RESEND_FROM", SMTP_FROM)
EMAIL_CODE_TTL = 60 * 60


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
        "employmentPosts": [],
        "threads": [],
        "externalConnections": [],
        "reports": [],
        "notifications": [],
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
    data.setdefault("classifieds", [])
    data.setdefault("employmentPosts", [])
    data.setdefault("externalConnections", [])
    data.setdefault("reports", [])
    data.setdefault("notifications", [])
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
    clean.pop("passwordResetToken", None)
    clean.pop("passwordResetExpires", None)
    clean.pop("lastVerificationEmailAt", None)
    return clean


def public_state(data, email=""):
    clean = dict(data)
    clean["users"] = [public_user(user) for user in data.get("users", []) if not user.get("blocked")]
    clean["sessionEmail"] = email or clean.get("sessionEmail", "")
    return clean


def normalize_digits(value):
    return "".join(ch for ch in str(value or "") if ch.isdigit())


def valid_document(value):
    digits = normalize_digits(value)
    return len(digits) in (11, 14)


def valid_phone(value):
    digits = normalize_digits(value)
    return 8 <= len(digits) <= 15


def event_count(data, event_type, email="", seconds=900):
    cutoff = now() - seconds
    return sum(1 for item in data.get("auditLog", []) if item.get("type") == event_type and item.get("email", "").lower() == email.lower() and int(item.get("at", 0)) >= cutoff)


def rate_limited(data, event_type, email="", limit=5, seconds=900):
    return event_count(data, event_type, email, seconds) >= limit


def current_user_from_session(data, current):
    if not current:
        return None
    email = current.get("email", "").lower()
    return next((u for u in data.get("users", []) if u.get("email", "").lower() == email), None)


def merge_current_user(existing_users, incoming_users, current_email):
    by_id = {u.get("id"): u for u in incoming_users if u.get("id")}
    by_email = {u.get("email", "").lower(): u for u in incoming_users if u.get("email")}
    result = []
    for user in existing_users:
        if user.get("email", "").lower() != current_email.lower():
            result.append(user)
            continue
        incoming = by_id.get(user.get("id")) or by_email.get(current_email.lower()) or {}
        allowed = ["name", "document", "postalCode", "city", "country", "region", "district", "address", "countryCode", "phone", "avatar", "specialties", "bio", "adTitle", "adSpecialty", "adValue", "adElements", "adDescription", "album", "lat", "lng"]
        updated = dict(user)
        for key in allowed:
            if key in incoming:
                updated[key] = incoming[key]
        result.append(updated)
    return result


def merge_owned_items(existing, incoming, owner_id, allowed_keys):
    incoming_by_id = {item.get("id"): item for item in incoming if item.get("id")}
    used = set()
    result = []
    for item in existing:
        if item.get("ownerId") != owner_id:
            result.append(item)
            continue
        incoming_item = incoming_by_id.get(item.get("id"))
        if not incoming_item:
            result.append(item)
            continue
        updated = dict(item)
        for key in allowed_keys:
            if key in incoming_item:
                updated[key] = incoming_item[key]
        updated["ownerId"] = owner_id
        result.append(updated)
        used.add(item.get("id"))
    for item in incoming:
        if item.get("id") in used or item.get("ownerId") != owner_id:
            continue
        clean = {key: item.get(key, "") for key in allowed_keys}
        clean["id"] = item.get("id") or secrets.token_urlsafe(10)
        clean["ownerId"] = owner_id
        result.insert(0, clean)
    return result


def merge_participant_threads(existing, incoming, user_id):
    incoming_by_id = {thread.get("id"): thread for thread in incoming if thread.get("id")}
    used = set()
    result = []
    for thread in existing:
        participants = thread.get("participants", [])
        if user_id not in participants:
            result.append(thread)
            continue
        incoming_thread = incoming_by_id.get(thread.get("id"))
        if incoming_thread and user_id in incoming_thread.get("participants", []):
            clean = dict(thread)
            clean["messages"] = incoming_thread.get("messages", thread.get("messages", []))[-200:]
            for key in ["active", "classifiedId", "employmentId", "jobUserId", "freelancerUserId"]:
                if key in incoming_thread:
                    clean[key] = incoming_thread[key]
            result.append(clean)
            used.add(thread.get("id"))
        else:
            result.append(thread)
    for thread in incoming:
        if thread.get("id") in used or user_id not in thread.get("participants", []):
            continue
        clean = dict(thread)
        clean["id"] = clean.get("id") or secrets.token_urlsafe(10)
        clean["messages"] = clean.get("messages", [])[-200:]
        result.insert(0, clean)
    return result


def send_notification_email(data, to_user, subject, text, event_type="notification_email"):
    if not to_user or not to_user.get("email") or not email_ready():
        return False
    try:
        sent = send_email(to_user["email"], subject, text)
        audit(data, event_type + ("_sent" if sent else "_not_configured"), email=to_user.get("email", ""))
        return sent
    except Exception as exc:
        audit(data, event_type + "_failed", email=to_user.get("email", ""), error=str(exc)[:160])
        return False


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
    if RESEND_API_KEY:
        payload = json.dumps({
            "from": RESEND_FROM,
            "to": [to],
            "subject": subject,
            "text": text,
        }).encode("utf-8")
        request = Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=15) as response:
                return 200 <= response.status < 300
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Resend API falhou: {exc.code} {detail[:180]}")

    if not SMTP_HOST:
        return False
    message = EmailMessage()
    message["From"] = SMTP_FROM
    message["To"] = to
    message["Subject"] = subject
    message.set_content(text)
    if SMTP_SSL:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=12) as server:
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(message)
    elif SMTP_TLS:
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


def generate_email_code(user):
    code = f"{secrets.randbelow(900000) + 100000}"
    user["emailCodeHash"] = password_hash(code)
    user["emailCodeExpires"] = now() + EMAIL_CODE_TTL
    user["emailToken"] = secrets.token_urlsafe(24)
    return code


def email_code_ok(user, code):
    if not code or int(user.get("emailCodeExpires", 0)) < now():
        return False
    return password_ok("".join(ch for ch in str(code) if ch.isdigit()), user.get("emailCodeHash", ""))


def mark_email_verified(data, user, audit_type):
    user["verified"] = True
    user.pop("emailToken", None)
    user.pop("emailCodeHash", None)
    user.pop("emailCodeExpires", None)
    token = create_session(user["email"])
    data["sessionEmail"] = user["email"]
    audit(data, audit_type, email=user["email"])
    save_state(data)
    return token


def remove_user_data(data, user):
    user_id = user.get("id")
    email = user.get("email", "").lower()
    data["users"] = [item for item in data.get("users", []) if item.get("id") != user_id and item.get("email", "").lower() != email]
    data["threads"] = [thread for thread in data.get("threads", []) if user_id not in thread.get("participants", [])]
    data["classifieds"] = [item for item in data.get("classifieds", []) if item.get("ownerId") != user_id]
    data["employmentPosts"] = [item for item in data.get("employmentPosts", []) if item.get("ownerId") != user_id]
    data["payments"] = [item for item in data.get("payments", []) if item.get("email", "").lower() != email]
    data["externalConnections"] = [
        item for item in data.get("externalConnections", [])
        if item.get("userId") != user_id and item.get("targetId") != user_id
    ]
    if data.get("sessionEmail", "").lower() == email:
        data["sessionEmail"] = ""


def send_verification_email(user):
    code = generate_email_code(user)
    text = (
        f"Ola, {user.get('name', '')}.\n\n"
        "Seu codigo de confirmacao no Freela'B Hub e:\n\n"
        f"{code}\n\n"
        "Digite esse codigo na tela de confirmacao do cadastro. Ele expira em 1 hora.\n\n"
        "Se voce nao fez esse cadastro, ignore este e-mail."
    )
    return send_email(user["email"], "Codigo de confirmacao Freela'B Hub", text)


def send_password_reset_email(user):
    token = secrets.token_urlsafe(24)
    user["passwordResetToken"] = token
    user["passwordResetExpires"] = now() + 3600
    link = f"{APP_BASE_URL}/?resetToken={quote(token)}"
    text = (
        f"Ola, {user.get('name', '')}.\n\n"
        "Recebemos uma solicitacao para redefinir sua senha no Freela'B Hub.\n"
        "Acesse o link abaixo em ate 1 hora para criar uma nova senha:\n"
        f"{link}\n\n"
        "Se voce nao pediu isso, ignore este e-mail."
    )
    return send_email(user["email"], "Redefina sua senha no Freela'B Hub", text)


def email_ready():
    return bool(RESEND_API_KEY and RESEND_FROM) or bool(SMTP_HOST and SMTP_FROM)


def session_cookie(name, token):
    secure = "; Secure" if APP_BASE_URL.startswith("https://") else ""
    return f"{name}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}{secure}"


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
            session_token = mark_email_verified(data, user, "verify_email_link")
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Set-Cookie", session_cookie("freelab_session", session_token))
            self.send_header("Location", "/?verified=ok")
            self.end_headers()
            return
        if parsed.path == "/api/state":
            current = self.current_session()
            if not current:
                return self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            data = state()
            user = current_user_from_session(data, current)
            if not user or user.get("blocked") or not user.get("verified"):
                return self.send_json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
            return self.send_json({"state": public_state(data, current["email"])})
        if parsed.path == "/api/admin/summary":
            if not self.current_admin():
                return self.send_json({"error": "admin_required"}, HTTPStatus.UNAUTHORIZED)
            data = state()
            users = [public_user(user) for user in data.get("users", [])]
            return self.send_json({
                "users": users,
                "classifieds": data.get("classifieds", []),
                "employmentPosts": data.get("employmentPosts", []),
                "threads": data.get("threads", []),
                "payments": data.get("payments", []),
                "deletionRequests": data.get("deletionRequests", []),
                "reports": data.get("reports", []),
                "notifications": data.get("notifications", [])[-100:],
                "auditLog": data.get("auditLog", [])[-150:],
                "emailConfigured": email_ready(),
                "metrics": {
                    "users": len(users),
                    "labs": len([u for u in users if u.get("role") == "lab"]),
                    "freelancers": len([u for u in users if u.get("role") == "freelancer"]),
                    "blocked": len([u for u in users if u.get("blocked")]),
                    "classifieds": len(data.get("classifieds", [])),
                    "employmentPosts": len(data.get("employmentPosts", [])),
                    "threads": len(data.get("threads", [])),
                    "payments": len(data.get("payments", [])),
                    "deletionRequests": len(data.get("deletionRequests", [])),
                    "reports": len(data.get("reports", [])),
                    "openReports": len([r for r in data.get("reports", []) if r.get("status", "open") != "done"]),
                    "notifications": len(data.get("notifications", [])),
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
                if rate_limited(data, "login_failed", email, limit=8, seconds=900):
                    return self.send_json({"error": "too_many_attempts"}, HTTPStatus.TOO_MANY_REQUESTS)
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
                cookie = session_cookie("freelab_session", token)
                return self.send_json({"state": public_state(data, email), "user": public_user(user)}, cookie=cookie)
            if parsed.path == "/api/register":
                body = self.json_body()
                data = state()
                email = body.get("email", "").strip().lower()
                if rate_limited(data, "register_attempt", email or self.client_address[0], limit=6, seconds=3600):
                    return self.send_json({"error": "too_many_attempts"}, HTTPStatus.TOO_MANY_REQUESTS)
                audit(data, "register_attempt", email=email or self.client_address[0])
                if not email or any(u.get("email", "").lower() == email for u in data.get("users", [])):
                    return self.send_json({"error": "email_exists"}, HTTPStatus.CONFLICT)
                if len(body.get("password", "")) < 6:
                    return self.send_json({"error": "weak_password"}, HTTPStatus.BAD_REQUEST)
                if not valid_document(body.get("document", "")):
                    return self.send_json({"error": "invalid_document"}, HTTPStatus.BAD_REQUEST)
                if not valid_phone(body.get("phone", "")):
                    return self.send_json({"error": "invalid_phone"}, HTTPStatus.BAD_REQUEST)
                user = {
                    "id": body.get("id") or secrets.token_urlsafe(12),
                    "role": body.get("role", "freelancer"),
                    "name": body.get("name", "").strip(),
                    "city": body.get("city", "").strip(),
                    "country": body.get("country", "Brasil"),
                    "address": body.get("address", "").strip(),
                    "document": body.get("document", "").strip(),
                    "postalCode": body.get("postalCode", "").strip(),
                    "region": body.get("region", "").strip(),
                    "district": body.get("district", "").strip(),
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
                return self.send_json({"user": public_user(user), "state": public_state(data), "emailSent": email_sent, "emailConfigured": email_ready()})
            if parsed.path == "/api/verify-email":
                body = self.json_body()
                data = state()
                token = body.get("token", "")
                email = body.get("email", "").strip().lower()
                code = body.get("code", "")
                user = None
                if token:
                    user = next((u for u in data.get("users", []) if u.get("emailToken") == token), None)
                elif email and code:
                    user = next((u for u in data.get("users", []) if u.get("email", "").lower() == email and email_code_ok(u, code)), None)
                if not user:
                    return self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                token = mark_email_verified(data, user, "verify_email")
                cookie = session_cookie("freelab_session", token)
                return self.send_json({"state": public_state(data, user["email"])}, cookie=cookie)
            if parsed.path == "/api/resend-verification":
                body = self.json_body()
                data = state()
                user = next((u for u in data.get("users", []) if u.get("email", "").lower() == body.get("email", "").strip().lower()), None)
                if not user:
                    return self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                if user.get("verified"):
                    return self.send_json({"ok": True, "alreadyVerified": True})
                if rate_limited(data, "verification_email_resent", user["email"], limit=4, seconds=900):
                    return self.send_json({"error": "too_many_attempts"}, HTTPStatus.TOO_MANY_REQUESTS)
                try:
                    sent = send_verification_email(user)
                    audit(data, "verification_email_resent" if sent else "verification_email_not_configured", email=user["email"])
                    save_state(data)
                    return self.send_json({"ok": sent, "emailSent": sent, "emailConfigured": email_ready()})
                except Exception as exc:
                    audit(data, "verification_email_failed", email=user["email"], error=str(exc)[:160])
                    save_state(data)
                    return self.send_json({"error": "email_failed", "detail": str(exc)}, HTTPStatus.BAD_GATEWAY)
            if parsed.path == "/api/request-password-reset":
                body = self.json_body()
                data = state()
                email = body.get("email", "").strip().lower()
                user = next((u for u in data.get("users", []) if u.get("email", "").lower() == email), None)
                if rate_limited(data, "password_reset_email_sent", email, limit=4, seconds=900):
                    return self.send_json({"error": "too_many_attempts"}, HTTPStatus.TOO_MANY_REQUESTS)
                if user:
                    try:
                        sent = send_password_reset_email(user)
                        audit(data, "password_reset_email_sent" if sent else "password_reset_email_not_configured", email=email)
                    except Exception as exc:
                        audit(data, "password_reset_email_failed", email=email, error=str(exc)[:160])
                        save_state(data)
                        return self.send_json({"error": "email_failed", "detail": str(exc)}, HTTPStatus.BAD_GATEWAY)
                    save_state(data)
                    return self.send_json({"ok": True, "emailSent": sent, "emailConfigured": email_ready()})
                audit(data, "password_reset_requested_unknown_email", email=email)
                save_state(data)
                return self.send_json({"ok": True, "emailSent": False, "emailConfigured": email_ready()})
            if parsed.path == "/api/reset-password":
                body = self.json_body()
                token = body.get("token", "")
                password = body.get("password", "")
                if len(password) < 6:
                    return self.send_json({"error": "weak_password"}, HTTPStatus.BAD_REQUEST)
                data = state()
                user = next((u for u in data.get("users", []) if token and u.get("passwordResetToken") == token), None)
                if not user or int(user.get("passwordResetExpires", 0)) < now():
                    return self.send_json({"error": "invalid_or_expired_token"}, HTTPStatus.BAD_REQUEST)
                user["passwordHash"] = password_hash(password)
                user.pop("passwordResetToken", None)
                user.pop("passwordResetExpires", None)
                audit(data, "password_reset_complete", email=user["email"])
                save_state(data)
                return self.send_json({"ok": True})
            if parsed.path == "/api/state":
                current = self.current_session()
                if not current:
                    return self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                body = self.json_body()
                incoming = body.get("state", {})
                data = state()
                current_user = current_user_from_session(data, current)
                if not current_user or current_user.get("blocked") or not current_user.get("verified"):
                    return self.send_json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
                if "users" in incoming:
                    data["users"] = merge_current_user(data.get("users", []), incoming.get("users", []), current["email"])
                owner_id = current_user.get("id")
                if "classifieds" in incoming:
                    data["classifieds"] = merge_owned_items(data.get("classifieds", []), incoming.get("classifieds", []), owner_id, ["id", "ownerId", "title", "value", "category", "city", "condition", "brand", "description", "createdAt", "status"])
                if "employmentPosts" in incoming:
                    data["employmentPosts"] = merge_owned_items(data.get("employmentPosts", []), incoming.get("employmentPosts", []), owner_id, ["id", "ownerId", "company", "title", "type", "mode", "salary", "schedule", "city", "benefits", "description", "createdAt", "status"])
                if "threads" in incoming:
                    data["threads"] = merge_participant_threads(data.get("threads", []), incoming.get("threads", []), owner_id)
                if "externalConnections" in incoming:
                    data["externalConnections"] = incoming.get("externalConnections", [])
                if "language" in incoming:
                    data["language"] = incoming.get("language")
                data["sessionEmail"] = current["email"]
                audit(data, "state_save", email=current["email"], users=len(data.get("users", [])), threads=len(data.get("threads", [])))
                save_state(data)
                return self.send_json({"ok": True, "state": public_state(data, current["email"])})
            if parsed.path == "/api/geocode":
                body = self.json_body()
                try:
                    result = geocode(", ".join([body.get("address", ""), body.get("city", ""), body.get("country", "")]))
                except Exception:
                    result = None
                return self.send_json({"location": result})
            if parsed.path == "/api/report":
                current = self.current_session()
                if not current:
                    return self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                body = self.json_body()
                data = state()
                reporter = current_user_from_session(data, current)
                if not reporter or reporter.get("blocked") or not reporter.get("verified"):
                    return self.send_json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
                if rate_limited(data, "report_created", reporter.get("email", ""), limit=10, seconds=3600):
                    return self.send_json({"error": "too_many_attempts"}, HTTPStatus.TOO_MANY_REQUESTS)
                report = {
                    "id": secrets.token_urlsafe(10),
                    "at": now(),
                    "reporterId": reporter.get("id"),
                    "reporterEmail": reporter.get("email"),
                    "targetId": body.get("targetId", ""),
                    "targetKind": body.get("targetKind", "user"),
                    "reason": body.get("reason", "").strip()[:600],
                    "status": "open",
                }
                data.setdefault("reports", []).append(report)
                audit(data, "report_created", email=reporter.get("email", ""), id=report["id"], kind=report["targetKind"])
                save_state(data)
                return self.send_json({"ok": True, "report": report})
            if parsed.path == "/api/notify":
                current = self.current_session()
                if not current:
                    return self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                body = self.json_body()
                data = state()
                sender = current_user_from_session(data, current)
                target = next((u for u in data.get("users", []) if u.get("id") == body.get("targetId")), None)
                if not sender or sender.get("blocked") or not sender.get("verified"):
                    return self.send_json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
                if not target or target.get("blocked") or target.get("id") == sender.get("id"):
                    return self.send_json({"ok": False, "emailSent": False})
                subject = "Nova mensagem no Freela'B Hub"
                text = f"Olá, {target.get('name', '')}.\n\n{sender.get('name', 'Um usuário')} enviou uma mensagem pelo Freela'B Hub.\nAcesse: {APP_BASE_URL}\n\nMensagem: {body.get('preview', '')[:300]}"
                sent = send_notification_email(data, target, subject, text, "message_notification_email")
                data.setdefault("notifications", []).append({"id": secrets.token_urlsafe(10), "at": now(), "fromId": sender.get("id"), "toId": target.get("id"), "type": body.get("type", "message"), "emailSent": sent})
                data["notifications"] = data["notifications"][-300:]
                save_state(data)
                return self.send_json({"ok": True, "emailSent": sent, "emailConfigured": email_ready()})
            if parsed.path == "/api/checkout":
                current = self.current_session()
                if not current:
                    return self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                body = self.json_body()
                plan = body.get("plan", "freelancer")
                method = body.get("method", "mercadopago")
                if method == "pix":
                    env_key = "PIX_PAYMENT_LINK_LAB" if plan == "lab" else "PIX_PAYMENT_LINK_FREELANCER"
                elif method == "play":
                    env_key = "GOOGLE_PLAY_PRODUCT_LAB" if plan == "lab" else "GOOGLE_PLAY_PRODUCT_FREELANCER"
                else:
                    env_key = "MERCADO_PAGO_LINK_LAB" if plan == "lab" else "MERCADO_PAGO_LINK_FREELANCER"
                payment_url = os.environ.get(env_key, "") or os.environ.get("STRIPE_PAYMENT_LINK_LAB" if plan == "lab" else "STRIPE_PAYMENT_LINK_FREELANCER", "")
                data = state()
                data.setdefault("payments", []).append({"id": secrets.token_urlsafe(10), "at": now(), "email": current["email"], "plan": plan, "method": method, "status": "pending_gateway" if not payment_url else "checkout_created"})
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
            if parsed.path == "/api/account-deletion-request":
                body = self.json_body()
                email = body.get("email", "").strip().lower()
                if not email or "@" not in email:
                    return self.send_json({"error": "invalid_email"}, HTTPStatus.BAD_REQUEST)
                data = state()
                request_item = {
                    "id": secrets.token_urlsafe(10),
                    "at": now(),
                    "email": email,
                    "reason": body.get("reason", "").strip()[:600],
                    "status": "pending",
                }
                data.setdefault("deletionRequests", []).append(request_item)
                audit(data, "account_deletion_requested", email=email, id=request_item["id"])
                save_state(data)
                return self.send_json({"ok": True})
            if parsed.path == "/api/delete-account":
                current = self.current_session()
                if not current:
                    return self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                body = self.json_body()
                data = state()
                user = next((u for u in data.get("users", []) if u.get("email", "").lower() == current["email"]), None)
                if not user:
                    return self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                if not password_ok(body.get("password", ""), user.get("passwordHash", "")):
                    return self.send_json({"error": "invalid_password"}, HTTPStatus.UNAUTHORIZED)
                email = user.get("email", "")
                user_id = user.get("id", "")
                remove_user_data(data, user)
                audit(data, "account_deleted_by_user", email=email, id=user_id)
                save_state(data)
                token = parse_cookie(self.headers.get("Cookie")).get("freelab_session")
                delete_session(token)
                cookie = "freelab_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
                return self.send_json({"ok": True}, cookie=cookie)
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
                cookie = session_cookie("freelab_admin", token)
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
                    user_id = user.get("id", "")
                    email = user.get("email", "")
                    remove_user_data(data, user)
                    audit(data, "admin_user_delete", id=user_id, email=email)
                    save_state(data)
                    return self.send_json({"ok": True})
                if "verified" in body:
                    user["verified"] = bool(body["verified"])
                if "blocked" in body:
                    user["blocked"] = bool(body["blocked"])
                if "role" in body:
                    user["role"] = body["role"]
                if body.get("resendEmail"):
                    try:
                        sent = send_verification_email(user)
                        audit(data, "admin_verification_email_sent" if sent else "admin_verification_email_not_configured", id=user["id"], email=user["email"])
                        save_state(data)
                        return self.send_json({"user": public_user(user), "emailSent": sent, "emailConfigured": email_ready()})
                    except Exception as exc:
                        audit(data, "admin_verification_email_failed", id=user["id"], email=user["email"], error=str(exc)[:160])
                        save_state(data)
                        return self.send_json({"error": "email_failed", "detail": str(exc)}, HTTPStatus.BAD_GATEWAY)
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
                elif kind == "employment":
                    data["employmentPosts"] = [item for item in data.get("employmentPosts", []) if item.get("id") != item_id]
                elif kind == "thread":
                    data["threads"] = [item for item in data.get("threads", []) if item.get("id") != item_id]
                elif kind == "payment":
                    for payment in data.get("payments", []):
                        if payment.get("id") == item_id:
                            payment["status"] = body.get("status", payment.get("status"))
                elif kind == "deletionRequest":
                    for request_item in data.get("deletionRequests", []):
                        if request_item.get("id") == item_id:
                            request_item["status"] = body.get("status", request_item.get("status", "pending"))
                elif kind == "report":
                    for report in data.get("reports", []):
                        if report.get("id") == item_id:
                            report["status"] = body.get("status", report.get("status", "open"))
                            report["note"] = body.get("note", report.get("note", ""))
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
