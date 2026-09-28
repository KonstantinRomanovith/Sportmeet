"""SportMeet: a small, reproducible client/server coursework application."""
from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import click
from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from domain import (CAPABILITY_LABELS, POLICIES, PUBLIC_FEATURES, ROLE_LABELS,
                    ROLE_PERMISSION, SchedulePolicy, TrainingSlot)


ROOT = Path(__file__).resolve().parent
MOSCOW = ZoneInfo("Europe/Moscow")
ROLES = {"participant", "organizer", "venue_admin", "event_admin", "global_admin"}
PASSWORD_METHOD = "scrypt:32768:8:1"
# Business actions are checked in addition to role and object ownership.
ROUTE_ACTIONS = {
    "notifications": "notifications", "read_notification": "notifications",
    "new_activity_request": "propose", "cancel_activity_request": "propose",
    "organizer_requests": "demand", "create_session": "create_session",
    "join_session": "join", "leave_session": "leave", "add_review": "review",
    "report_venue": "report", "cancel_session": "own_sessions",
    "cancel_series": "own_sessions", "reschedule_session": "own_sessions",
    "participants": "applications", "decide_participant": "applications",
    "remove_participant": "applications", "mark_attendance": "attendance",
    "edit_organization_description": "organization_profile",
    "admin_venues": "venue_edits", "edit_venue": "venue_edits",
    "decide_report": "venue_reports", "venue_visibility": "venue_reports",
    "export_venue_report": "venue_export",
    "admin_create_organization": "organizations", "decide_organization": "organizations",
    "decide_membership": "organizations", "revoke_membership": "organizations",
    "decide_session": "publish_sessions", "decide_series": "publish_sessions",
    "admin_cancel_session": "publish_sessions", "decide_review": "reviews_moderation",
    "set_role": "role_assign", "export_report": "system_export",
}


def hash_password(password: str) -> str:
    """Werkzeug's scrypt stores a random salt and derived key, never plaintext."""
    return generate_password_hash(password, method=PASSWORD_METHOD)


def website_link(value: str | None) -> str | None:
    """Make archived hostnames clickable without accepting unsafe URL schemes."""
    value = (value or "").strip()
    if not value or re.search(r"\s|[<>\"']", value):
        return None
    address = value if "://" in value else "https://" + value
    try:
        parsed = urlsplit(address)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or "." not in parsed.hostname:
            return None
        if parsed.username or parsed.password or parsed.port is not None:
            return None
    except ValueError:
        return None
    return address


def phone_link(value: str | None) -> str | None:
    digits = re.sub(r"\D", "", value or "")
    if len(digits) == 10:
        return "tel:+7" + digits
    if len(digits) == 11 and digits[0] in "78":
        return "tel:+7" + digits[1:]
    return None

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS areas (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS venues (
 id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL UNIQUE,
 name TEXT NOT NULL, facility_name TEXT NOT NULL,
 area_id INTEGER NOT NULL REFERENCES areas(id), address TEXT NOT NULL,
 lat REAL NOT NULL CHECK(lat BETWEEN 54 AND 57),
 lon REAL NOT NULL CHECK(lon BETWEEN 36 AND 39),
 usage_period TEXT NOT NULL,
 paid TEXT NOT NULL, paid_comment TEXT, website TEXT, phone TEXT,
 accessibility TEXT, public_status TEXT NOT NULL DEFAULT 'visible'
 CHECK(public_status IN ('visible','hidden')), admin_note TEXT NOT NULL DEFAULT '',
 verified_at TEXT, verified_by INTEGER REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_venues_area ON venues(area_id);
CREATE INDEX IF NOT EXISTS idx_venues_name ON venues(name);
CREATE TABLE IF NOT EXISTS venue_hours (
 venue_id INTEGER NOT NULL REFERENCES venues(id), weekday INTEGER NOT NULL CHECK(weekday BETWEEN 1 AND 7),
 hours TEXT NOT NULL, PRIMARY KEY(venue_id,weekday)
);
CREATE TABLE IF NOT EXISTS sports (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS venue_sports (
 venue_id INTEGER NOT NULL REFERENCES venues(id), sport_id INTEGER NOT NULL REFERENCES sports(id),
 PRIMARY KEY (venue_id, sport_id)
);
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, email TEXT NOT NULL COLLATE NOCASE UNIQUE,
 password_hash TEXT NOT NULL, display_name TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('participant','organizer','venue_admin','event_admin','global_admin')),
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 auth_version INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS organizations (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','rejected')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS organization_memberships (
 user_id INTEGER NOT NULL REFERENCES users(id), organization_id INTEGER NOT NULL REFERENCES organizations(id),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_by INTEGER REFERENCES users(id),
 PRIMARY KEY (user_id,organization_id)
);
CREATE INDEX IF NOT EXISTS idx_membership_org_status ON organization_memberships(organization_id,status);
CREATE TABLE IF NOT EXISTS activity_requests (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 sport_id INTEGER NOT NULL REFERENCES sports(id), area_id INTEGER NOT NULL REFERENCES areas(id),
 note TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open'
 CHECK(status IN ('open','fulfilled','cancelled')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_activity_requests ON activity_requests(status,area_id,sport_id);
CREATE TABLE IF NOT EXISTS event_series (
 id INTEGER PRIMARY KEY, organizer_id INTEGER NOT NULL REFERENCES users(id),
 organization_id INTEGER NOT NULL REFERENCES organizations(id),
 venue_id INTEGER NOT NULL REFERENCES venues(id), sport_id INTEGER NOT NULL REFERENCES sports(id),
 title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 duration_minutes INTEGER NOT NULL CHECK(duration_minutes BETWEEN 30 AND 240),
 capacity INTEGER NOT NULL CHECK(capacity BETWEEN 2 AND 100),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS training_sessions (
 id INTEGER PRIMARY KEY, venue_id INTEGER NOT NULL REFERENCES venues(id),
 sport_id INTEGER NOT NULL REFERENCES sports(id), organizer_id INTEGER NOT NULL REFERENCES users(id),
 organization_id INTEGER REFERENCES organizations(id),
 request_id INTEGER REFERENCES activity_requests(id),
 series_id INTEGER REFERENCES event_series(id),
 title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', starts_at TEXT NOT NULL,
 duration_minutes INTEGER NOT NULL CHECK(duration_minutes BETWEEN 30 AND 240),
 capacity INTEGER NOT NULL CHECK(capacity BETWEEN 2 AND 100),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','published','rejected','cancelled')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sessions_venue_time ON training_sessions(venue_id, starts_at);
CREATE TABLE IF NOT EXISTS registrations (
 id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES training_sessions(id),
 user_id INTEGER NOT NULL REFERENCES users(id),
 status TEXT NOT NULL DEFAULT 'pending'
 CHECK(status IN ('pending','waitlisted','waitlist_approved','active','rejected','cancelled')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(session_id,user_id)
);
CREATE INDEX IF NOT EXISTS idx_registrations_user ON registrations(user_id);
CREATE INDEX IF NOT EXISTS idx_registrations_queue ON registrations(session_id,status,created_at,id);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 session_id INTEGER REFERENCES training_sessions(id), kind TEXT NOT NULL,
 message TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, read_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id,read_at,created_at);
CREATE TABLE IF NOT EXISTS session_attendance (
 session_id INTEGER NOT NULL REFERENCES training_sessions(id),
 user_id INTEGER NOT NULL REFERENCES users(id),
 marked_by INTEGER NOT NULL REFERENCES users(id), marked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(session_id,user_id)
);
CREATE TABLE IF NOT EXISTS venue_edits (
 id INTEGER PRIMARY KEY, venue_id INTEGER NOT NULL REFERENCES venues(id),
 actor_id INTEGER NOT NULL REFERENCES users(id), field_name TEXT NOT NULL,
 old_value TEXT, new_value TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_venue_edits ON venue_edits(venue_id,id);
CREATE TABLE IF NOT EXISTS reviews (
 id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES training_sessions(id),
 user_id INTEGER NOT NULL REFERENCES users(id), rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
 body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
 CHECK(status IN ('pending','approved','rejected')), UNIQUE(session_id,user_id)
);
CREATE TABLE IF NOT EXISTS venue_reports (
 id INTEGER PRIMARY KEY, venue_id INTEGER NOT NULL REFERENCES venues(id),
 user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved','escalated')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY, actor_id INTEGER NOT NULL REFERENCES users(id),
 action TEXT NOT NULL, object_type TEXT NOT NULL, object_id INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def initialize_database(connection: sqlite3.Connection) -> None:
    """Install schema and upgrade an existing database without deleting user data."""
    connection.executescript(SCHEMA)
    if "auth_version" not in {column[1] for column in connection.execute("PRAGMA table_info(users)")}:
        connection.execute("ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0")
    columns = {column[1] for column in connection.execute("PRAGMA table_info(training_sessions)")}
    if "organization_id" not in columns:
        connection.execute("ALTER TABLE training_sessions ADD COLUMN organization_id INTEGER REFERENCES organizations(id)")
    if "request_id" not in columns:
        connection.execute("ALTER TABLE training_sessions ADD COLUMN request_id INTEGER REFERENCES activity_requests(id)")
    if "series_id" not in columns:
        connection.execute("ALTER TABLE training_sessions ADD COLUMN series_id INTEGER REFERENCES event_series(id)")
    venue_columns = {column[1] for column in connection.execute("PRAGMA table_info(venues)")}
    if "verified_at" not in venue_columns:
        connection.execute("ALTER TABLE venues ADD COLUMN verified_at TEXT")
    if "verified_by" not in venue_columns:
        connection.execute("ALTER TABLE venues ADD COLUMN verified_by INTEGER REFERENCES users(id)")
    for column in ("paid_comment", "website", "phone"):
        if column not in venue_columns:
            connection.execute(f"ALTER TABLE venues ADD COLUMN {column} TEXT")
    if "opening_hours" in venue_columns:
        # Older databases duplicated the timetable in venues and venue_hours.
        # Copy any missing days before removing the denormalized legacy column.
        missing = connection.execute("""SELECT v.id,v.opening_hours FROM venues v
            WHERE (SELECT count(*) FROM venue_hours h WHERE h.venue_id=v.id)<7""").fetchall()
        for venue_id, raw_hours in missing:
            days = json.loads(raw_hours)
            if len(days) != 7:
                raise ValueError(f"Incomplete opening hours for venue {venue_id}")
            for weekday, day in enumerate(days, 1):
                connection.execute("""INSERT OR IGNORE INTO venue_hours(venue_id,weekday,hours)
                    VALUES (?,?,?)""", (venue_id, weekday, day["Hours"]))
        connection.execute("ALTER TABLE venues DROP COLUMN opening_hours")
    if "description" not in {column[1] for column in connection.execute("PRAGMA table_info(organizations)")}:
        connection.execute("ALTER TABLE organizations ADD COLUMN description TEXT NOT NULL DEFAULT ''")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_sessions_organization ON training_sessions(organization_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_sessions_series ON training_sessions(series_id,starts_at)")
    connection.commit()
    original = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='registrations'"
    ).fetchone()[0]
    if "updated_at" in original and "'waitlist_approved'" in original:
        return
    # The previous table allowed only active/cancelled. SQLite requires a table
    # rebuild to change CHECK; all existing registrations retain their status.
    connection.execute("PRAGMA foreign_keys=OFF")
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""CREATE TABLE registrations_new (
            id INTEGER PRIMARY KEY,
            session_id INTEGER NOT NULL REFERENCES training_sessions(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending','waitlisted','waitlist_approved','active','rejected','cancelled')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(session_id,user_id)
        )""")
        updated_column = "updated_at" if "updated_at" in original else "created_at"
        connection.execute(f"""INSERT INTO registrations_new
            (id,session_id,user_id,status,created_at,updated_at)
            SELECT id,session_id,user_id,status,created_at,{updated_column} FROM registrations""")
        connection.execute("DROP TABLE registrations")
        connection.execute("ALTER TABLE registrations_new RENAME TO registrations")
        connection.execute("CREATE INDEX idx_registrations_user ON registrations(user_id)")
        connection.execute("CREATE INDEX idx_registrations_queue ON registrations(session_id,status,created_at,id)")
        if connection.execute("PRAGMA foreign_key_check").fetchone():
            raise sqlite3.IntegrityError("Invalid foreign key after migration")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys=ON")


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    secret_path = Path(app.instance_path) / ".session_secret"
    if not secret_path.exists():
        secret_path.write_text(secrets.token_hex(32), encoding="ascii")
        secret_path.chmod(0o600)
    app.config.update(
        SECRET_KEY=os.environ.get("SPORTMEET_SECRET_KEY", secret_path.read_text().strip()),
        DATABASE=os.environ.get("SPORTMEET_DB", str(Path(app.instance_path) / "sportmeet.sqlite3")),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if config:
        app.config.update(config)

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"], timeout=10)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys=ON")
            g.db.execute("PRAGMA busy_timeout=10000")
        return g.db

    def current_user():
        if "current_user" not in g:
            user_id = session.get("user_id")
            user=db().execute("SELECT * FROM users WHERE id=? AND active=1",(user_id,)).fetchone() if user_id else None
            g.current_user=user if user and session.get("auth_version")==user["auth_version"] else None
        return g.current_user

    def approved_organizations(user_id):
        return db().execute("""SELECT o.id,o.name FROM organizations o
            JOIN organization_memberships m ON m.organization_id=o.id
            WHERE m.user_id=? AND m.status='approved' AND o.status='active'
            ORDER BY o.name""", (user_id,)).fetchall()

    def request_organizations(user_id):
        ids = request.form.getlist("organization_ids")
        name = request.form.get("new_organization", "").strip()
        if len(ids) > 3 or len(name) > 120 or (not ids and not name):
            raise ValueError("Выберите организацию или укажите её название (до 120 символов).")
        selected = set()
        for value in ids:
            try:
                org_id = int(value)
            except ValueError as exc:
                raise ValueError("Неизвестная организация.") from exc
            row = db().execute("SELECT id FROM organizations WHERE id=? AND status='active'", (org_id,)).fetchone()
            if not row:
                raise ValueError("Выбранная организация недоступна.")
            selected.add(org_id)
        if name:
            if len(name) < 3:
                raise ValueError("Название организации должно содержать не менее трёх символов.")
            db().execute("INSERT OR IGNORE INTO organizations(name) VALUES (?)", (name,))
            org = db().execute("SELECT id,status FROM organizations WHERE name=?", (name,)).fetchone()
            if org["status"] == "rejected":
                raise ValueError("Эта организация отклонена. Выберите другую или обратитесь к администратору.")
            selected.add(org["id"])
        for org_id in selected:
            db().execute("""INSERT INTO organization_memberships(user_id,organization_id,status)
                VALUES (?,?,'pending') ON CONFLICT(user_id,organization_id)
                DO UPDATE SET status='pending',requested_at=CURRENT_TIMESTAMP,reviewed_by=NULL
                WHERE status='rejected'""", (user_id, org_id))

    def require(*roles):
        def decorator(func):
            @wraps(func)
            def wrapped(*args, **kwargs):
                user = current_user()
                if not user:
                    return redirect(url_for("login", next=request.path))
                policy = POLICIES[user["role"]]
                if roles and not any(policy.allows(ROLE_PERMISSION[role]) for role in roles):
                    abort(403)
                action=ROUTE_ACTIONS.get(request.endpoint)
                if action and not policy.allows(action):
                    abort(403)
                if (user["role"] == "organizer" and request.endpoint in {
                    "create_session", "cancel_session", "reschedule_session",
                    "participants", "decide_participant", "remove_participant", "organizer_requests",
                    "cancel_series", "mark_attendance"
                } and not approved_organizations(user["id"])):
                    if request.method == "GET":
                        flash("Сначала дождитесь подтверждения связи с организацией.", "error")
                        return redirect(url_for("organizer_organizations"))
                    abort(403, "Организация ещё не подтверждена")
                return func(*args, **kwargs)
            return wrapped
        return decorator

    def audit(action, kind, object_id):
        db().execute("INSERT INTO audit_log(actor_id,action,object_type,object_id) VALUES (?,?,?,?)",
                     (current_user()["id"], action, kind, object_id))

    def notify(user_id, kind, message, session_id=None):
        db().execute("INSERT INTO notifications(user_id,session_id,kind,message) VALUES (?,?,?,?)",
                     (user_id,session_id,kind,message))

    def notify_registrants(session_id, message):
        for row in db().execute("""SELECT user_id FROM registrations
            WHERE session_id=? AND status IN ('pending','waitlisted','waitlist_approved','active')""",(session_id,)):
            notify(row["user_id"],"session",message,session_id)

    def promote_waitlist(item):
        """Called under a write transaction after a seat is released."""
        if item["status"]!="published" or item["starts_at"]<=datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M"):
            return
        if db().execute("SELECT public_status FROM venues WHERE id=?",(item["venue_id"],)).fetchone()[0]!="visible":
            return
        count=db().execute("SELECT count(*) FROM registrations WHERE session_id=? AND status='active'",(item["id"],)).fetchone()[0]
        while count<item["capacity"]:
            waiting=db().execute("""SELECT id,user_id FROM registrations
                WHERE session_id=? AND status='waitlist_approved' ORDER BY created_at,id LIMIT 1""",(item["id"],)).fetchone()
            if not waiting: break
            db().execute("UPDATE registrations SET status='active',updated_at=CURRENT_TIMESTAMP WHERE id=?",(waiting["id"],))
            notify(waiting["user_id"],"seat","Освободилось место: ваша запись подтверждена.",item["id"])
            count+=1

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.before_request
    def csrf_guard():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not session.get("csrf") or not secrets.compare_digest(session["csrf"], request.form.get("csrf", "")):
                abort(400, "Invalid CSRF token")

    @app.context_processor
    def inject_globals():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(24)
        user = current_user()
        requests_count = 0
        if user and user["role"] == "organizer":
            requests_count = db().execute("""SELECT count(*) FROM registrations r
                JOIN training_sessions t ON t.id=r.session_id
                WHERE t.organizer_id=? AND t.status='published' AND t.starts_at>?
                AND r.status IN ('pending','waitlisted')""",
                (user["id"],datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M"))).fetchone()[0]
        organizer_verified = bool(approved_organizations(user["id"])) if user and user["role"] == "organizer" else False
        unread_count = db().execute("SELECT count(*) FROM notifications WHERE user_id=? AND read_at IS NULL",
                                    (user["id"],)).fetchone()[0] if user else 0
        return {"me": user, "csrf": session["csrf"], "now": datetime.now(MOSCOW),
                "requests_count": requests_count, "organizer_verified": organizer_verified,
                "unread_count": unread_count, "role_labels": ROLE_LABELS}

    @app.get("/roles")
    def roles():
        rows=[(ROLE_LABELS[role], [label for action,label in CAPABILITY_LABELS.items()
                                   if POLICIES[role].allows(action)])
              for role in ("participant","organizer","venue_admin","event_admin","global_admin")]
        return render_template("roles.html",guest_features=PUBLIC_FEATURES,roles=rows)

    @app.get("/account")
    @require()
    def account():
        user=current_user()
        allowed=[label for action,label in CAPABILITY_LABELS.items()
                 if POLICIES[user["role"]].allows(action)]
        return render_template("account.html",allowed=allowed,
                               organizations=approved_organizations(user["id"]) if user["role"]=="organizer" else [])

    @app.post("/account/password")
    @require()
    def change_password():
        old=request.form.get("current_password","")
        new=request.form.get("new_password","")
        if (not check_password_hash(current_user()["password_hash"],old)
                or len(new)<10 or len(new)>200 or new!=request.form.get("confirm_password")
                or new==old):
            flash("Проверьте текущий пароль и новый пароль (от 10 символов, два одинаковых ввода).","error")
            return redirect(url_for("account"))
        user_id=current_user()["id"]
        with db():
            db().execute("UPDATE users SET password_hash=?,auth_version=auth_version+1 WHERE id=?",
                         (hash_password(new),user_id))
            audit("change_password","user",user_id)
            version=db().execute("SELECT auth_version FROM users WHERE id=?",(user_id,)).fetchone()[0]
        session.clear()
        session.update(user_id=user_id,auth_version=version,csrf=secrets.token_hex(24))
        flash("Пароль изменён. Другие сеансы этой учётной записи завершены.","success")
        return redirect(url_for("account"))

    @app.get("/notifications")
    @require()
    def notifications():
        rows=db().execute("""SELECT * FROM notifications WHERE user_id=?
            ORDER BY id DESC LIMIT 100""",(current_user()["id"],)).fetchall()
        return render_template("notifications.html",items=rows)

    @app.post("/notifications/<int:notification_id>/read")
    @require()
    def read_notification(notification_id):
        with db():
            changed=db().execute("""UPDATE notifications SET read_at=CURRENT_TIMESTAMP
                WHERE id=? AND user_id=? AND read_at IS NULL""",(notification_id,current_user()["id"]))
            if not changed.rowcount: abort(404)
        return redirect(url_for("notifications"))

    @app.get("/")
    def home():
        conn = db()
        today = datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M")
        counts = {"venues": conn.execute("SELECT count(*) FROM venues WHERE public_status='visible'").fetchone()[0],
                  "sessions": conn.execute("""SELECT count(*) FROM training_sessions t JOIN venues v ON v.id=t.venue_id
                      WHERE t.status='published' AND t.starts_at>=? AND v.public_status='visible'""",
                      (today,)).fetchone()[0]}
        upcoming = conn.execute("""SELECT t.*,v.name AS venue_name,v.address,a.name AS area,
                    s.name AS sport,o.name AS organization_name,
                    (SELECT count(*) FROM registrations r WHERE r.session_id=t.id AND r.status='active') AS enrolled
                    FROM training_sessions t JOIN venues v ON v.id=t.venue_id
                    JOIN areas a ON a.id=v.area_id LEFT JOIN organizations o ON o.id=t.organization_id
                    JOIN sports s ON s.id=t.sport_id WHERE t.status='published' AND t.starts_at>=?
                    AND v.public_status='visible'
                    ORDER BY t.starts_at LIMIT 6""", (today,)).fetchall()
        sports = conn.execute("""SELECT s.id,s.name,
            (SELECT count(*) FROM venue_sports vs JOIN venues v ON v.id=vs.venue_id
             WHERE vs.sport_id=s.id AND v.public_status='visible') AS venue_count,
            (SELECT count(*) FROM training_sessions t JOIN venues v ON v.id=t.venue_id
             WHERE t.sport_id=s.id AND t.status='published' AND t.starts_at>=? AND v.public_status='visible') AS event_count
            FROM sports s ORDER BY s.name""", (today,)).fetchall()
        areas = conn.execute("SELECT name FROM areas ORDER BY name").fetchall()
        return render_template("home.html", counts=counts, upcoming=upcoming, sports=sports, areas=areas)

    @app.get("/sessions")
    def sessions():
        """Public list of future, published sessions that participants can find."""
        conn = db()
        page = max(1, min(request.args.get("page", 1, type=int), 200))
        q = request.args.get("q", "").strip()[:80]
        area = request.args.get("area", "").strip()[:80]
        sport_id = request.args.get("sport_id", type=int)
        available = request.args.get("available") == "1"
        date_from=request.args.get("date_from","").strip()
        date_to=request.args.get("date_to","").strip()
        time_from=request.args.get("time_from","").strip()
        time_to=request.args.get("time_to","").strip()
        view=request.args.get("view","list")
        try:
            for value,pattern in ((date_from,"%Y-%m-%d"),(date_to,"%Y-%m-%d"),
                                  (time_from,"%H:%M"),(time_to,"%H:%M")):
                if value and datetime.strptime(value,pattern).strftime(pattern)!=value:
                    raise ValueError()
        except ValueError: abort(400,"Некорректная дата или время")
        if date_from and date_to and date_from>date_to or time_from and time_to and time_from>time_to:
            abort(400,"Начало диапазона позже конца")
        params = [datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M")]
        condition = "t.status='published' AND t.starts_at>=? AND v.public_status='visible'"
        if q:
            condition += " AND (t.title LIKE ? OR v.name LIKE ? OR v.address LIKE ? OR s.name LIKE ? OR o.name LIKE ?)"
            params.extend([f"%{q}%"] * 5)
        if area:
            condition += " AND a.name=?"
            params.append(area)
        if sport_id is not None:
            condition += " AND t.sport_id=?"
            params.append(sport_id)
        if date_from:
            condition+=" AND substr(t.starts_at,1,10)>=?";params.append(date_from)
        if date_to:
            condition+=" AND substr(t.starts_at,1,10)<=?";params.append(date_to)
        if time_from:
            condition+=" AND substr(t.starts_at,12,5)>=?";params.append(time_from)
        if time_to:
            condition+=" AND substr(t.starts_at,12,5)<=?";params.append(time_to)
        if available:
            condition += " AND (SELECT count(*) FROM registrations r WHERE r.session_id=t.id AND r.status='active') < t.capacity"
        joins = """FROM training_sessions t JOIN venues v ON v.id=t.venue_id
            JOIN areas a ON a.id=v.area_id JOIN sports s ON s.id=t.sport_id
            LEFT JOIN organizations o ON o.id=t.organization_id"""
        found = conn.execute(f"SELECT count(*) {joins} WHERE {condition}", params).fetchone()[0]
        rows = conn.execute(f"""SELECT t.*,v.name AS venue_name,v.address,v.lat,v.lon,a.name AS area,s.name AS sport,
            o.name AS organization_name,
            (SELECT count(*) FROM registrations r WHERE r.session_id=t.id AND r.status='active') AS enrolled
            {joins} WHERE {condition} ORDER BY t.starts_at,t.id LIMIT ? OFFSET ?""",
            (*params, 300 if view=="map" else 24, 0 if view=="map" else (page-1)*24)).fetchall()
        areas = conn.execute("SELECT name FROM areas ORDER BY name").fetchall()
        sports = conn.execute("SELECT id,name FROM sports ORDER BY name").fetchall()
        return render_template("sessions.html", items=rows, found=found, q=q, area=area,
                               sport_id=sport_id, available=available, sports=sports, areas=areas, page=page,
                               view=view, date_from=date_from,date_to=date_to,time_from=time_from,time_to=time_to,
                               pins=[{"lat":x["lat"],"lon":x["lon"],"title":x["title"],
                                      "date":x["starts_at"],"url":url_for("session_detail",session_id=x["id"])}
                                     for x in rows] if view=="map" else [])

    @app.get("/venues")
    def venues():
        page = max(1, min(request.args.get("page", 1, type=int), 200))
        q = request.args.get("q", "").strip()[:80]
        area = request.args.get("area", "").strip()[:80]
        sport_id = request.args.get("sport_id", type=int)
        with_events = request.args.get("with_events") == "1"
        now = datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M")
        conditions = ["v.public_status='visible'"]
        values = []
        if q:
            conditions.append("(v.name LIKE ? OR v.address LIKE ? OR v.facility_name LIKE ?)")
            values.extend([f"%{q}%"] * 3)
        if area:
            conditions.append("a.name=?")
            values.append(area)
        if sport_id is not None:
            conditions.append("EXISTS (SELECT 1 FROM venue_sports vs WHERE vs.venue_id=v.id AND vs.sport_id=?)")
            values.append(sport_id)
        if with_events:
            conditions.append("EXISTS (SELECT 1 FROM training_sessions t WHERE t.venue_id=v.id AND t.status='published' AND t.starts_at>=?)")
            values.append(now)
        where = " AND ".join(conditions)
        conn = db()
        found = conn.execute(f"SELECT count(*) FROM venues v JOIN areas a ON a.id=v.area_id WHERE {where}", values).fetchone()[0]
        rows = conn.execute(f"""SELECT v.*,a.name AS area,
            (SELECT count(*) FROM training_sessions t WHERE t.venue_id=v.id
             AND t.status='published' AND t.starts_at>=?) AS upcoming_count
            FROM venues v JOIN areas a ON a.id=v.area_id
            WHERE {where} ORDER BY upcoming_count DESC,v.id LIMIT 24 OFFSET ?""",
            (now,*values,(page-1)*24)).fetchall()
        areas = conn.execute("SELECT name FROM areas ORDER BY name").fetchall()
        sports = conn.execute("SELECT id,name FROM sports ORDER BY name").fetchall()
        return render_template("venues.html", venues=rows, areas=areas, sports=sports,
                               sport_id=sport_id, found=found, page=page, q=q, area=area,
                               with_events=with_events)

    @app.get("/venues/<int:venue_id>")
    def venue_detail(venue_id):
        venue = db().execute("""SELECT v.*,a.name AS area FROM venues v JOIN areas a ON a.id=v.area_id
                WHERE v.id=? AND v.public_status='visible'""", (venue_id,)).fetchone()
        if not venue: abort(404)
        sports = db().execute("""SELECT s.name FROM sports s JOIN venue_sports vs ON vs.sport_id=s.id
                    WHERE vs.venue_id=? ORDER BY s.name""", (venue_id,)).fetchall()
        sessions = db().execute("""SELECT t.*,u.display_name AS organizer,o.name AS organization_name
                    FROM training_sessions t JOIN users u ON u.id=t.organizer_id
                    LEFT JOIN organizations o ON o.id=t.organization_id
                    WHERE t.venue_id=? AND t.status='published' AND t.starts_at>=?
                    ORDER BY t.starts_at LIMIT 20""", (venue_id, datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M"))).fetchall()
        opening=db().execute("SELECT weekday,hours FROM venue_hours WHERE venue_id=? ORDER BY weekday",(venue_id,)).fetchall()
        return render_template("venue.html", venue=venue, sports=sports, sessions=sessions,
                               opening=opening, website_url=website_link(venue["website"]),
                               phone_url=phone_link(venue["phone"]))

    @app.get("/organizations/<int:organization_id>")
    def organization_profile(organization_id):
        org=db().execute("SELECT * FROM organizations WHERE id=? AND status='active'",(organization_id,)).fetchone()
        if not org: abort(404)
        rows=db().execute("""SELECT t.id,t.title,t.starts_at,v.name AS venue_name,
            (SELECT count(*) FROM session_attendance a WHERE a.session_id=t.id) AS attended
            FROM training_sessions t JOIN venues v ON v.id=t.venue_id
            WHERE t.organization_id=? AND t.status='published' AND v.public_status='visible'
            ORDER BY t.starts_at DESC LIMIT 100""",(organization_id,)).fetchall()
        editors=db().execute("""SELECT 1 FROM organization_memberships WHERE organization_id=?
            AND user_id=? AND status='approved'""",(organization_id,current_user()["id"])).fetchone() if current_user() else None
        return render_template("organization.html",org=org,items=rows,can_edit=bool(editors) or
                               bool(current_user() and current_user()["role"] in {"event_admin","global_admin"}))

    @app.post("/organizations/<int:organization_id>/description")
    @require("organizer","event_admin","global_admin")
    def edit_organization_description(organization_id):
        allowed=current_user()["role"] in {"event_admin","global_admin"} or db().execute(
            """SELECT 1 FROM organization_memberships WHERE organization_id=? AND user_id=?
            AND status='approved'""",(organization_id,current_user()["id"])).fetchone()
        if not allowed: abort(403)
        description=request.form.get("description","").strip()
        if len(description)>1000: abort(400)
        with db():
            changed=db().execute("UPDATE organizations SET description=? WHERE id=? AND status='active'",
                                 (description,organization_id))
            if not changed.rowcount: abort(404)
            audit("edit_description","organization",organization_id)
        return redirect(url_for("organization_profile",organization_id=organization_id))

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        orgs = db().execute("SELECT id,name FROM organizations WHERE status='active' ORDER BY name").fetchall()
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()[:190]
            name = request.form.get("name", "").strip()[:100]
            password = request.form.get("password", "")
            role = request.form.get("role", "participant")
            if not email or "@" not in email or len(name)<2 or len(password)<10 or role not in {"participant", "organizer"}:
                flash("Проверьте имя, адрес, роль и пароль (не менее 10 символов).", "error")
            else:
                try:
                    with db():
                        cur = db().execute("INSERT INTO users(email,password_hash,display_name,role) VALUES (?,?,?,?)",
                                           (email,hash_password(password),name,role))
                        if role == "organizer":
                            request_organizations(cur.lastrowid)
                    session.clear(); session["user_id"] = cur.lastrowid
                    session["auth_version"]=0; session["csrf"] = secrets.token_hex(24)
                    flash("Аккаунт создан. Связь с организацией должна быть подтверждена администратором." if role == "organizer" else "Аккаунт создан.", "success")
                    destination = request.args.get("next", "")
                    return redirect(url_for("organizer_organizations") if role == "organizer" else
                                    destination if destination.startswith("/") and not destination.startswith("//") else url_for("home"))
                except ValueError as exc:
                    flash(str(exc), "error")
                except sqlite3.IntegrityError:
                    flash("Этот адрес уже зарегистрирован.", "error")
        return render_template("auth.html", mode="signup", organizations=orgs)

    @app.route("/organizer/organizations", methods=["GET", "POST"])
    @require("organizer")
    def organizer_organizations():
        if request.method == "POST":
            try:
                with db():
                    request_organizations(current_user()["id"])
                flash("Заявка на связь с организацией передана администратору.", "success")
                return redirect(url_for("organizer_organizations"))
            except ValueError as exc:
                flash(str(exc), "error")
        memberships = db().execute("""SELECT o.name,o.status AS organization_status,m.status
            FROM organization_memberships m JOIN organizations o ON o.id=m.organization_id
            WHERE m.user_id=? ORDER BY m.requested_at DESC""", (current_user()["id"],)).fetchall()
        organizations = db().execute("SELECT id,name FROM organizations WHERE status='active' ORDER BY name").fetchall()
        return render_template("organizer_organizations.html", memberships=memberships, organizations=organizations)

    @app.route("/requests/new", methods=["GET", "POST"])
    @require("participant")
    def new_activity_request():
        if request.method == "POST":
            try:
                sport_id=int(request.form.get("sport_id", ""))
                area_id=int(request.form.get("area_id", ""))
            except (ValueError,TypeError):
                abort(400)
            note=request.form.get("note", "").strip()
            if len(note)>500 or not db().execute("SELECT 1 FROM sports WHERE id=?", (sport_id,)).fetchone() or not db().execute("SELECT 1 FROM areas WHERE id=?", (area_id,)).fetchone():
                abort(400)
            with db():
                open_requests=db().execute("SELECT sport_id,area_id FROM activity_requests WHERE user_id=? AND status='open'",
                    (current_user()["id"],)).fetchall()
                if any(r["sport_id"]==sport_id and r["area_id"]==area_id for r in open_requests):
                    flash("У вас уже есть открытое предложение для этого направления и района.", "error")
                    return redirect(url_for("my_sessions"))
                if len(open_requests)>=3:
                    flash("Можно держать не более трёх открытых предложений.", "error")
                    return redirect(url_for("my_sessions"))
                cur=db().execute("INSERT INTO activity_requests(user_id,sport_id,area_id,note) VALUES (?,?,?,?)",
                                 (current_user()["id"],sport_id,area_id,note))
                audit("propose", "activity_request",cur.lastrowid)
            flash("Предложение опубликовано для подтверждённых организаторов. Это ещё не заявка на мероприятие.","success")
            return redirect(url_for("my_sessions"))
        sports=db().execute("SELECT id,name FROM sports ORDER BY name").fetchall()
        areas=db().execute("SELECT id,name FROM areas ORDER BY name").fetchall()
        return render_template("new_request.html", sports=sports, areas=areas)

    @app.post("/requests/<int:request_id>/cancel")
    @require("participant")
    def cancel_activity_request(request_id):
        with db():
            cur=db().execute("""UPDATE activity_requests SET status='cancelled'
                WHERE id=? AND user_id=? AND status='open'""", (request_id,current_user()["id"]))
            if not cur.rowcount: abort(404)
            audit("cancel", "activity_request",request_id)
        flash("Предложение отозвано.","success")
        return redirect(url_for("my_sessions"))

    @app.get("/organizer/requests")
    @require("organizer", "event_admin", "global_admin")
    def organizer_requests():
        area = request.args.get("area", "").strip()[:80]
        sport_id = request.args.get("sport_id", type=int)
        filters=["r.status='open'"]
        params=[]
        if area:
            filters.append("a.name=?"); params.append(area)
        if sport_id is not None:
            filters.append("r.sport_id=?"); params.append(sport_id)
        rows=db().execute(f"""SELECT r.id,r.note,r.created_at,s.name AS sport,
            a.name AS area,(SELECT count(*) FROM activity_requests other
                WHERE other.status='open' AND other.sport_id=r.sport_id AND other.area_id=r.area_id) AS interest_count,
            (SELECT count(*) FROM training_sessions t WHERE t.request_id=r.id AND t.status='pending') AS waiting_count
            FROM activity_requests r JOIN sports s ON s.id=r.sport_id JOIN areas a ON a.id=r.area_id
            WHERE {' AND '.join(filters)} ORDER BY interest_count DESC,r.created_at DESC LIMIT 100""",params).fetchall()
        areas=db().execute("SELECT name FROM areas ORDER BY name").fetchall()
        sports=db().execute("SELECT id,name FROM sports ORDER BY name").fetchall()
        return render_template("organizer_requests.html", requests=rows, areas=areas, sports=sports,
                               area=area,sport_id=sport_id)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            user = db().execute("SELECT * FROM users WHERE email=? AND active=1", (request.form.get("email", "").strip(),)).fetchone()
            if user and check_password_hash(user["password_hash"],request.form.get("password", "")):
                session.clear(); session["user_id"] = user["id"]
                session["auth_version"]=user["auth_version"]; session["csrf"] = secrets.token_hex(24)
                destination = request.args.get("next", "")
                return redirect(destination if destination.startswith("/") and not destination.startswith("//") else url_for("home"))
            flash("Неверные данные для входа.", "error")
        return render_template("auth.html", mode="login")

    @app.post("/logout")
    @require()
    def logout():
        session.clear()
        return redirect(url_for("home"))

    @app.route("/sessions/new", methods=["GET", "POST"])
    @require("organizer")
    def create_session():
        conn = db()
        organizations = approved_organizations(current_user()["id"])
        selected = request.args.get("venue_id",type=int)
        request_id = request.args.get("request_id",type=int)
        demand = conn.execute("""SELECT r.*,s.name AS sport_name,a.name AS area_name FROM activity_requests r
            JOIN sports s ON s.id=r.sport_id JOIN areas a ON a.id=r.area_id
            WHERE r.id=? AND r.status='open'""", (request_id,)).fetchone() if request_id else None
        if request_id and not demand: abort(404, "Предложение больше не актуально")
        if request.method == "POST":
            try:
                venue_id, sport_id = map(int, request.form.get("venue_sport", "").split(":"))
                organization_id = int(request.form.get("organization_id", ""))
                selected = venue_id
                start = datetime.fromisoformat(request.form.get("starts_at", ""))
                duration = int(request.form.get("duration", ""))
                capacity = int(request.form.get("capacity", ""))
                occurrences = int(request.form.get("occurrences", "1"))
                title = request.form.get("title", "").strip()[:100]
                description = request.form.get("description", "").strip()[:1000]
                if not title or not (30<=duration<=240) or not (2<=capacity<=100) or not (1<=occurrences<=12) or start.tzinfo is not None or start <= datetime.now(MOSCOW).replace(tzinfo=None):
                    raise ValueError()
                venue = conn.execute("SELECT id FROM venues WHERE id=? AND public_status='visible'",(venue_id,)).fetchone()
                allowed = conn.execute("SELECT 1 FROM venue_sports WHERE venue_id=? AND sport_id=?",(venue_id,sport_id)).fetchone()
                if not venue or not allowed or organization_id not in {row["id"] for row in organizations}:
                    raise ValueError()
                if demand:
                    belongs=conn.execute("SELECT area_id FROM venues WHERE id=?",(venue_id,)).fetchone()
                    if sport_id!=demand["sport_id"] or belongs["area_id"]!=demand["area_id"]:
                        raise ValueError()
                with conn:
                    if demand and not conn.execute("SELECT 1 FROM activity_requests WHERE id=? AND status='open'",
                                                   (request_id,)).fetchone():
                        abort(409,"Предложение отозвано")
                    if demand and conn.execute("""SELECT 1 FROM training_sessions
                        WHERE request_id=? AND status IN ('pending','published')""",(request_id,)).fetchone():
                        abort(409,"По этому предложению встреча уже создана и ожидает проверки")
                    series_id=None
                    if occurrences>1:
                        series_id=conn.execute("""INSERT INTO event_series
                            (organizer_id,organization_id,venue_id,sport_id,title,description,duration_minutes,capacity)
                            VALUES (?,?,?,?,?,?,?,?)""",(current_user()["id"],organization_id,venue_id,sport_id,
                            title,description,duration,capacity)).lastrowid
                    for index in range(occurrences):
                        cur = conn.execute("""INSERT INTO training_sessions
                            (venue_id,sport_id,organizer_id,organization_id,request_id,series_id,
                            title,description,starts_at,duration_minutes,capacity)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",(venue_id,sport_id,current_user()["id"],organization_id,
                            request_id if index==0 else None,series_id,title,description,
                            (start+timedelta(weeks=index)).strftime("%Y-%m-%dT%H:%M"),duration,capacity))
                        audit("create", "session", cur.lastrowid)
                flash(f"На проверку отправлено занятий: {occurrences}.", "success")
                return redirect(url_for("my_sessions"))
            except (ValueError, TypeError):
                flash("Проверьте организацию, площадку, вид спорта, дату и параметры занятия.", "error")
        q = request.args.get("q", "").strip()[:80]
        choices = conn.execute("""SELECT v.id,v.name,v.address,s.id AS sport_id,s.name AS sport
                    FROM venues v JOIN venue_sports vs ON vs.venue_id=v.id JOIN sports s ON s.id=vs.sport_id
                    WHERE v.public_status='visible' AND v.id=? AND (? IS NULL OR (v.area_id=? AND s.id=?))
                    ORDER BY s.name""",(selected,request_id,demand["area_id"] if demand else None,
                        demand["sport_id"] if demand else None)).fetchall() if selected else []
        results = conn.execute("""SELECT v.id,v.name,v.address FROM venues v
                    WHERE v.public_status='visible' AND (v.name LIKE ? OR v.address LIKE ? OR v.facility_name LIKE ?)
                    AND (? IS NULL OR (v.area_id=? AND EXISTS (SELECT 1 FROM venue_sports vs
                        WHERE vs.venue_id=v.id AND vs.sport_id=?)))
                    ORDER BY v.id LIMIT 30""",(*(f"%{q}%",)*3, request_id,
                        demand["area_id"] if demand else None,
                        demand["sport_id"] if demand else None)).fetchall() if (q or demand) and not selected else []
        return render_template("session_form.html", choices=choices, results=results,
                               selected=selected, q=q, organizations=organizations, demand=demand,request_id=request_id)

    @app.get("/sessions/<int:session_id>")
    def session_detail(session_id):
        row = db().execute("""SELECT t.*,v.name AS venue_name,v.address,v.public_status AS venue_status,
                    u.display_name AS organizer,o.name AS organization_name,
                    s.name AS sport, (SELECT count(*) FROM registrations r WHERE r.session_id=t.id AND r.status='active') AS enrolled
                    FROM training_sessions t JOIN venues v ON v.id=t.venue_id JOIN users u ON u.id=t.organizer_id
                    JOIN sports s ON s.id=t.sport_id LEFT JOIN organizations o ON o.id=t.organization_id
                    WHERE t.id=?""",(session_id,)).fetchone()
        if not row: abort(404)
        enrolled = current_user() and db().execute("""SELECT r.status,
            EXISTS(SELECT 1 FROM session_attendance a WHERE a.session_id=r.session_id
                   AND a.user_id=r.user_id) AS attended,
            (SELECT status FROM reviews WHERE session_id=r.session_id AND user_id=r.user_id) AS review_status
            FROM registrations r WHERE r.session_id=? AND r.user_id=?""",
            (session_id,current_user()["id"])).fetchone()
        if (row["status"]!="published" or row["venue_status"]!="visible") and (not current_user() or
                current_user()["id"]!=row["organizer_id"] and
                current_user()["role"] not in {"event_admin","global_admin"} and not enrolled):
            abort(404)
        reviews = db().execute("""SELECT r.*,u.display_name FROM reviews r JOIN users u ON u.id=r.user_id
                                  WHERE r.session_id=? AND r.status='approved'""",(session_id,)).fetchall()
        return render_template("session.html", item=row, enrolled=enrolled, reviews=reviews)

    @app.post("/sessions/<int:session_id>/join")
    @require("participant")
    def join_session(session_id):
        conn = db()
        # Serialize with approval so a new request cannot race a filled session.
        conn.execute("BEGIN IMMEDIATE")
        try:
            item = conn.execute("SELECT * FROM training_sessions WHERE id=?",(session_id,)).fetchone()
            existing = conn.execute("SELECT status FROM registrations WHERE session_id=? AND user_id=?",
                                    (session_id,current_user()["id"])).fetchone()
            visible = item and conn.execute("SELECT public_status FROM venues WHERE id=?",(item["venue_id"],)).fetchone()[0]=='visible'
            if not item or not visible or item["status"]!="published" or item["starts_at"]<=datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M"):
                abort(409, "Запись недоступна")
            if existing and existing["status"] in {"pending","active","waitlisted","waitlist_approved"}:
                conn.commit()
                flash("Ваша заявка уже подана или участие подтверждено.","success")
                return redirect(url_for("my_sessions"))
            count = conn.execute("SELECT count(*) FROM registrations WHERE session_id=? AND status='active'",(session_id,)).fetchone()[0]
            queued=conn.execute("""SELECT 1 FROM registrations WHERE session_id=?
                AND status='waitlist_approved' LIMIT 1""",(session_id,)).fetchone()
            status="waitlisted" if count>=item["capacity"] or queued else "pending"
            if not existing or existing["status"] in {"cancelled","rejected"}:
                conn.execute("""INSERT INTO registrations(session_id,user_id,status) VALUES (?,?,?)
                    ON CONFLICT(session_id,user_id) DO UPDATE SET status=excluded.status,
                    created_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP""",
                    (session_id,current_user()["id"],status))
                audit("request_join", "session", session_id)
                notify(item["organizer_id"],"application","Новая заявка на мероприятие: "+item["title"],session_id)
                if status=="waitlisted":
                    notify(current_user()["id"],"waitlist","Вы в списке ожидания. Организатор должен рассмотреть заявку.",session_id)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        flash("Заявка отправлена организатору. Статус и список ожидания видны в «Моих заявках».","success")
        return redirect(url_for("my_sessions"))

    @app.post("/sessions/<int:session_id>/leave")
    @require("participant")
    def leave_session(session_id):
        conn=db();conn.execute("BEGIN IMMEDIATE")
        try:
            previous=conn.execute("SELECT status FROM registrations WHERE session_id=? AND user_id=?",
                                  (session_id,current_user()["id"])).fetchone()
            changed=db().execute("""UPDATE registrations SET status='cancelled',updated_at=CURRENT_TIMESTAMP
                WHERE session_id=? AND user_id=? AND status IN ('pending','waitlisted','waitlist_approved','active')
                AND EXISTS (SELECT 1 FROM training_sessions t WHERE t.id=registrations.session_id
                AND t.status IN ('pending','published') AND t.starts_at>?)""",
                (session_id,current_user()["id"],datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M")))
            if not changed.rowcount: abort(404)
            audit("leave","session",session_id)
            if previous["status"]=="active":
                promote_waitlist(conn.execute("SELECT * FROM training_sessions WHERE id=?",(session_id,)).fetchone())
            conn.commit()
        except Exception:
            conn.rollback();raise
        flash("Заявка или запись отменена.","success")
        return redirect(url_for("my_sessions"))

    @app.post("/sessions/<int:session_id>/review")
    @require("participant")
    def add_review(session_id):
        item = db().execute("SELECT * FROM training_sessions WHERE id=? AND status='published'",(session_id,)).fetchone()
        attended = db().execute("""SELECT 1 FROM registrations r
            JOIN session_attendance a ON a.session_id=r.session_id AND a.user_id=r.user_id
            WHERE r.session_id=? AND r.user_id=? AND r.status='active'""",
            (session_id,current_user()["id"])).fetchone()
        try: rating = int(request.form.get("rating", ""))
        except ValueError: rating = 0
        body = request.form.get("body", "").strip()[:1000]
        if not item or not attended or item["starts_at"]>=datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M") or rating not in range(1,6) or len(body)<5:
            abort(400)
        try:
            with db():
                cur=db().execute("INSERT INTO reviews(session_id,user_id,rating,body) VALUES (?,?,?,?)",(session_id,current_user()["id"],rating,body))
                audit("review","review",cur.lastrowid)
        except sqlite3.IntegrityError: abort(409)
        flash("Отзыв отправлен на модерацию.","success")
        return redirect(url_for("session_detail",session_id=session_id))

    @app.post("/venues/<int:venue_id>/report")
    @require("participant","organizer")
    def report_venue(venue_id):
        body=request.form.get("body", "").strip()[:1000]
        if len(body)<10 or not db().execute("SELECT 1 FROM venues WHERE id=?",(venue_id,)).fetchone(): abort(400)
        with db():
            cur=db().execute("INSERT INTO venue_reports(venue_id,user_id,body) VALUES (?,?,?)",(venue_id,current_user()["id"],body))
            audit("report","venue_report",cur.lastrowid)
        flash("Сообщение отправлено администратору площадок.","success")
        return redirect(url_for("venue_detail",venue_id=venue_id))

    @app.get("/my/sessions")
    @require("organizer","participant")
    def my_sessions():
        user=current_user()
        today=datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M")
        if user["role"]=="organizer":
            rows=db().execute("""SELECT t.*,v.name AS venue_name,
                    (SELECT count(*) FROM registrations r WHERE r.session_id=t.id AND r.status='active') AS enrolled,
                    (SELECT count(*) FROM registrations r WHERE r.session_id=t.id
                     AND r.status IN ('pending','waitlisted')) AS requests
                    FROM training_sessions t JOIN venues v ON v.id=t.venue_id
                    WHERE t.organizer_id=?
                    ORDER BY (t.status IN ('pending','published') AND t.starts_at>=?) DESC,
                    requests DESC,CASE WHEN t.starts_at>=? THEN t.starts_at END ASC,t.starts_at DESC""",
                    (user["id"],today,today)).fetchall()
        else:
            rows=db().execute("""SELECT t.*,v.name AS venue_name,r.status AS registration_status FROM registrations r
                    JOIN training_sessions t ON t.id=r.session_id JOIN venues v ON v.id=t.venue_id
                    WHERE r.user_id=?
                    ORDER BY (r.status IN ('pending','waitlisted','waitlist_approved','active')
                      AND t.status='published' AND t.starts_at>=?) DESC,
                      CASE WHEN t.starts_at>=? THEN t.starts_at END ASC,t.starts_at DESC""",
                    (user["id"],today,today)).fetchall()
        proposals=db().execute("""SELECT r.*,s.name AS sport,a.name AS area,
            (SELECT t.id FROM training_sessions t WHERE t.request_id=r.id AND t.status='published'
                AND t.starts_at>? ORDER BY t.starts_at LIMIT 1) AS meeting_id
            FROM activity_requests r JOIN sports s ON s.id=r.sport_id JOIN areas a ON a.id=r.area_id
            WHERE r.user_id=? ORDER BY r.id DESC""",
            (today,user["id"])).fetchall() if user["role"]=="participant" else []
        reports=db().execute("""SELECT r.*,v.name AS venue_name,v.public_status
            FROM venue_reports r JOIN venues v ON v.id=r.venue_id
            WHERE r.user_id=? ORDER BY r.id DESC LIMIT 30""",(user["id"],)).fetchall()
        return render_template("my_sessions.html", items=rows, proposals=proposals, reports=reports)

    @app.post("/sessions/<int:session_id>/cancel")
    @require("organizer")
    def cancel_session(session_id):
        with db():
            cur=db().execute("""UPDATE training_sessions SET status='cancelled'
                WHERE id=? AND organizer_id=? AND status IN ('pending','published') AND starts_at>?""",
                (session_id,current_user()["id"],datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M")))
            if not cur.rowcount: abort(404)
            notify_registrants(session_id,"Мероприятие отменено организатором.")
            db().execute("""UPDATE registrations SET status='cancelled',updated_at=CURRENT_TIMESTAMP
                WHERE session_id=? AND status IN ('pending','waitlisted','waitlist_approved','active')""",(session_id,))
            db().execute("""UPDATE activity_requests SET status='open' WHERE status='fulfilled'
                AND id=(SELECT request_id FROM training_sessions WHERE id=?)""",(session_id,))
            audit("cancel","session",session_id)
        flash("Тренировка и связанные с ней заявки отменены.","success")
        return redirect(url_for("my_sessions"))

    @app.post("/series/<int:series_id>/cancel")
    @require("organizer")
    def cancel_series(series_id):
        conn=db();conn.execute("BEGIN IMMEDIATE")
        try:
            rows=conn.execute("""SELECT t.* FROM training_sessions t
                WHERE t.series_id=? AND t.organizer_id=? AND t.status IN ('pending','published')
                AND t.starts_at>? ORDER BY t.starts_at""",
                (series_id,current_user()["id"],datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M"))).fetchall()
            if not rows: abort(404)
            for item in rows:
                notify_registrants(item["id"],"Будущая встреча серии отменена организатором.")
                conn.execute("UPDATE training_sessions SET status='cancelled' WHERE id=?",(item["id"],))
                conn.execute("""UPDATE registrations SET status='cancelled',updated_at=CURRENT_TIMESTAMP
                    WHERE session_id=? AND status IN ('pending','waitlisted','waitlist_approved','active')""",(item["id"],))
                if item["request_id"]:
                    conn.execute("UPDATE activity_requests SET status='open' WHERE id=? AND status='fulfilled'",(item["request_id"],))
                audit("cancel","session",item["id"])
            conn.commit()
        except Exception:
            conn.rollback();raise
        flash(f"Будущие занятия серии отменены: {len(rows)}.","success")
        return redirect(url_for("my_sessions"))

    @app.get("/sessions/<int:session_id>/participants")
    @require("organizer","event_admin","global_admin")
    def participants(session_id):
        item=db().execute("SELECT * FROM training_sessions WHERE id=?",(session_id,)).fetchone()
        if not item or (current_user()["role"]=="organizer" and item["organizer_id"]!=current_user()["id"]): abort(404)
        rows=db().execute("""SELECT r.id,r.user_id,r.status,r.updated_at,u.display_name,
                   (SELECT 1 FROM session_attendance a WHERE a.session_id=r.session_id AND a.user_id=r.user_id) AS attended
                   FROM registrations r
                   JOIN users u ON u.id=r.user_id WHERE r.session_id=?
                   ORDER BY CASE WHEN r.status IN ('pending','waitlisted') THEN 0
                       WHEN r.status='waitlist_approved' THEN 1 ELSE 2 END,r.created_at,r.id""",(session_id,)).fetchall()
        return render_template("participants.html",item=item,participants=rows)

    @app.post("/sessions/<int:session_id>/attendance/<int:user_id>/<decision>")
    @require("organizer","event_admin","global_admin")
    def mark_attendance(session_id,user_id,decision):
        if decision not in {"present","absent"}: abort(400)
        conn=db()
        with conn:
            item=conn.execute("SELECT * FROM training_sessions WHERE id=?",(session_id,)).fetchone()
            if not item or current_user()["role"]=="organizer" and item["organizer_id"]!=current_user()["id"]:
                abort(404)
            if item["status"]!="published" or item["starts_at"]>datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M"):
                abort(409,"Отметки доступны после начала встречи")
            if not conn.execute("""SELECT 1 FROM registrations WHERE session_id=? AND user_id=? AND status='active'""",
                                (session_id,user_id)).fetchone(): abort(404)
            if decision=="present":
                conn.execute("""INSERT OR IGNORE INTO session_attendance(session_id,user_id,marked_by)
                    VALUES (?,?,?)""",(session_id,user_id,current_user()["id"]))
            else:
                conn.execute("DELETE FROM session_attendance WHERE session_id=? AND user_id=?",(session_id,user_id))
            audit("attendance_"+decision,"session",session_id)
        return redirect(url_for("participants",session_id=session_id))

    @app.post("/sessions/<int:session_id>/participants/<int:registration_id>/<decision>")
    @require("organizer","event_admin","global_admin")
    def decide_participant(session_id, registration_id, decision):
        if decision not in {"active", "rejected"}: abort(400)
        conn=db(); conn.execute("BEGIN IMMEDIATE")
        try:
            item=conn.execute("SELECT * FROM training_sessions WHERE id=?",(session_id,)).fetchone()
            if not item or (current_user()["role"]=="organizer" and item["organizer_id"]!=current_user()["id"]):
                abort(404)
            if item["status"]!='published' or item["starts_at"]<=datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M"):
                abort(409,"Тренировка не опубликована или уже прошла")
            applicant=conn.execute("SELECT user_id,status FROM registrations WHERE id=? AND session_id=?",
                                   (registration_id,session_id)).fetchone()
            if not applicant or applicant["status"] not in {"pending","waitlisted"}: abort(404)
            final_status=decision
            if decision=='active':
                if conn.execute("SELECT public_status FROM venues WHERE id=?",(item["venue_id"],)).fetchone()[0]!='visible':
                    abort(409,"Площадка временно скрыта")
                count=conn.execute("SELECT count(*) FROM registrations WHERE session_id=? AND status='active'",(session_id,)).fetchone()[0]
                older=conn.execute("""SELECT 1 FROM registrations WHERE session_id=?
                    AND status='waitlist_approved' LIMIT 1""",(session_id,)).fetchone()
                if count>=item["capacity"] or older: final_status="waitlist_approved"
            cur=conn.execute("""UPDATE registrations SET status=?,updated_at=CURRENT_TIMESTAMP
                WHERE id=? AND session_id=? AND status IN ('pending','waitlisted')""",
                (final_status,registration_id,session_id))
            if not cur.rowcount: abort(404)
            audit("approve_join" if decision=='active' else "reject_join","registration",registration_id)
            notify(applicant["user_id"],"application",
                   "Ваша заявка отклонена." if decision=="rejected" else
                   "Организатор одобрил место в очереди." if final_status=="waitlist_approved" else
                   "Ваша запись подтверждена.",session_id)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        flash("Заявка рассмотрена.","success")
        return redirect(url_for("participants",session_id=session_id))

    @app.post("/sessions/<int:session_id>/participants/<int:registration_id>/remove")
    @require("organizer","event_admin","global_admin")
    def remove_participant(session_id,registration_id):
        item=db().execute("SELECT organizer_id,status,starts_at FROM training_sessions WHERE id=?",(session_id,)).fetchone()
        if not item or (current_user()["role"]=="organizer" and item["organizer_id"]!=current_user()["id"]): abort(404)
        if item["status"]!='published' or item["starts_at"]<=datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M"):
            abort(409,"Завершённую тренировку изменить нельзя")
        conn=db();conn.execute("BEGIN IMMEDIATE")
        try:
            applicant=conn.execute("SELECT user_id FROM registrations WHERE id=? AND session_id=? AND status='active'",
                                   (registration_id,session_id)).fetchone()
            cur=db().execute("""UPDATE registrations SET status='cancelled',updated_at=CURRENT_TIMESTAMP
                WHERE id=? AND session_id=? AND status='active'""",(registration_id,session_id))
            if not cur.rowcount: abort(404)
            audit("remove_participant","registration",registration_id)
            notify(applicant["user_id"],"application","Организатор отменил вашу запись.",session_id)
            promote_waitlist(conn.execute("SELECT * FROM training_sessions WHERE id=?",(session_id,)).fetchone())
            conn.commit()
        except Exception:
            conn.rollback();raise
        flash("Запись участника отменена.","success")
        return redirect(url_for("participants",session_id=session_id))

    @app.post("/sessions/<int:session_id>/reschedule")
    @require("organizer")
    def reschedule_session(session_id):
        try:
            start=datetime.fromisoformat(request.form.get("starts_at", ""))
            if start.tzinfo is not None or start<=datetime.now(MOSCOW).replace(tzinfo=None): raise ValueError()
        except (ValueError,TypeError): abort(400)
        with db():
            cur=db().execute("""UPDATE training_sessions SET starts_at=?,status='pending'
                    WHERE id=? AND organizer_id=? AND status IN ('pending','published') AND starts_at>?""",
                    (start.strftime("%Y-%m-%dT%H:%M"),session_id,current_user()["id"],
                     datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M")))
            if not cur.rowcount: abort(404)
            notify_registrants(session_id,"Время мероприятия изменено; прежние заявки отменены. После публикации подайте новую.")
            db().execute("""UPDATE registrations SET status='cancelled',updated_at=CURRENT_TIMESTAMP
                WHERE session_id=? AND status IN ('pending','waitlisted','waitlist_approved','active')""",(session_id,))
            db().execute("""UPDATE activity_requests SET status='open' WHERE status='fulfilled'
                AND id=(SELECT request_id FROM training_sessions WHERE id=?)""",(session_id,))
            audit("reschedule","session",session_id)
        flash("Новое время отправлено на проверку. Прежние заявки отменены; после публикации участники смогут подать их заново.","success")
        return redirect(url_for("my_sessions"))

    @app.get("/admin")
    @require("venue_admin","event_admin","global_admin")
    def admin():
        conn=db()
        metrics={
            "venues":"SELECT count(*) FROM venues",
            "hidden":"SELECT count(*) FROM venues WHERE public_status='hidden'",
            "reports":"SELECT count(*) FROM venue_reports WHERE status IN ('open','escalated')",
            "pending":"SELECT count(*) FROM training_sessions WHERE status='pending'",
            "registrations":"SELECT count(*) FROM registrations WHERE status='active'",
            "affiliations":"SELECT count(*) FROM organization_memberships WHERE status='pending'",
            "reviews":"SELECT count(*) FROM reviews WHERE status='pending'",
            "users":"SELECT count(*) FROM users",
        }
        role=current_user()["role"]
        if role=="venue_admin":
            metrics["reports"]="SELECT count(*) FROM venue_reports WHERE status='open'"
        allowed_keys=({"venues","hidden","reports"} if role=="venue_admin" else
                      {"pending","registrations","affiliations","reviews"} if role=="event_admin" else
                      set(metrics))
        stats={k:conn.execute(sql).fetchone()[0] for k,sql in metrics.items() if k in allowed_keys}
        can_manage_events = current_user()["role"] in {"event_admin", "global_admin"}
        pending_orgs=conn.execute("""SELECT o.id,o.name,count(m.user_id) AS applicants
            FROM organizations o LEFT JOIN organization_memberships m ON m.organization_id=o.id
            WHERE o.status='pending' GROUP BY o.id ORDER BY o.created_at,o.id LIMIT 100""").fetchall() if can_manage_events else []
        pending_memberships=conn.execute("""SELECT m.user_id,m.organization_id,
            u.display_name,u.email,o.name AS organization_name,o.status AS organization_status
            FROM organization_memberships m JOIN users u ON u.id=m.user_id
            JOIN organizations o ON o.id=m.organization_id
            WHERE m.status='pending' ORDER BY m.requested_at,m.user_id LIMIT 100""").fetchall() if can_manage_events else []
        approved_memberships=conn.execute("""SELECT m.user_id,m.organization_id,u.display_name,
            o.name AS organization_name FROM organization_memberships m
            JOIN users u ON u.id=m.user_id JOIN organizations o ON o.id=m.organization_id
            WHERE m.status='approved' ORDER BY o.name,u.display_name LIMIT 100""").fetchall() if can_manage_events else []
        active_orgs=conn.execute("SELECT id,name FROM organizations WHERE status='active' ORDER BY name LIMIT 50").fetchall() if can_manage_events else []
        pending=conn.execute("""SELECT t.*,v.name AS venue_name,u.display_name AS organizer FROM training_sessions t
                    JOIN venues v ON v.id=t.venue_id JOIN users u ON u.id=t.organizer_id
                    WHERE t.status='pending' ORDER BY t.starts_at LIMIT 100""").fetchall() if current_user()["role"] in {"event_admin","global_admin"} else []
        reports=conn.execute("""SELECT r.*,v.name AS venue_name FROM venue_reports r JOIN venues v ON v.id=r.venue_id
                    WHERE r.status IN ('open','escalated') AND (?='global_admin' OR r.status='open')
                    ORDER BY r.created_at DESC LIMIT 100""",(role,)).fetchall() if role in {"venue_admin","global_admin"} else []
        reviews=conn.execute("""SELECT r.*,t.title AS session_title FROM reviews r JOIN training_sessions t ON t.id=r.session_id
                    WHERE r.status='pending' LIMIT 100""").fetchall() if current_user()["role"] in {"event_admin","global_admin"} else []
        published=conn.execute("""SELECT t.id,t.title,t.starts_at,v.name AS venue_name FROM training_sessions t
                    JOIN venues v ON v.id=t.venue_id WHERE t.status='published'
                    ORDER BY (t.starts_at>=?) DESC,
                      CASE WHEN t.starts_at>=? THEN t.starts_at END ASC,t.starts_at DESC LIMIT 30""",
                    (datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M"),)*2).fetchall() if current_user()["role"] in {"event_admin","global_admin"} else []
        hidden=conn.execute("""SELECT id,name,address FROM venues WHERE public_status='hidden'
                    ORDER BY id DESC LIMIT 30""").fetchall() if current_user()["role"] in {"venue_admin","global_admin"} else []
        resolved=conn.execute("""SELECT r.id,r.body,v.name AS venue_name FROM venue_reports r
                    JOIN venues v ON v.id=r.venue_id WHERE r.status='resolved'
                    ORDER BY r.id DESC LIMIT 10""").fetchall() if current_user()["role"] in {"venue_admin","global_admin"} else []
        users=conn.execute("SELECT id,display_name,email,role FROM users ORDER BY id DESC LIMIT 50").fetchall() if current_user()["role"]=="global_admin" else []
        return render_template("admin.html",stats=stats,pending=pending,reports=reports,reviews=reviews,
                               published=published,hidden=hidden,resolved=resolved,users=users,
                               pending_orgs=pending_orgs,pending_memberships=pending_memberships,
                               active_orgs=active_orgs,approved_memberships=approved_memberships)

    @app.get("/admin/venues")
    @require("venue_admin","global_admin")
    def admin_venues():
        q=request.args.get("q","").strip()[:80]
        rows=db().execute("""SELECT v.id,v.name,v.address,v.public_status,v.verified_at
            FROM venues v WHERE v.name LIKE ? OR v.address LIKE ? OR CAST(v.source_id AS TEXT)=?
            ORDER BY v.id LIMIT 50""",(f"%{q}%",f"%{q}%",q)).fetchall() if q else []
        return render_template("admin_venues.html",items=rows,q=q)

    @app.post("/admin/organizations/new")
    @require("event_admin", "global_admin")
    def admin_create_organization():
        name = request.form.get("name", "").strip()
        if not 3 <= len(name) <= 120:
            abort(400, "Укажите название организации от 3 до 120 символов")
        try:
            with db():
                cur = db().execute("INSERT INTO organizations(name,status) VALUES (?,'active')", (name,))
                audit("create", "organization", cur.lastrowid)
        except sqlite3.IntegrityError:
            abort(409, "Организация с таким названием уже есть")
        flash("Организация добавлена в список.", "success")
        return redirect(url_for("admin"))

    @app.post("/admin/organizations/<int:organization_id>/<decision>")
    @require("event_admin", "global_admin")
    def decide_organization(organization_id, decision):
        if decision not in {"active", "rejected"}: abort(400)
        with db():
            cur=db().execute("UPDATE organizations SET status=? WHERE id=? AND status='pending'",
                             (decision, organization_id))
            if not cur.rowcount: abort(404)
            audit("organization_"+decision, "organization", organization_id)
        flash("Организация подтверждена." if decision == "active" else "Организация отклонена.", "success")
        return redirect(url_for("admin"))

    @app.post("/admin/memberships/<int:user_id>/<int:organization_id>/<decision>")
    @require("event_admin", "global_admin")
    def decide_membership(user_id, organization_id, decision):
        if decision not in {"approved", "rejected"}: abort(400)
        with db():
            row=db().execute("""SELECT o.status AS org_status,u.active,u.role
                FROM organization_memberships m JOIN organizations o ON o.id=m.organization_id
                JOIN users u ON u.id=m.user_id
                WHERE m.user_id=? AND m.organization_id=? AND m.status='pending'""",
                (user_id, organization_id)).fetchone()
            if not row: abort(404)
            if decision == "approved" and (row["org_status"] != "active" or not row["active"] or row["role"] != "organizer"):
                abort(409, "Сначала подтвердите организацию и проверьте роль организатора")
            cur=db().execute("""UPDATE organization_memberships SET status=?,reviewed_by=?
                WHERE user_id=? AND organization_id=? AND status='pending'""",
                (decision,current_user()["id"],user_id,organization_id))
            if not cur.rowcount: abort(409)
            audit("membership_"+decision,"user",user_id)
            notify(user_id,"organization",
                   "Связь с организацией подтверждена." if decision=="approved" else
                   "Заявка на связь с организацией отклонена.")
        flash("Организатор подтверждён." if decision == "approved" else "Заявка отклонена.", "success")
        return redirect(url_for("admin"))

    @app.post("/admin/memberships/<int:user_id>/<int:organization_id>/revoke")
    @require("event_admin","global_admin")
    def revoke_membership(user_id,organization_id):
        with db():
            changed=db().execute("""UPDATE organization_memberships
                SET status='rejected',reviewed_by=? WHERE user_id=? AND organization_id=?
                AND status='approved'""",(current_user()["id"],user_id,organization_id))
            if not changed.rowcount: abort(404)
            db().execute("UPDATE users SET auth_version=auth_version+1 WHERE id=?",(user_id,))
            audit("membership_revoked","user",user_id)
            notify(user_id,"organization","Доступ организатора к организации отозван.")
        flash("Связь с организацией отозвана; пользователь должен войти заново.","success")
        return redirect(url_for("admin"))

    def review_sessions(items, decision):
        """Validate and apply an entire series atomically under BEGIN IMMEDIATE."""
        conn=db()
        schedules={}
        if decision=="published":
            for item in items:
                owner=conn.execute("SELECT role,active FROM users WHERE id=?",(item["organizer_id"],)).fetchone()
                if not owner or owner["role"]!="organizer" or not owner["active"]:
                    abort(409,"Организатор больше не имеет доступа к мероприятиям")
                approved={org["id"] for org in approved_organizations(item["organizer_id"])}
                if not approved or item["organization_id"] is not None and item["organization_id"] not in approved:
                    abort(409,"Связь организатора с указанной организацией не подтверждена")
                if item["request_id"] is not None:
                    proposed=conn.execute("SELECT * FROM activity_requests WHERE id=? AND status='open'",
                                          (item["request_id"],)).fetchone()
                    area=conn.execute("SELECT area_id FROM venues WHERE id=?",(item["venue_id"],)).fetchone()
                    if not proposed or proposed["sport_id"]!=item["sport_id"] or proposed["area_id"]!=area["area_id"]:
                        abort(409,"Предложение отозвано или не соответствует мероприятию")
                if item["starts_at"]<=datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M"):
                    abort(409,"Дата уже прошла")
                if conn.execute("SELECT public_status FROM venues WHERE id=?",(item["venue_id"],)).fetchone()[0]!="visible":
                    abort(409,"Площадка скрыта")
                if item["venue_id"] not in schedules:
                    occupied=conn.execute("""SELECT starts_at,duration_minutes FROM training_sessions
                        WHERE venue_id=? AND status='published'""",(item["venue_id"],)).fetchall()
                    schedules[item["venue_id"]]=[
                        TrainingSlot.from_values(x["starts_at"],x["duration_minutes"]) for x in occupied]
                slot=TrainingSlot.from_values(item["starts_at"],item["duration_minutes"])
                if SchedulePolicy(schedules[item["venue_id"]]).has_conflict(slot):
                    abort(409,"В приложении уже есть занятие на этой площадке в это время")
                schedules[item["venue_id"]].append(slot)
        for item in items:
            conn.execute("UPDATE training_sessions SET status=? WHERE id=?",(decision,item["id"]))
            if decision=="published" and item["request_id"] is not None:
                conn.execute("UPDATE activity_requests SET status='fulfilled' WHERE id=?",(item["request_id"],))
                requester=conn.execute("SELECT user_id FROM activity_requests WHERE id=?",(item["request_id"],)).fetchone()
                notify(requester["user_id"],"proposal","По вашему предложению опубликована встреча. Для участия подайте заявку.",item["id"])
            notify(item["organizer_id"],"publication",
                   "Встреча опубликована." if decision=="published" else "Публикация встречи отклонена.",item["id"])
            audit(decision,"session",item["id"])

    @app.post("/admin/sessions/<int:session_id>/<decision>")
    @require("event_admin","global_admin")
    def decide_session(session_id,decision):
        if decision not in {"published","rejected"}: abort(400)
        conn=db();conn.execute("BEGIN IMMEDIATE")
        try:
            item=conn.execute("SELECT * FROM training_sessions WHERE id=? AND status='pending'",(session_id,)).fetchone()
            if not item: abort(404)
            review_sessions([item],decision)
            conn.commit()
        except Exception:
            conn.rollback();raise
        flash("Решение по встрече сохранено.","success")
        return redirect(url_for("admin"))

    @app.post("/admin/series/<int:series_id>/<decision>")
    @require("event_admin","global_admin")
    def decide_series(series_id,decision):
        if decision not in {"published","rejected"}: abort(400)
        conn=db();conn.execute("BEGIN IMMEDIATE")
        try:
            items=conn.execute("""SELECT * FROM training_sessions WHERE series_id=?
                AND status='pending' ORDER BY starts_at,id""",(series_id,)).fetchall()
            if not items: abort(404)
            review_sessions(items,decision)
            conn.commit()
        except Exception:
            conn.rollback();raise
        flash(f"Решение применено к занятиям серии: {len(items)}.","success")
        return redirect(url_for("admin"))

    @app.post("/admin/sessions/<int:session_id>/cancel")
    @require("event_admin","global_admin")
    def admin_cancel_session(session_id):
        with db():
            changed=db().execute("""UPDATE training_sessions SET status='cancelled'
                WHERE id=? AND status='published' AND starts_at>?""",
                (session_id,datetime.now(MOSCOW).strftime("%Y-%m-%dT%H:%M")))
            if not changed.rowcount: abort(404)
            notify_registrants(session_id,"Мероприятие отменено администратором.")
            db().execute("""UPDATE registrations SET status='cancelled',updated_at=CURRENT_TIMESTAMP
                WHERE session_id=? AND status IN ('pending','waitlisted','waitlist_approved','active')""",(session_id,))
            db().execute("""UPDATE activity_requests SET status='open' WHERE status='fulfilled'
                AND id=(SELECT request_id FROM training_sessions WHERE id=?)""",(session_id,))
            audit("admin_cancel","session",session_id)
        flash("Тренировка и связанные с ней заявки отменены.","success")
        return redirect(url_for("admin"))

    @app.post("/admin/reviews/<int:review_id>/<decision>")
    @require("event_admin","global_admin")
    def decide_review(review_id,decision):
        if decision not in {"approved","rejected"}: abort(400)
        with db():
            cur=db().execute("UPDATE reviews SET status=? WHERE id=? AND status='pending'",(decision,review_id))
            if not cur.rowcount: abort(404)
            audit(decision,"review",review_id)
        return redirect(url_for("admin"))

    @app.post("/admin/reports/<int:report_id>/<decision>")
    @require("venue_admin","global_admin")
    def decide_report(report_id,decision):
        if decision not in {"resolved","escalated"}: abort(400)
        role=current_user()["role"]
        if decision=="escalated" and role!="venue_admin": abort(403)
        with db():
            report=db().execute("SELECT user_id,venue_id,status FROM venue_reports WHERE id=?",(report_id,)).fetchone()
            if not report or report["status"] not in ({"open","escalated"} if role=="global_admin" else {"open"}):
                abort(404)
            cur=db().execute("UPDATE venue_reports SET status=? WHERE id=? AND status=?",
                             (decision,report_id,report["status"]))
            if not cur.rowcount: abort(404)
            notify(report["user_id"],"venue_report",
                   "Сообщение о площадке рассмотрено." if decision=="resolved" else
                   "Сообщение о площадке передано на дополнительную проверку.")
            audit(decision,"venue_report",report_id)
        return redirect(url_for("admin"))

    @app.post("/admin/venues/<int:venue_id>/visibility")
    @require("venue_admin","global_admin")
    def venue_visibility(venue_id):
        status=request.form.get("status")
        if status not in {"visible","hidden"}: abort(400)
        with db():
            cur=db().execute("UPDATE venues SET public_status=?,admin_note=? WHERE id=?",(status,request.form.get("note","").strip()[:300],venue_id))
            if not cur.rowcount: abort(404)
            audit("visibility_"+status,"venue",venue_id)
        return redirect(url_for("admin"))

    @app.route("/admin/venues/<int:venue_id>/edit",methods=["GET","POST"])
    @require("venue_admin","global_admin")
    def edit_venue(venue_id):
        conn=db()
        venue=conn.execute("SELECT * FROM venues WHERE id=?",(venue_id,)).fetchone()
        if not venue: abort(404)
        fields={"name":120,"facility_name":120,"address":250,"usage_period":120,
                "paid":120,"paid_comment":300,"website":250,"phone":80,"accessibility":300}
        if request.method=="POST":
            changes={}
            for field,limit in fields.items():
                value=request.form.get(field,"").strip()
                if (field in {"name","facility_name","address","usage_period","paid"} and not value) or len(value)>limit:
                    abort(400,"Некорректные сведения о площадке")
                if field=="website" and value and not website_link(value):
                    abort(400,"Укажите адрес сайта с доменом и протоколом HTTP(S), если он нужен")
                if value!=(venue[field] or ""): changes[field]=value
            if not changes:
                flash("Изменений нет.","success")
                return redirect(url_for("edit_venue",venue_id=venue_id))
            with conn:
                for field,value in changes.items():
                    conn.execute("""INSERT INTO venue_edits(venue_id,actor_id,field_name,old_value,new_value)
                        VALUES (?,?,?,?,?)""",(venue_id,current_user()["id"],field,venue[field],value))
                    conn.execute(f"UPDATE venues SET {field}=? WHERE id=?",(value,venue_id))
                conn.execute("""UPDATE venues SET verified_at=CURRENT_TIMESTAMP,verified_by=? WHERE id=?""",
                             (current_user()["id"],venue_id))
                audit("verify_edit","venue",venue_id)
            flash("Исправления сохранены с историей изменений.","success")
            return redirect(url_for("edit_venue",venue_id=venue_id))
        edits=conn.execute("""SELECT e.*,u.display_name FROM venue_edits e JOIN users u ON u.id=e.actor_id
            WHERE e.venue_id=? ORDER BY e.id DESC LIMIT 100""",(venue_id,)).fetchall()
        return render_template("venue_edit.html",venue=venue,edits=edits,fields=fields)

    @app.get("/admin/venues/export.csv")
    @require("venue_admin","global_admin")
    def export_venue_report():
        output=io.StringIO();writer=csv.writer(output)
        writer.writerow(["source_id","name","area","address","paid","paid_comment",
                         "website","phone","status","reports"])
        for row in db().execute("""SELECT v.source_id,v.name,a.name,v.address,v.paid,
                    v.paid_comment,v.website,v.phone,v.public_status,
                    (SELECT count(*) FROM venue_reports r WHERE r.venue_id=v.id) FROM venues v
                    JOIN areas a ON a.id=v.area_id ORDER BY v.id"""):
            writer.writerow(row)
        return Response('\ufeff'+output.getvalue(),mimetype="text/csv",
                        headers={"Content-Disposition":"attachment; filename=venue_report.csv"})

    @app.post("/admin/users/<int:user_id>/role")
    @require("global_admin")
    def set_role(user_id):
        role=request.form.get("role")
        if role not in ROLES or user_id==current_user()["id"]: abort(400)
        with db():
            cur=db().execute("UPDATE users SET role=?,auth_version=auth_version+1 WHERE id=?",(role,user_id))
            if not cur.rowcount: abort(404)
            audit("role_"+role,"user",user_id)
        return redirect(url_for("admin"))

    @app.get("/admin/export.csv")
    @require("global_admin")
    def export_report():
        output=io.StringIO();writer=csv.writer(output)
        writer.writerow(["session_id","name","venue","starts_at","status","active_participants"])
        for row in db().execute("""SELECT t.id,t.title,v.name,t.starts_at,t.status,
                    (SELECT count(*) FROM registrations r WHERE r.session_id=t.id AND r.status='active')
                    FROM training_sessions t JOIN venues v ON v.id=t.venue_id ORDER BY t.id"""):
            writer.writerow(row)
        return Response('\ufeff'+output.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=training_report.csv"})

    @app.cli.command("init-db")
    def init_db_command():
        with sqlite3.connect(app.config["DATABASE"]) as connection:
            initialize_database(connection)
        click.echo("Database schema initialized")

    @app.cli.command("import-venues")
    @click.option("--file", "path", type=click.Path(exists=True,dir_okay=False), default=str(ROOT / "data" / "venues_seed.csv"))
    def import_venues_command(path):
        with sqlite3.connect(app.config["DATABASE"]) as connection:
            initialize_database(connection)
            with open(path,encoding="utf-8",newline="") as handle:
                rows=list(csv.DictReader(handle))
            areas=sorted({row["area"] for row in rows})
            connection.executemany("INSERT OR IGNORE INTO areas(name) VALUES (?)",[(x,) for x in areas])
            area_ids={name:area_id for area_id,name in connection.execute("SELECT id,name FROM areas")}
            names={"футбол":"Футбол", "баскетбол":"Баскетбол", "волейбол":"Волейбол", "теннис":"Теннис"}
            sports=["Общая физическая подготовка",*names.values()]
            connection.executemany("INSERT OR IGNORE INTO sports(name) VALUES (?)",[(x,) for x in sports])
            sport_ids={name:idx for idx,name in connection.execute("SELECT id,name FROM sports")}
            # Early releases kept an extra NOT NULL copy of the schedule in venues.
            # Supply it on INSERT so importing an old primary DB remains possible.
            legacy_hours = "opening_hours" in {
                column[1] for column in connection.execute("PRAGMA table_info(venues)")}
            for row in rows:
                columns=("source_id","name","facility_name","area_id","address","lat","lon",
                         "usage_period","paid","paid_comment","website","phone","accessibility")
                if legacy_hours:
                    columns += ("opening_hours",)
                values=(int(row["source_id"]),row["name"],row["facility_name"],area_ids[row["area"]],row["address"],
                        float(row["lat"]),float(row["lon"]),row["usage_period"],row["paid"],
                        row.get("paid_comment") or None,row.get("website") or None,row.get("phone") or None,
                        row["accessibility"] or None)
                if legacy_hours:
                    values += (row["opening_hours"],)
                connection.execute(f"""INSERT INTO venues({','.join(columns)})
                    VALUES ({','.join('?' for _ in columns)}) ON CONFLICT(source_id) DO UPDATE SET name=excluded.name,
                    facility_name=excluded.facility_name,area_id=excluded.area_id,address=excluded.address,
                    lat=excluded.lat,lon=excluded.lon,
                    usage_period=excluded.usage_period,paid=excluded.paid,
                    paid_comment=excluded.paid_comment,website=excluded.website,phone=excluded.phone,
                    accessibility=excluded.accessibility
                    WHERE venues.verified_at IS NULL""", values)
                venue_id=connection.execute("SELECT id FROM venues WHERE source_id=?",(row["source_id"],)).fetchone()[0]
                hours=json.loads(row["opening_hours"])
                if len(hours)!=7: raise ValueError(f"Unexpected schedule for {row['source_id']}")
                for weekday,day in enumerate(hours,start=1):
                    connection.execute("""INSERT INTO venue_hours(venue_id,weekday,hours) VALUES (?,?,?)
                         ON CONFLICT(venue_id,weekday) DO UPDATE SET hours=excluded.hours""",
                         (venue_id,weekday,day["Hours"]))
                selected=[label for fragment,label in names.items() if fragment in row["name"].lower()] or ["Общая физическая подготовка"]
                for label in selected:
                    connection.execute("INSERT OR IGNORE INTO venue_sports(venue_id,sport_id) VALUES (?,?)",(venue_id,sport_ids[label]))
        click.echo(f"Imported {len(rows)} rows; total venues {connection_total(app.config['DATABASE'])}")

    @app.cli.command("create-user")
    @click.option("--email",prompt=True)
    @click.option("--name",prompt=True)
    @click.option("--role",type=click.Choice(sorted(ROLES)),prompt=True)
    @click.password_option()
    def create_user_command(email,name,role,password):
        if len(password)<10: raise click.BadParameter("Password must be at least 10 characters")
        with sqlite3.connect(app.config["DATABASE"]) as connection:
            initialize_database(connection)
            connection.execute("INSERT INTO users(email,password_hash,display_name,role) VALUES (?,?,?,?)",
                               (email.lower().strip(),hash_password(password),name.strip(),role))
        click.echo("User created")

    return app


def connection_total(path):
    with sqlite3.connect(path) as connection:
        return connection.execute("SELECT count(*) FROM venues").fetchone()[0]


app = create_app()
