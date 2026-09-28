"""Business-process checks using the imported 4,751-row source snapshot."""
import csv
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from app import create_app, SCHEMA, initialize_database
from domain import CAPABILITY_LABELS, POLICIES


@pytest.fixture
def setup(tmp_path):
    path = tmp_path / "test.sqlite3"
    app = create_app({"TESTING": True, "DATABASE": str(path), "SECRET_KEY": "tests-only"})
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.execute("INSERT INTO areas(name) VALUES ('Тестовый район')")
        conn.execute("INSERT INTO sports(name) VALUES ('Баскетбол')")
        conn.execute("""INSERT INTO venues(source_id,name,facility_name,area_id,address,lat,lon,usage_period,paid)
            VALUES (123,'Баскетбольная площадка','Тестовый комплекс',1,'Тестовая улица',55.75,37.61,'01.01-31.12','бесплатно')""")
        conn.execute("INSERT INTO venue_sports VALUES (1,1)")
        for i,role in enumerate(("organizer","participant","event_admin","venue_admin","global_admin"),start=1):
            conn.execute("INSERT INTO users(email,password_hash,display_name,role) VALUES (?,?,?,?)",
                (f"u{i}@example.test",generate_password_hash("verylongpass"),f"User {i}",role))
        conn.execute("INSERT INTO organizations(name,status) VALUES ('Клуб Север','active')")
        conn.execute("INSERT INTO organization_memberships(user_id,organization_id,status) VALUES (1,1,'approved')")
    return app, path


def login(client, idx):
    client.get("/login")
    with client.session_transaction() as sess:
        token=sess["csrf"]
    response=client.post("/login",data={"email":f"u{idx}@example.test","password":"verylongpass","csrf":token})
    assert response.status_code==302


def token(client):
    with client.session_transaction() as sess:
        return sess["csrf"]


def test_guest_and_role_boundary(setup):
    app,_=setup
    with app.test_client() as client:
        assert client.get("/").status_code==200
        assert client.get("/venues?q=Баскет").status_code==200
        assert client.get("/venues/1").status_code==200
        assert client.get("/admin").status_code==302
        login(client,2)
        assert client.get("/sessions/new").status_code==403
        assert client.post("/venues/1/report",data={"body":"Здесь неисправно покрытие"}).status_code==400
        client.post("/logout",data={"csrf":token(client)})
        login(client,1)
        assert 'Найдите площадку'.encode() in client.get("/sessions/new").data
        assert 'Баскетбольная площадка'.encode() in client.get("/sessions/new?q=Баскетбольная").data
        assert 'Направление'.encode() in client.get("/sessions/new?venue_id=1").data


def test_publish_join_capacity_and_moderation(setup):
    app,path=setup
    start=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=7)).strftime("%Y-%m-%dT%H:%M")
    with app.test_client() as client:
        login(client,1)
        r=client.post("/sessions/new",data={"csrf":token(client),"venue_sport":"1:1","organization_id":"1","title":"Игра в баскетбол",
            "starts_at":start,"duration":"60","capacity":"2","description":"Встреча команды"})
        assert r.status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM training_sessions").fetchone()[0]=="pending"
        assert client.get("/sessions").status_code==200
        assert 'Игра в баскетбол'.encode() not in client.get("/sessions").data
        client.post("/logout",data={"csrf":token(client)})
        login(client,3)
        assert client.post("/admin/sessions/1/published",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        login(client,2)
        assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==302
        # The request is visible at once to the participant; no place is yet assigned.
        assert 'Ожидает ответа организатора'.encode() in client.get("/my/sessions").data
        assert 'ожидает решения'.encode() in client.get("/sessions/1").data
        assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT count(*) FROM registrations WHERE status='pending'").fetchone()[0]==1
            assert conn.execute("SELECT count(*) FROM registrations WHERE status='active'").fetchone()[0]==0
        # Reporting a venue is a separate moderation queue, not an event request.
        assert client.post("/venues/1/report",data={"csrf":token(client),"body":"На покрытии появилась опасная яма"}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        login(client,1)
        assert 'Заявки: 1'.encode() in client.get("/my/sessions").data
        assert 'Заявки: 1'.encode() in client.get("/").data
        assert 'Подтвердить'.encode() in client.get("/sessions/1/participants").data
        assert client.post("/sessions/1/participants/1/active",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        login(client,2)
        assert 'Подтверждена организатором'.encode() in client.get("/my/sessions").data
        assert 'подтвердил вашу запись'.encode() in client.get("/sessions/1").data
        assert client.post("/sessions/1/leave",data={"csrf":token(client)}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM registrations WHERE id=1").fetchone()[0]=="cancelled"
        client.post("/logout",data={"csrf":token(client)})
        login(client,4)
        assert client.post("/admin/reports/1/resolved",data={"csrf":token(client)}).status_code==302


def test_requests_rejections_permissions_and_capacity(setup):
    app,path=setup
    start=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=10)).strftime("%Y-%m-%dT%H:%M")
    with sqlite3.connect(path) as conn:
        conn.execute("""INSERT INTO training_sessions
            (venue_id,sport_id,organizer_id,title,starts_at,duration_minutes,capacity,status)
            VALUES (1,1,1,'Командная игра',?,60,2,'published')""",(start,))
        for i,role in ((6,"participant"),(7,"participant"),(8,"organizer")):
            conn.execute("INSERT INTO users(email,password_hash,display_name,role) VALUES (?,?,?,?)",
                (f"u{i}@example.test",generate_password_hash("verylongpass"),f"User {i}",role))
        conn.execute("INSERT INTO organization_memberships(user_id,organization_id,status) VALUES (8,1,'approved')")
    with app.test_client() as client:
        for idx in (2,6,7):
            login(client,idx)
            assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==302
            assert 'Ожидает ответа организатора'.encode() in client.get("/my/sessions").data
            assert client.post("/sessions/1/participants/1/active",data={"csrf":token(client)}).status_code==403
            client.post("/logout",data={"csrf":token(client)})
        login(client,8)
        assert client.get("/sessions/1/participants").status_code==404
        assert client.post("/sessions/1/participants/1/active",data={"csrf":token(client)}).status_code==404
        client.post("/logout",data={"csrf":token(client)})
        login(client,1)
        assert client.post("/sessions/1/participants/1/active",data={"csrf":token(client)}).status_code==302
        assert client.post("/sessions/1/participants/2/active",data={"csrf":token(client)}).status_code==302
        assert client.post("/sessions/1/participants/3/active",data={"csrf":token(client)}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM registrations WHERE id=3").fetchone()[0]=="waitlist_approved"
            assert conn.execute("SELECT count(*) FROM registrations WHERE status='active'").fetchone()[0]==2
        client.post("/logout",data={"csrf":token(client)})
        login(client,7)
        assert 'В очереди: одобрена'.encode() in client.get("/my/sessions").data
        assert client.get("/sessions").status_code==200
        assert 'Очередь ожидания'.encode() in client.get("/sessions").data
        client.post("/logout",data={"csrf":token(client)})
        login(client,2)
        # A repeated POST must not turn an already confirmed seat back into a request.
        assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM registrations WHERE user_id=2").fetchone()[0]=="active"


def test_reschedule_and_cancel_update_participant_history(setup):
    app,path=setup
    later=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=7)).strftime("%Y-%m-%dT%H:%M")
    new_time=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=8)).strftime("%Y-%m-%dT%H:%M")
    with sqlite3.connect(path) as conn:
        conn.execute("""INSERT INTO training_sessions
            (venue_id,sport_id,organizer_id,title,starts_at,duration_minutes,capacity,status)
            VALUES (1,1,1,'Перенос занятия',?,60,2,'published')""",(later,))
    with app.test_client() as client:
        login(client,2)
        assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        login(client,1)
        assert client.post("/sessions/1/participants/1/active",data={"csrf":token(client)}).status_code==302
        assert client.post("/sessions/1/reschedule",data={"csrf":token(client),"starts_at":new_time}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM training_sessions").fetchone()[0]=="pending"
            assert conn.execute("SELECT status FROM registrations").fetchone()[0]=="cancelled"
        client.post("/logout",data={"csrf":token(client)})
        login(client,2)
        history=client.get("/my/sessions").data
        assert 'Отменена'.encode() in history and 'ожидает публикации'.encode() in history
        assert client.post("/sessions/1/leave",data={"csrf":token(client)}).status_code==404
        client.post("/logout",data={"csrf":token(client)})
        login(client,3)
        assert client.post("/admin/sessions/1/published",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        login(client,2)
        assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        login(client,1)
        assert client.post("/sessions/1/cancel",data={"csrf":token(client)}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM training_sessions").fetchone()[0]=="cancelled"
            assert conn.execute("SELECT status FROM registrations").fetchone()[0]=="cancelled"


def test_hidden_venue_blocks_direct_join_and_approval(setup):
    app,path=setup
    later=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=7)).strftime("%Y-%m-%dT%H:%M")
    with sqlite3.connect(path) as conn:
        conn.execute("""INSERT INTO training_sessions
            (venue_id,sport_id,organizer_id,title,starts_at,duration_minutes,capacity,status)
            VALUES (1,1,1,'Временно недоступна',?,60,2,'published')""",(later,))
    with app.test_client() as client:
        login(client,2)
        assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        login(client,4)
        assert client.post("/admin/venues/1/visibility",data={"csrf":token(client),"status":"hidden"}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        assert client.get("/sessions/1").status_code==404
        login(client,2)
        assert 'Площадка временно скрыта'.encode() in client.get("/sessions/1").data
        assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==409
        client.post("/logout",data={"csrf":token(client)})
        login(client,1)
        assert client.post("/sessions/1/participants/1/active",data={"csrf":token(client)}).status_code==409
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM registrations").fetchone()[0]=="pending"


def test_legacy_registration_migration_preserves_rows(tmp_path):
    path=tmp_path / "legacy.sqlite3"
    old_table="""CREATE TABLE IF NOT EXISTS registrations (
        id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES training_sessions(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','cancelled')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(session_id,user_id)
    );\n"""
    begin=SCHEMA.index("CREATE TABLE IF NOT EXISTS registrations (")
    end=SCHEMA.index("CREATE INDEX IF NOT EXISTS idx_registrations_user",begin)
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA[:begin]+old_table+SCHEMA[end:])
        conn.execute("INSERT INTO areas(name) VALUES ('Район')")
        conn.execute("INSERT INTO sports(name) VALUES ('Спорт')")
        conn.execute("""INSERT INTO venues(source_id,name,facility_name,area_id,address,lat,lon,usage_period,paid)
            VALUES (10,'Площадка','Комплекс',1,'Адрес',55.75,37.61,'круглый год','нет')""")
        for i in (1,2):
            conn.execute("INSERT INTO users(email,password_hash,display_name,role) VALUES (?,?,?,'participant')",
                (f"test{i}@example.test","hash",f"Tester {i}"))
        conn.execute("""INSERT INTO training_sessions(venue_id,sport_id,organizer_id,title,starts_at,duration_minutes,capacity)
            VALUES (1,1,1,'Старая',?,60,2)""",((datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=3)).strftime("%Y-%m-%dT%H:%M"),))
        conn.execute("INSERT INTO registrations(session_id,user_id,status) VALUES (1,2,'active')")
    app=create_app({"TESTING":True,"DATABASE":str(path),"SECRET_KEY":"test-only"})
    runner=app.test_cli_runner()
    assert runner.invoke(args=["init-db"]).exit_code==0
    assert runner.invoke(args=["init-db"]).exit_code==0
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT id,session_id,user_id,status FROM registrations").fetchall()==[(1,1,2,'active')]
        assert conn.execute("SELECT updated_at FROM registrations").fetchone()[0]
        assert conn.execute("PRAGMA foreign_key_check").fetchall()==[]
        conn.execute("UPDATE registrations SET status='pending' WHERE id=1")


def test_internal_schedule_conflict(setup):
    app,path=setup
    start=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=8)).strftime("%Y-%m-%dT%H:%M")
    with sqlite3.connect(path) as conn:
        for title,status in (("Первое","published"),("Второе","pending")):
            conn.execute("""INSERT INTO training_sessions(venue_id,sport_id,organizer_id,title,starts_at,duration_minutes,capacity,status)
                VALUES (1,1,1,?,?,60,10,?)""",(title,start,status))
    with app.test_client() as client:
        login(client,3)
        result=client.post("/admin/sessions/2/published",data={"csrf":token(client)})
        assert result.status_code==409
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM training_sessions WHERE id=2").fetchone()[0]=="pending"


def test_source_import_is_complete_and_idempotent(tmp_path):
    path=tmp_path / "import.sqlite3"
    app=create_app({"TESTING":True,"DATABASE":str(path),"SECRET_KEY":"tests-only"})
    runner=app.test_cli_runner()
    assert runner.invoke(args=["import-venues"]).exit_code==0
    assert runner.invoke(args=["import-venues"]).exit_code==0
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT count(*) FROM venues").fetchone()[0]==4751
        assert conn.execute("SELECT count(*) FROM venue_hours").fetchone()[0]==4751*7
        assert conn.execute("SELECT count(DISTINCT source_id) FROM venues").fetchone()[0]==4751
        assert conn.execute("PRAGMA foreign_key_check").fetchall()==[]


def test_event_admin_can_cancel_published_session_but_venue_admin_cannot(setup):
    app,path=setup
    start=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=7)).strftime("%Y-%m-%dT%H:%M")
    with sqlite3.connect(path) as conn:
        conn.execute("""INSERT INTO training_sessions
            (venue_id,sport_id,organizer_id,title,starts_at,duration_minutes,capacity,status)
            VALUES (1,1,1,'Тестовая тренировка',?,60,10,'published')""",(start,))
    with app.test_client() as client:
        login(client,4)
        assert client.post("/admin/sessions/1/cancel",data={"csrf":token(client)}).status_code==403
        client.post("/logout",data={"csrf":token(client)})
        login(client,3)
        panel=client.get("/admin")
        assert b'/admin/sessions/1/cancel' in panel.data
        assert client.post("/admin/sessions/1/cancel",data={"csrf":token(client)}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM training_sessions WHERE id=1").fetchone()[0]=="cancelled"
            assert conn.execute("SELECT action FROM audit_log WHERE object_type='session' ORDER BY id DESC").fetchone()[0]=="admin_cancel"


def test_venue_admin_can_restore_card_and_export_but_participant_cannot(setup):
    app,path=setup
    with app.test_client() as client:
        login(client,2)
        assert client.get("/admin/venues/export.csv").status_code==403
        assert client.post("/admin/venues/1/visibility",data={"csrf":token(client),"status":"hidden"}).status_code==403
        client.post("/logout",data={"csrf":token(client)})
        login(client,4)
        assert client.post("/admin/venues/1/visibility",data={"csrf":token(client),"status":"hidden"}).status_code==302
        assert client.get("/venues/1").status_code==404
        assert b'/admin/venues/1/visibility' in client.get("/admin").data
        assert client.post("/admin/venues/1/visibility",data={"csrf":token(client),"status":"visible"}).status_code==302
        assert client.get("/venues/1").status_code==200
        export=client.get("/admin/venues/export.csv")
        assert export.status_code==200
        assert 'source_id' in export.get_data(as_text=True)
        assert 'paid_comment,website,phone' in export.get_data(as_text=True)
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT public_status FROM venues WHERE id=1").fetchone()[0]=="visible"


def test_organizer_approval_to_public_signup_and_district_search(setup):
    app,path = setup
    when=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=7)).strftime("%Y-%m-%dT%H:%M")
    with app.test_client() as client:
        client.get("/signup")
        bad=client.post("/signup",data={"csrf":token(client),"name":"Новый организатор",
            "email":"wrong@example.test","password":"long-password","role":"organizer","organization_ids":"999"})
        assert bad.status_code==200
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT count(*) FROM users WHERE email='wrong@example.test'").fetchone()[0]==0
        created=client.post("/signup",data={"csrf":token(client),"name":"Новый организатор",
            "email":"new@example.test","password":"long-password","role":"organizer",
            "new_organization":"Спортивный клуб Восток"})
        assert created.status_code==302 and "/organizer/organizations" in created.location
        assert 'ожидает'.encode() in client.get("/organizer/organizations").data
        assert client.get("/sessions/new").status_code==302
        assert client.post("/sessions/new",data={"csrf":token(client),"organization_id":"2",
            "venue_sport":"1:1","title":"Встреча","starts_at":when,"duration":"60","capacity":"4"}).status_code==403
        client.post("/logout",data={"csrf":token(client)})
        login(client,4)
        assert client.post("/admin/organizations/2/active",data={"csrf":token(client)}).status_code==403
        client.post("/logout",data={"csrf":token(client)})
        login(client,3)
        assert 'Спортивный клуб Восток'.encode() in client.get("/admin").data
        assert client.post("/admin/memberships/6/2/approved",data={"csrf":token(client)}).status_code==409
        assert client.post("/admin/organizations/2/active",data={"csrf":token(client)}).status_code==302
        assert client.post("/admin/memberships/6/2/approved",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        client.get("/login")
        response=client.post("/login",data={"csrf":token(client),"email":"new@example.test","password":"long-password"})
        assert response.status_code==302
        assert client.get("/sessions/new?venue_id=1").status_code==200
        assert client.post("/sessions/new",data={"csrf":token(client),"organization_id":"1",
            "venue_sport":"1:1","title":"Недопустимая организация","starts_at":when,
            "duration":"60","capacity":"4"}).status_code==200
        r=client.post("/sessions/new",data={"csrf":token(client),"organization_id":"2",
            "venue_sport":"1:1","title":"Баскетбол у дома","starts_at":when,
            "duration":"60","capacity":"4"})
        assert r.status_code==302
        assert 'Баскетбол у дома'.encode() not in client.get("/sessions").data
        client.post("/logout",data={"csrf":token(client)})
        login(client,3)
        assert client.post("/admin/sessions/1/published",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        good=client.get("/sessions?sport_id=1&area=Тестовый+район&available=1")
        assert 'Баскетбол у дома'.encode() in good.data
        assert 'Спортивный клуб Восток'.encode() in good.data
        assert 'Баскетбол у дома'.encode() not in client.get("/sessions?sport_id=1&area=Другой+район").data
        assert 'Баскетбол у дома'.encode() not in client.get("/sessions?sport_id=999").data
        assert 'Баскетбольная площадка'.encode() in client.get("/venues?area=Тестовый+район&sport_id=1").data
        login(client,2)
        assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==302
        assert 'Ожидает ответа организатора'.encode() in client.get("/my/sessions").data
        client.post("/logout",data={"csrf":token(client)})
        client.get("/login")
        client.post("/login",data={"csrf":token(client),"email":"new@example.test","password":"long-password"})
        assert 'Заявки: 1'.encode() in client.get("/my/sessions").data
        assert client.post("/sessions/1/participants/1/active",data={"csrf":token(client)}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM registrations WHERE session_id=1 AND user_id=2").fetchone()[0]=="active"
            assert conn.execute("SELECT organization_id FROM training_sessions WHERE id=1").fetchone()[0]==2
            assert conn.execute("PRAGMA foreign_key_check").fetchall()==[]


def test_existing_database_upgrade_preserves_events_and_requires_affiliation(tmp_path):
    path=tmp_path / "previous.sqlite3"
    # Reproduce the previous schema with no organizations or event organization_id.
    start=SCHEMA.index("CREATE TABLE IF NOT EXISTS organizations (")
    end=SCHEMA.index("CREATE TABLE IF NOT EXISTS training_sessions (")
    old_schema=(SCHEMA[:start]+SCHEMA[end:]).replace(
        " organization_id INTEGER REFERENCES organizations(id),\n", "").replace(
        " request_id INTEGER REFERENCES activity_requests(id),\n", "").replace(
        " series_id INTEGER REFERENCES event_series(id),\n", "").replace(
        " active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),\n auth_version INTEGER NOT NULL DEFAULT 0",
        " active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))")
    with sqlite3.connect(path) as conn:
        conn.executescript(old_schema)
        conn.execute("INSERT INTO areas(name) VALUES ('Район')")
        conn.execute("INSERT INTO sports(name) VALUES ('Баскетбол')")
        conn.execute("""INSERT INTO venues(source_id,name,facility_name,area_id,address,lat,lon,usage_period,paid)
            VALUES (1,'Старая площадка','Комплекс',1,'Улица',55.75,37.61,'весь год','нет')""")
        conn.execute("INSERT INTO venue_sports VALUES (1,1)")
        conn.execute("INSERT INTO users(email,password_hash,display_name,role) VALUES (?,?,?,'organizer')",
                     ('old@example.test',generate_password_hash('verylongpass'),'Прежний организатор'))
        conn.execute("INSERT INTO users(email,password_hash,display_name,role) VALUES (?,?,?,'participant')",
                     ('oldmember@example.test','hash','Участник'))
        when=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=4)).strftime("%Y-%m-%dT%H:%M")
        conn.execute("""INSERT INTO training_sessions(venue_id,sport_id,organizer_id,title,starts_at,duration_minutes,capacity,status)
            VALUES (1,1,1,'Старая встреча',?,60,10,'published')""",(when,))
        conn.execute("INSERT INTO registrations(session_id,user_id,status) VALUES (1,2,'pending')")
    app=create_app({"TESTING":True,"DATABASE":str(path),"SECRET_KEY":"test-only"})
    runner=app.test_cli_runner()
    assert runner.invoke(args=["init-db"]).exit_code==0
    assert runner.invoke(args=["init-db"]).exit_code==0
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT title,organization_id,request_id FROM training_sessions").fetchall()==[("Старая встреча",None,None)]
        assert conn.execute("SELECT status FROM registrations").fetchall()==[("pending",)]
        assert conn.execute("SELECT count(*) FROM organizations").fetchone()[0]==0
        assert "auth_version" in [column[1] for column in conn.execute("PRAGMA table_info(users)")]
        assert conn.execute("PRAGMA foreign_key_check").fetchall()==[]
    with app.test_client() as client:
        assert 'Старая встреча'.encode() in client.get("/sessions").data
        client.get("/login")
        client.post("/login",data={"csrf":token(client),"email":"old@example.test","password":"verylongpass"})
        assert client.get("/sessions/new").status_code==302
        assert 'Старая встреча'.encode() in client.get("/my/sessions").data
        assert client.post("/sessions/1/participants/1/active",data={"csrf":token(client)}).status_code==403


def test_weekly_series_atomic_review_and_date_filters(setup):
    app,path=setup
    first=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=10)).replace(hour=15,minute=0).strftime("%Y-%m-%dT%H:%M")
    with app.test_client() as client:
        login(client,1)
        response=client.post("/sessions/new",data={"csrf":token(client),"venue_sport":"1:1",
            "organization_id":"1","title":"Еженедельный баскетбол","starts_at":first,
            "duration":"60","capacity":"4","occurrences":"3"})
        assert response.status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT count(*) FROM event_series").fetchone()[0]==1
            dates=[x[0] for x in conn.execute("SELECT starts_at FROM training_sessions ORDER BY id")]
            assert dates==[(datetime.fromisoformat(first)+timedelta(weeks=i)).strftime("%Y-%m-%dT%H:%M")
                           for i in range(3)]
            conn.execute("""INSERT INTO training_sessions
                (venue_id,sport_id,organizer_id,organization_id,title,starts_at,duration_minutes,capacity,status)
                VALUES (1,1,1,1,'Занято',?,60,4,'published')""",(dates[1],))
        client.post("/logout",data={"csrf":token(client)})
        login(client,3)
        assert client.post("/admin/series/1/published",data={"csrf":token(client)}).status_code==409
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT count(*) FROM training_sessions WHERE series_id=1 AND status='published'").fetchone()[0]==0
            conn.execute("UPDATE training_sessions SET status='cancelled' WHERE title='Занято'")
        assert client.post("/admin/series/1/published",data={"csrf":token(client)}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT count(*) FROM training_sessions WHERE series_id=1 AND status='published'").fetchone()[0]==3
        response=client.get("/sessions?date_from="+dates[1][:10]+"&date_to="+dates[1][:10]+"&time_from=14:00&time_to=16:00")
        assert response.status_code==200 and 'Найдено встреч'.encode() in response.data
        assert dates[1].encode() not in response.data  # rendered with separated date and time
        assert client.get("/sessions?view=map").status_code==200
        assert b'events-map' in client.get("/sessions?view=map").data
        assert client.get("/sessions?date_from=2026-99-99").status_code==400


def test_waitlist_promotion_and_notifications(setup):
    app,path=setup
    when=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=5)).strftime("%Y-%m-%dT%H:%M")
    with sqlite3.connect(path) as conn:
        conn.execute("""INSERT INTO training_sessions
            (venue_id,sport_id,organizer_id,organization_id,title,starts_at,duration_minutes,capacity,status)
            VALUES (1,1,1,1,'Матч',?,60,2,'published')""",(when,))
        for idx in (6,7):
            conn.execute("INSERT INTO users(email,password_hash,display_name,role) VALUES (?,?,?,'participant')",
                         (f"u{idx}@example.test",generate_password_hash("verylongpass"),f"User {idx}"))
    with app.test_client() as client:
        for idx in (2,6):
            login(client,idx)
            assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==302
            client.post("/logout",data={"csrf":token(client)})
        login(client,1)
        for reg in (1,2):
            assert client.post(f"/sessions/1/participants/{reg}/active",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        login(client,7)
        assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==302
        assert 'В очереди: ожидает решения'.encode() in client.get("/my/sessions").data
        client.post("/logout",data={"csrf":token(client)})
        login(client,1)
        assert client.post("/sessions/1/participants/3/active",data={"csrf":token(client)}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM registrations WHERE id=3").fetchone()[0]=="waitlist_approved"
        client.post("/logout",data={"csrf":token(client)})
        login(client,2)
        assert client.post("/sessions/1/leave",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        login(client,7)
        assert 'Подтверждена организатором'.encode() in client.get("/my/sessions").data
        assert 'Освободилось место'.encode() in client.get("/notifications").data
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM registrations WHERE id=3").fetchone()[0]=="active"
            assert conn.execute("SELECT count(*) FROM registrations WHERE status='active'").fetchone()[0]==2
        assert client.post("/notifications/1/read",data={"csrf":token(client)}).status_code==404


def test_organization_attendance_and_venue_edit_history(setup):
    app,path=setup
    past=(datetime.now(ZoneInfo("Europe/Moscow"))-timedelta(days=2)).strftime("%Y-%m-%dT%H:%M")
    with sqlite3.connect(path) as conn:
        conn.execute("""INSERT INTO training_sessions
            (venue_id,sport_id,organizer_id,organization_id,title,starts_at,duration_minutes,capacity,status)
            VALUES (1,1,1,1,'Прошедший матч',?,60,2,'published')""",(past,))
        conn.execute("INSERT INTO registrations(session_id,user_id,status) VALUES (1,2,'active')")
    with app.test_client() as client:
        assert client.get("/organizations/1").status_code==200
        login(client,2)
        assert client.post("/sessions/1/attendance/2/present",data={"csrf":token(client)}).status_code==403
        assert client.post("/organizations/1/description",data={"csrf":token(client),"description":"Подмена"}).status_code==403
        client.post("/logout",data={"csrf":token(client)})
        login(client,1)
        assert client.post("/sessions/1/attendance/2/present",data={"csrf":token(client)}).status_code==302
        assert client.post("/organizations/1/description",data={"csrf":token(client),"description":"Тренировки по баскетболу"}).status_code==302
        assert 'Присутствовало: 1'.encode() in client.get("/organizations/1").data
        client.post("/logout",data={"csrf":token(client)})
        login(client,4)
        assert client.get("/admin/venues/1/edit").status_code==200
        values={"name":"Новое имя","facility_name":"Тестовый комплекс","address":"Проверенный адрес",
                "usage_period":"01.01-31.12","paid":"бесплатно","accessibility":""}
        assert client.post("/admin/venues/1/edit",data={"csrf":token(client),**values}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT count(*) FROM venue_edits").fetchone()[0]==2
            assert conn.execute("SELECT address,verified_at FROM venues").fetchone()[0]=="Проверенный адрес"
            assert conn.execute("PRAGMA foreign_key_check").fetchall()==[]
        assert 'Проверенный адрес'.encode() in client.get("/venues/1").data
    seed=path.parent/"one_venue.csv"
    fields=["source_id","name","facility_name","area","address","lat","lon",
            "usage_period","paid","accessibility","opening_hours"]
    with seed.open("w",encoding="utf-8",newline="") as handle:
        writer=csv.DictWriter(handle,fieldnames=fields);writer.writeheader()
        writer.writerow({"source_id":123,"name":"Архивное имя","facility_name":"Старый объект",
            "area":"Тестовый район","address":"Архивный адрес","lat":55.75,"lon":37.61,
            "usage_period":"01.01-31.12","paid":"бесплатно","accessibility":"",
            "opening_hours":json.dumps([{"Hours":"10:00–18:00"}]*7)})
    assert app.test_cli_runner().invoke(args=["import-venues","--file",str(seed)]).exit_code==0
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT name,address FROM venues WHERE id=1").fetchone()==(
            "Новое имя","Проверенный адрес")
        assert conn.execute("SELECT count(*) FROM venue_edits").fetchone()[0]==2


def test_venue_contact_details_import_render_and_admin_correction(setup, tmp_path):
    app,path=setup
    seed=tmp_path/"contacts.csv"
    fields=["source_id","name","facility_name","area","address","lat","lon",
            "usage_period","paid","paid_comment","website","phone","accessibility","opening_hours"]
    row={"source_id":123,"name":"Баскетбольная площадка","facility_name":"Тестовый комплекс",
         "area":"Тестовый район","address":"Тестовая улица","lat":55.75,"lon":37.61,
         "usage_period":"01.01-31.12","paid":"платно","paid_comment":"аренда 5000 руб в час",
         "website":"stadion-spartakovets.ru","phone":"(495) 963-31-63","accessibility":"",
         "opening_hours":json.dumps([{"Hours":"10:00–18:00"}]*7)}
    with seed.open("w",encoding="utf-8",newline="") as handle:
        writer=csv.DictWriter(handle,fieldnames=fields);writer.writeheader();writer.writerow(row)
    assert app.test_cli_runner().invoke(args=["import-venues","--file",str(seed)]).exit_code==0
    with app.test_client() as client:
        detail=client.get("/venues/1").data.decode()
        assert 'href="https://stadion-spartakovets.ru"' in detail
        assert 'href="tel:+74959633163"' in detail
        assert "аренда 5000 руб в час" in detail
        listing=client.get("/venues").data.decode()
        assert "Справочная: (495) 963-31-63" in listing
        assert "Сайт: stadion-spartakovets.ru" in listing
        login(client,4)
        values={"name":row["name"],"facility_name":row["facility_name"],"address":row["address"],
                "usage_period":row["usage_period"],"paid":row["paid"],"accessibility":"",
                "paid_comment":"Стоимость по телефону","website":"https://example.org/info","phone":"+7 495 111-22-33"}
        assert client.post("/admin/venues/1/edit",data={"csrf":token(client),**values,
            "website":"javascript:alert(1)"}).status_code==400
        assert client.post("/admin/venues/1/edit",data={"csrf":token(client),**values}).status_code==302
        assert 'href="https://example.org/info"' in client.get("/venues/1").data.decode()
    assert app.test_cli_runner().invoke(args=["import-venues","--file",str(seed)]).exit_code==0
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT website,phone,paid_comment FROM venues WHERE id=1").fetchone()==(
            "https://example.org/info","+7 495 111-22-33","Стоимость по телефону")
        assert conn.execute("SELECT count(*) FROM venue_edits").fetchone()[0]==3


def test_existing_database_gains_contact_columns(tmp_path):
    path=tmp_path/"old.sqlite3"
    with sqlite3.connect(path) as conn:
        legacy_schema=SCHEMA.replace(" usage_period TEXT NOT NULL,",
                                     " opening_hours TEXT NOT NULL, usage_period TEXT NOT NULL,",1)
        conn.executescript(legacy_schema)
        # Simulate a database created before these three nullable fields existed.
        conn.execute("ALTER TABLE venues DROP COLUMN paid_comment")
        conn.execute("ALTER TABLE venues DROP COLUMN website")
        conn.execute("ALTER TABLE venues DROP COLUMN phone")
        conn.execute("INSERT INTO areas(name) VALUES ('Тестовый район')")
        hours=json.dumps([{"Hours":"08:00–22:00"}]*7)
        conn.execute("""INSERT INTO venues(source_id,name,facility_name,area_id,address,lat,lon,opening_hours,usage_period,paid)
            VALUES (999,'Старая площадка','Стадион',1,'Адрес',55.75,37.61,?,'лето','бесплатно')""",(hours,))
        initialize_database(conn)
        assert {"website","phone","paid_comment"} <= {
            col[1] for col in conn.execute("PRAGMA table_info(venues)")}
        assert "opening_hours" not in {col[1] for col in conn.execute("PRAGMA table_info(venues)")}
        assert conn.execute("SELECT count(*) FROM venue_hours").fetchone()[0]==7
    app=create_app({"TESTING":True,"DATABASE":str(path),"SECRET_KEY":"legacy-only"})
    seed=tmp_path/"legacy.csv"
    with seed.open("w",encoding="utf-8",newline="") as handle:
        fields=["source_id","name","facility_name","area","address","lat","lon",
                "usage_period","paid","paid_comment","website","phone","accessibility","opening_hours"]
        writer=csv.DictWriter(handle,fieldnames=fields);writer.writeheader()
        writer.writerow({"source_id":123,"name":"Тестовая площадка","facility_name":"Старый стадион",
            "area":"Тестовый район","address":"Тестовая улица","lat":55.75,"lon":37.61,
            "usage_period":"лето","paid":"платно","paid_comment":"500 руб/час",
            "website":"example.org","phone":"(495) 123-45-67","accessibility":"",
            "opening_hours":json.dumps([{"Hours":"10:00–18:00"}]*7)})
    result=app.test_cli_runner().invoke(args=["import-venues","--file",str(seed)])
    assert result.exit_code==0, result.output
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT website,paid_comment FROM venues WHERE source_id=123").fetchone()==("example.org","500 руб/час")


def test_venue_filter_shows_places_with_bookable_meetings_first(setup):
    app,path=setup
    future=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=3)).strftime("%Y-%m-%dT%H:%M")
    with sqlite3.connect(path) as conn:
        conn.execute("""INSERT INTO venues(source_id,name,facility_name,area_id,address,lat,lon,usage_period,paid)
            VALUES (124,'Ранний в каталоге','Комплекс',1,'Другая улица',55.75,37.62,'лето','бесплатно')""")
        conn.execute("""INSERT INTO training_sessions(venue_id,sport_id,organizer_id,organization_id,title,starts_at,duration_minutes,capacity,status)
            VALUES (2,1,1,1,'Игра с записью',?,60,10,'published')""",(future,))
    with app.test_client() as client:
        listing=client.get("/venues").data.decode()
        assert listing.index('Ранний в каталоге') < listing.index('Баскетбольная площадка')
        filtered=client.get("/venues?with_events=1").data.decode()
        assert 'Ранний в каталоге' in filtered
        assert 'Баскетбольная площадка' not in filtered
        assert 'Есть встречи: 1' in filtered


def test_venue_report_is_visible_to_author_and_escalates_to_global_admin(setup):
    app,path=setup
    with app.test_client() as client:
        login(client,2)
        assert client.post("/venues/1/report",data={"csrf":token(client),
            "body":"Неверно указан контактный телефон"}).status_code==302
        assert 'Ожидает проверки'.encode() in client.get("/my/sessions").data
        client.post("/logout",data={"csrf":token(client)})
        login(client,4)
        assert 'Неверно указан контактный телефон'.encode() in client.get("/admin").data
        assert client.post("/admin/reports/1/escalated",data={"csrf":token(client)}).status_code==302
        assert 'Неверно указан контактный телефон'.encode() not in client.get("/admin").data
        assert client.post("/admin/reports/1/resolved",data={"csrf":token(client)}).status_code==404
        client.post("/logout",data={"csrf":token(client)})
        login(client,5)
        assert 'Передано на проверку'.encode() in client.get("/admin").data
        assert client.post("/admin/reports/1/resolved",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        login(client,2)
        assert 'Рассмотрено'.encode() in client.get("/my/sessions").data
        assert 'Сообщение о площадке рассмотрено.'.encode() in client.get("/notifications").data
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT status FROM venue_reports").fetchone()[0]=="resolved"


def test_participant_proposal_turns_into_bookable_event(setup):
    app,path=setup
    when=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=7)).strftime("%Y-%m-%dT%H:%M")
    with app.test_client() as client:
        assert client.get("/requests/new").status_code==302
        login(client,2)
        assert client.get("/requests/new").status_code==200
        assert client.post("/requests/new",data={"csrf":token(client),"sport_id":"1",
            "area_id":"1","note":"Дружеская встреча для новичков"}).status_code==302
        assert 'Дружеская встреча для новичков'.encode() in client.get("/my/sessions").data
        assert client.post("/requests/new",data={"csrf":token(client),"sport_id":"1",
            "area_id":"1","note":"Повтор"}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT count(*) FROM activity_requests").fetchone()[0]==1
        client.post("/logout",data={"csrf":token(client)})
        login(client,1)
        assert 'Дружеская встреча для новичков'.encode() in client.get("/organizer/requests").data
        assert 'Баскетбольная площадка'.encode() in client.get("/sessions/new?request_id=1").data
        wrong=client.post("/sessions/new?request_id=1&venue_id=1",data={"csrf":token(client),
            "organization_id":"1","venue_sport":"1:999","title":"Неподходящая встреча",
            "starts_at":when,"duration":"60","capacity":"4"})
        assert wrong.status_code==200
        made=client.post("/sessions/new?request_id=1&venue_id=1",data={"csrf":token(client),
            "organization_id":"1","venue_sport":"1:1","title":"Игра для новичков",
            "starts_at":when,"duration":"60","capacity":"4"})
        assert made.status_code==302
        assert 'Встреча на проверке'.encode() in client.get("/organizer/requests").data
        client.post("/logout",data={"csrf":token(client)})
        login(client,3)
        assert client.post("/admin/sessions/1/published",data={"csrf":token(client)}).status_code==302
        client.post("/logout",data={"csrf":token(client)})
        login(client,2)
        assert 'Посмотреть встречу'.encode() in client.get("/my/sessions").data
        assert client.post("/sessions/1/join",data={"csrf":token(client)}).status_code==302
        assert 'Ожидает ответа организатора'.encode() in client.get("/my/sessions").data
        client.post("/logout",data={"csrf":token(client)})
        login(client,1)
        assert client.post("/sessions/1/cancel",data={"csrf":token(client)}).status_code==302
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT status FROM activity_requests WHERE id=1").fetchone()[0]=="open"
            assert conn.execute("SELECT status FROM registrations WHERE session_id=1").fetchone()[0]=="cancelled"


def test_packaged_primary_database_contains_usable_starting_content(tmp_path):
    import shutil
    source=Path(__file__).resolve().parents[1] / "instance" / "sportmeet.sqlite3"
    path=tmp_path / "sportmeet.sqlite3"
    shutil.copy2(source,path)
    app=create_app({"TESTING":True,"DATABASE":str(path),"SECRET_KEY":"test-only"})
    runner=app.test_cli_runner()
    assert runner.invoke(args=["init-db"]).exit_code==0
    assert runner.invoke(args=["init-db"]).exit_code==0
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT count(*) FROM venues").fetchone()[0]==4751
        assert conn.execute("SELECT count(*) FROM users").fetchone()[0]==30
        assert conn.execute("SELECT count(*) FROM training_sessions WHERE status='published'").fetchone()[0]==31
        assert conn.execute("SELECT count(*) FROM training_sessions WHERE status='pending'").fetchone()[0]==5
        assert conn.execute("SELECT count(*) FROM event_series").fetchone()[0]==2
        assert conn.execute("SELECT count(*) FROM organizations").fetchone()[0]==4
        assert conn.execute("SELECT count(*) FROM registrations").fetchone()[0]==12
        assert conn.execute("SELECT count(*) FROM training_sessions WHERE title LIKE '%учебный пример%'").fetchone()[0]==0
        assert conn.execute("""SELECT count(*) FROM (
            SELECT t.id FROM training_sessions t JOIN registrations r ON r.session_id=t.id
            WHERE r.status='active' GROUP BY t.id HAVING count(*)>t.capacity)""").fetchone()[0]==0
        assert conn.execute("PRAGMA foreign_key_check").fetchall()==[]
        rows=conn.execute("SELECT email,role,password_hash FROM users ORDER BY role").fetchall()
        assert all(check_password_hash(row[2],"SportRyadom26!") for row in rows)
        assert len({row[2] for row in rows})==30
    with app.test_client() as client:
        assert 'Футбол для начинающих'.encode() in client.get("/sessions").data
        for role in ("participant","organizer","venue-admin","event-admin","global-admin"):
            client.get("/login")
            response=client.post("/login",data={"csrf":token(client),
                "email":f"{role}@sportmeet.local","password":"SportRyadom26!"})
            assert response.status_code==302
            client.post("/logout",data={"csrf":token(client)})


def test_password_change_rehashes_and_revokes_other_sessions(setup):
    app,path=setup
    one=app.test_client(); other=app.test_client()
    login(one,2)
    login(other,2)
    assert one.get("/account").status_code==200
    assert one.post("/account/password",data={"csrf":token(one),
        "current_password":"wrong","new_password":"NewStrongPassword!2026",
        "confirm_password":"NewStrongPassword!2026"}).status_code==302
    with sqlite3.connect(path) as conn:
        assert check_password_hash(conn.execute("SELECT password_hash FROM users WHERE id=2").fetchone()[0],
                                   "verylongpass")
    assert one.post("/account/password",data={"csrf":token(one),
        "current_password":"verylongpass","new_password":"NewStrongPassword!2026",
        "confirm_password":"NewStrongPassword!2026"}).status_code==302
    with sqlite3.connect(path) as conn:
        hashed,version=conn.execute("SELECT password_hash,auth_version FROM users WHERE id=2").fetchone()
        assert hashed.startswith("scrypt:32768:8:1$") and version==1
        assert "NewStrongPassword!2026" not in hashed
        assert check_password_hash(hashed,"NewStrongPassword!2026")
    assert other.get("/account").status_code==302
    assert one.get("/account").status_code==200
    one.post("/logout",data={"csrf":token(one)})
    one.get("/login")
    assert one.post("/login",data={"csrf":token(one),"email":"u2@example.test",
                                  "password":"verylongpass"}).status_code==200
    assert one.post("/login",data={"csrf":token(one),"email":"u2@example.test",
                                  "password":"NewStrongPassword!2026"}).status_code==302


def test_specific_role_actions_and_role_change_revokes_access(setup):
    app,path=setup
    assert POLICIES["venue_admin"].allows("venue_edits")
    assert not POLICIES["venue_admin"].allows("publish_sessions")
    assert POLICIES["event_admin"].allows("publish_sessions")
    assert not POLICIES["event_admin"].allows("venue_edits")
    assert POLICIES["global_admin"].allows("role_assign")
    assert len(CAPABILITY_LABELS)>=15
    when=(datetime.now(ZoneInfo("Europe/Moscow"))+timedelta(days=6)).strftime("%Y-%m-%dT%H:%M")
    with sqlite3.connect(path) as conn:
        conn.execute("""INSERT INTO training_sessions(venue_id,sport_id,organizer_id,organization_id,
            title,starts_at,duration_minutes,capacity,status)
            VALUES (1,1,1,1,'Ожидает решения',?,60,8,'pending')""",(when,))
    organizer=app.test_client(); admin=app.test_client()
    assert organizer.get("/roles").status_code==200
    login(organizer,1)
    login(admin,5)
    assert admin.post("/admin/users/1/role",data={"csrf":token(admin),"role":"participant"}).status_code==302
    assert organizer.get("/sessions/new").status_code==302
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT auth_version FROM users WHERE id=1").fetchone()[0]==1
    admin.post("/logout",data={"csrf":token(admin)})
    login(admin,3)
    assert admin.post("/admin/sessions/1/published",data={"csrf":token(admin)}).status_code==409
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT status FROM training_sessions WHERE id=1").fetchone()[0]=="pending"


def test_affiliation_revoke_blocks_organizer_and_keeps_other_roles_scoped(setup):
    app,path=setup
    organizer=app.test_client();event_admin=app.test_client();venue_admin=app.test_client()
    login(organizer,1);login(event_admin,3);login(venue_admin,4)
    assert event_admin.get("/admin/venues/1/edit").status_code==403
    assert venue_admin.post("/admin/memberships/1/1/revoke",data={"csrf":token(venue_admin)}).status_code==403
    assert event_admin.post("/admin/memberships/1/1/revoke",data={"csrf":token(event_admin)}).status_code==302
    assert organizer.get("/sessions/new").status_code==302
    organizer.get("/login")
    organizer.post("/login",data={"csrf":token(organizer),"email":"u1@example.test","password":"verylongpass"})
    assert organizer.get("/sessions/new").status_code==302
    assert organizer.post("/sessions/new",data={"csrf":token(organizer)}).status_code==403
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT status FROM organization_memberships WHERE user_id=1").fetchone()[0]=="rejected"
        assert conn.execute("SELECT auth_version FROM users WHERE id=1").fetchone()[0]==1


def test_review_requires_recorded_attendance(setup):
    app,path=setup
    past=(datetime.now(ZoneInfo("Europe/Moscow"))-timedelta(days=2)).strftime("%Y-%m-%dT%H:%M")
    with sqlite3.connect(path) as conn:
        conn.execute("""INSERT INTO training_sessions
            (venue_id,sport_id,organizer_id,organization_id,title,starts_at,duration_minutes,capacity,status)
            VALUES (1,1,1,1,'Прошедшая встреча',?,60,8,'published')""",(past,))
        conn.execute("INSERT INTO registrations(session_id,user_id,status) VALUES (1,2,'active')")
    participant=app.test_client(); organizer=app.test_client()
    login(participant,2)
    data={"rating":"5","body":"Хорошая тренировка и отличная команда."}
    assert participant.post("/sessions/1/review",data={"csrf":token(participant),**data}).status_code==400
    assert 'Отправить отзыв'.encode() not in participant.get("/sessions/1").data
    login(organizer,1)
    assert organizer.post("/sessions/1/attendance/2/present",
                          data={"csrf":token(organizer)}).status_code==302
    assert 'Отправить отзыв'.encode() in participant.get("/sessions/1").data
    assert participant.post("/sessions/1/review",data={"csrf":token(participant),**data}).status_code==302
    response=participant.get("/sessions/1").data
    assert 'Ваш отзыв отправлен на проверку.'.encode() in response
    assert 'Отправить отзыв'.encode() not in response
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT status FROM reviews").fetchone()[0]=="pending"
