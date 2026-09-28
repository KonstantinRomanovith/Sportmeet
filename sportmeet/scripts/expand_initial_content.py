"""One-time source of the bundled local sample accounts and events.

Run only on the original five-user, six-event database. Normal app startup
does not invoke this script and never resets user changes.
"""
from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import hash_password, initialize_database  # noqa: E402


def main() -> None:
    path = ROOT / "instance" / "sportmeet.sqlite3"
    now = datetime.now(ZoneInfo("Europe/Moscow"))

    def when(days: int, hour: int) -> str:
        return (now + timedelta(days=days)).replace(
            hour=hour, minute=0, second=0, microsecond=0
        ).strftime("%Y-%m-%dT%H:%M")

    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        initialize_database(conn)
        counts = tuple(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                       for table in ("users", "training_sessions"))
        if counts != (5, 6):
            raise SystemExit("This one-time source expects five users and six events; database left untouched.")
        with conn:
            conn.execute("""UPDATE organizations SET name='Городской спортивный клуб',
                description='Сообщество для открытых тренировок. Начальные записи локальной базы
                служат проверке проекта; реальная деятельность не подтверждена.' WHERE id=1""")
            conn.execute("""UPDATE event_series SET title=replace(title,' · учебный пример',''),
                description='Расписание в локальной версии служит проверке записи; фактическое проведение не подтверждено.'""")
            conn.execute("""UPDATE training_sessions SET title=replace(title,' · учебный пример',''),
                description='Встреча доступна для проверки записи; фактическое проведение вне приложения не подтверждено.'
                WHERE title LIKE '%учебный пример%'""")
            for name,desc in (
                ("Северное движение", "Открытые тренировки жителей северных районов."),
                ("Дворовая лига", "Любительские игры и командные встречи."),
                ("Спортивное сообщество Юг", "Групповые занятия по нескольким видам спорта."),
            ):
                conn.execute("INSERT INTO organizations(name,status,description) VALUES (?,'active',?)", (name,desc))
            accounts = [(f"participant{i:02d}@sportmeet.local",f"Участник {i:02d}","participant")
                        for i in range(2,21)]
            accounts += [(f"organizer{i:02d}@sportmeet.local",f"Организатор {i:02d}","organizer")
                         for i in range(2,6)]
            accounts += [
                ("venue-admin02@sportmeet.local","Администратор площадок 02","venue_admin"),
                ("event-admin02@sportmeet.local","Администратор мероприятий 02","event_admin"),
            ]
            for email,name,role in accounts:
                conn.execute("INSERT INTO users(email,password_hash,display_name,role) VALUES (?,?,?,?)",
                             (email,hash_password("SportRyadom26!"),name,role))
            orgs=[row[0] for row in conn.execute("SELECT id FROM organizations ORDER BY id")]
            owners=[conn.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()[0]
                    for email in ("organizer@sportmeet.local",
                                  *(f"organizer{i:02d}@sportmeet.local" for i in range(2,6)))]
            for index,owner in enumerate(owners[1:],start=1):
                conn.execute("""INSERT INTO organization_memberships(user_id,organization_id,status)
                    VALUES (?,?,'approved')""",(owner,orgs[index%len(orgs)]))
            conn.execute("""INSERT INTO organization_memberships(user_id,organization_id,status)
                VALUES (?,?,'approved')""",(owners[-1],orgs[1]))

            titles={
                1:["Зарядка на свежем воздухе","ОФП без специальной подготовки",
                   "Тренировка на выносливость","Утренняя разминка","Движение после работы"],
                2:["Футбол 5×5","Футбол для любителей","Вечерняя игра в футбол",
                   "Открытая футбольная тренировка","Футбол в выходной"],
                3:["Баскетбол для начинающих","Играем в баскетбол","Баскетбол после работы",
                   "Тренировка броска","Командный баскетбол"],
                4:["Волейбол для соседей","Вечерний волейбол","Волейбол для новичков",
                   "Игра в команде","Открытая волейбольная встреча"],
                5:["Теннис для начинающих","Парный теннис","Теннис вечером",
                   "Тренировка подачи","Теннисная встреча"],
            }
            desc=("Подходит участникам разного уровня. Возьмите удобную одежду и воду. "
                  "Заявку подтверждает организатор. Начальные записи служат проверке приложения; "
                  "фактическое проведение не подтверждено.")
            new_ids=[]
            for i in range(25):
                sport=1+i%5
                venue=conn.execute("""SELECT venue_id FROM venue_sports WHERE sport_id=?
                    ORDER BY venue_id LIMIT 1 OFFSET ?""",(sport,i//5+2)).fetchone()[0]
                owner_index=i%len(owners)
                status="pending" if i in {6,12,18,24} else "published"
                new_ids.append(conn.execute("""INSERT INTO training_sessions
                    (venue_id,sport_id,organizer_id,organization_id,title,description,
                    starts_at,duration_minutes,capacity,status)
                    VALUES (?,?,?,?,?,?,?,60,?,?)""",
                    (venue,sport,owners[owner_index],orgs[owner_index%len(orgs)],
                     titles[sport][i//5],desc,when(3+2*i,(10,12,16,18)[i%4]),
                     2 if i==0 else (6,8,10,12,16)[i%5],status)).lastrowid)
            venue=conn.execute("""SELECT venue_id FROM venue_sports WHERE sport_id=2
                ORDER BY venue_id LIMIT 1 OFFSET 10""").fetchone()[0]
            series=conn.execute("""INSERT INTO event_series
                (organizer_id,organization_id,venue_id,sport_id,title,description,duration_minutes,capacity)
                VALUES (?,?,?,2,?,?,60,10)""",
                (owners[1],orgs[1],venue,"Еженедельный футбол",desc)).lastrowid
            for day in (20,27,34):
                conn.execute("""INSERT INTO training_sessions
                    (venue_id,sport_id,organizer_id,organization_id,series_id,title,
                    description,starts_at,duration_minutes,capacity,status)
                    VALUES (?,2,?,?,?,?,?,?,60,10,'published')""",
                    (venue,owners[1],orgs[1],series,"Еженедельный футбол",desc,when(day,19)))
            past=[]
            for venue,sport,owner,org,title,day in (
                (90,3,owners[2],orgs[2],"Баскетбольная встреча",-6),
                (17,4,owners[3],orgs[3],"Волейбольная встреча",-10),
            ):
                past.append(conn.execute("""INSERT INTO training_sessions
                    (venue_id,sport_id,organizer_id,organization_id,title,description,
                    starts_at,duration_minutes,capacity,status)
                    VALUES (?,?,?,?,?,?,?,60,10,'published')""",
                    (venue,sport,owner,org,title,desc,when(day,14))).lastrowid)
            people=[conn.execute("SELECT id FROM users WHERE email=?",
                     (f"participant{i:02d}@sportmeet.local",)).fetchone()[0] for i in range(2,21)]
            for person,status in zip(people[:4],
                                     ("active","active","waitlist_approved","waitlisted")):
                conn.execute("INSERT INTO registrations(session_id,user_id,status) VALUES (?,?,?)",
                             (new_ids[0],person,status))
            for person in people[4:7]:
                conn.execute("INSERT INTO registrations(session_id,user_id,status) VALUES (?,?,'pending')",
                             (new_ids[2],person))
            for person in people[7:10]:
                conn.execute("INSERT INTO registrations(session_id,user_id,status) VALUES (?,?,'active')",
                             (new_ids[3],person))
            for event,owner,person in zip(past,(owners[2],owners[3]),people[10:12]):
                conn.execute("INSERT INTO registrations(session_id,user_id,status) VALUES (?,?,'active')",
                             (event,person))
                conn.execute("INSERT INTO session_attendance(session_id,user_id,marked_by) VALUES (?,?,?)",
                             (event,person,owner))
            conn.execute("""INSERT INTO reviews(session_id,user_id,rating,body,status)
                VALUES (?,?,5,?,'approved')""",
                (past[0],people[10],"Занятие прошло в дружелюбной атмосфере."))
            conn.execute("""INSERT INTO reviews(session_id,user_id,rating,body,status)
                VALUES (?,?,4,?,'pending')""",
                (past[1],people[11],"Понравился формат командной игры."))
            for sport,venue,person in ((2,16,people[12]),(3,90,people[13]),(4,17,people[14])):
                area=conn.execute("SELECT area_id FROM venues WHERE id=?",(venue,)).fetchone()[0]
                conn.execute("INSERT INTO activity_requests(user_id,sport_id,area_id,note) VALUES (?,?,?,?)",
                             (person,sport,area,"Хотелось бы больше встреч в этом районе в выходные."))
            for venue,person,status in ((16,people[15],"open"),(90,people[16],"escalated")):
                conn.execute("""INSERT INTO venue_reports(venue_id,user_id,body,status)
                    VALUES (?,?,?,?)""",
                    (venue,person,"Прошу проверить актуальность сведений из архивного каталога.",status))
            conn.execute("""INSERT INTO notifications(user_id,session_id,kind,message)
                VALUES (?,?,?,?)""",
                (people[2],new_ids[0],"application","Организатор одобрил место в очереди."))
            if conn.execute("PRAGMA foreign_key_check").fetchone():
                raise sqlite3.IntegrityError("Invalid foreign key in bundled content")
        print("Added local accounts, organizations, meetings, registrations and moderation queues.")


if __name__ == "__main__":
    main()
