"""Создание таблиц и первичных данных.

Запуск:  .venv\\Scripts\\python.exe init_db.py            (создать таблицы)
         .venv\\Scripts\\python.exe init_db.py --demo     (создать таблицы + демо-аккаунт)

Скрипт печатает реальный путь к файлу базы — именно его открывайте в DBeaver.
"""
import os
import sys
from datetime import date, time, timedelta

from sqlalchemy import inspect

from app import app, db, User, Event, Lesson, Grade

DEMO_EMAIL = "demo@example.ru"
DEMO_PASSWORD = "demo12345"


def main() -> None:
    with app.app_context():
        uri = app.config["SQLALCHEMY_DATABASE_URI"]
        db.create_all()

        print(f"База данных: {db.engine.url.database}")
        print(f"Строка подключения: {uri}")

        tables = sorted(inspect(db.engine).get_table_names())
        print("Таблицы:", ", ".join(tables) if tables else "—")

        if "--demo" in sys.argv:
            user = User.query.filter_by(email=DEMO_EMAIL).first()
            if not user:
                user = User(email=DEMO_EMAIL, email_verified=True)
                user.set_password(DEMO_PASSWORD)
                db.session.add(user)
                db.session.commit()
                print(f"Создан демо-аккаунт: {DEMO_EMAIL} / {DEMO_PASSWORD}")
            else:
                print("Демо-аккаунт уже существует.")

            profile = user.profile_or_create()
            profile.full_name = "Иванова Мария Сергеевна"
            profile.group_name = "ЛДс 26-2-0"
            profile.faculty = "Лечебное дело"
            profile.course = 2
            user.settings_or_create()

            if not Event.query.filter_by(user_id=user.id).first():
                today = date.today()
                db.session.add_all([
                    Event(user_id=user.id, title="Контрольная по анатомии", kind="test",
                          event_date=today + timedelta(days=2), start_time=time(10, 0),
                          end_time=time(11, 30), location="101"),
                    Event(user_id=user.id, title="Олимпиада по фармакологии", kind="olymp",
                          event_date=today + timedelta(days=5), start_time=time(14, 0),
                          location="Актовый зал"),
                ])

            if not Lesson.query.filter_by(user_id=user.id).first():
                db.session.add_all([
                    Lesson(user_id=user.id, subject="Анатомия человека", teacher="Иванова М. С.",
                           room="101", weekday=0, start_time=time(9, 0),
                           end_time=time(10, 30), parity="all", kind="lecture"),
                    Lesson(user_id=user.id, subject="Фармакология", room="204", weekday=2,
                           start_time=time(10, 40), end_time=time(12, 10),
                           parity="even", kind="practice"),
                ])

            if not Grade.query.filter_by(user_id=user.id).first():
                db.session.add_all([
                    Grade(user_id=user.id, subject="Анатомия человека", value=5,
                          control="Контрольная"),
                    Grade(user_id=user.id, subject="Фармакология", value=4, control="Семинар"),
                ])

            db.session.commit()
            print("Демо-данные добавлены.")

        print("Готово.")


if __name__ == "__main__":
    main()
