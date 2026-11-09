from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import (StringField, PasswordField, SubmitField, TextAreaField, SelectField,
                     DateField, TimeField, BooleanField, IntegerField)
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional, NumberRange
from datetime import datetime, timedelta, date, time
import hashlib
import hmac
import secrets
import smtplib
import ssl
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import gzip
from sqlalchemy.exc import IntegrityError
from urllib.parse import urlsplit
import calendar as pycalendar
import os
from dotenv import load_dotenv

load_dotenv()  # читает .env и кладёт переменные в os.environ

app = Flask(__name__)

# --- Подключение к базе данных ---
# Если в .env задан DB_USER (как в исходном MySQL-варианте) — подключаемся к MySQL.
# Иначе работаем с SQLite в папке instance рядом с app.py.
# DATABASE_URL, если задан, имеет приоритет над DB_*.
#
# Важно: относительный путь в SQLite считается от ТЕКУЩЕЙ рабочей папки,
# а не от файла app.py. Поэтому путь всегда вычисляется от BASE_DIR ниже —
# иначе база создаётся в неожиданном месте (например, instance/instance/pr3.db)
# и DBeaver её не видит.

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
SQLITE_PATH = os.path.join(INSTANCE_DIR, "pr3.db")


def _normalize_database_url(url: str) -> str:
    """Приводит DATABASE_URL к абсолютному пути для SQLite.

    sqlite:///C:/путь/файл.db  — уже абсолютный (Windows-диск)
    sqlite:///instance/pr3.db  — относительный, пересчитывается от BASE_DIR
    sqlite:////абсолютный/путь — абсолютный в POSIX
    """
    if not url or not url.startswith("sqlite"):
        return url
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        return url
    raw = url[len(prefix):]
    if not raw or raw == ":memory:":
        return url
    if len(raw) > 2 and raw[1] == ":":
        return url
    if raw.startswith("/") or raw.startswith("\\\\"):
        return url
    raw = raw.replace("\\", "/")
    return prefix + os.path.join(BASE_DIR, raw).replace("\\", "/")


DATABASE_URL = os.environ.get("DATABASE_URL")
DB_USER = os.environ.get("DB_USER")
DB_NAME = os.environ.get("DB_NAME")

if DATABASE_URL:
    app.config["SQLALCHEMY_DATABASE_URI"] = _normalize_database_url(DATABASE_URL)
elif DB_USER and DB_NAME:
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
    DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
    DB_PORT = os.environ.get("DB_PORT", "3306")

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        "?charset=utf8mb4"
    )
else:
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "sqlite:///" + SQLITE_PATH.replace("\\", "/")
    )

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

# --- Безопасность сессии и CSRF ---
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"

# Secure cookies включаются для production по умолчанию или явно через COOKIE_SECURE=1.
# Для локального HTTP оставляйте COOKIE_SECURE=0; для HTTPS staging/production включайте 1.
cookie_secure_env = os.environ.get("COOKIE_SECURE", "").strip().lower()
cookie_secure = (
    cookie_secure_env in {"1", "true", "yes", "on"}
    if cookie_secure_env
    else os.environ.get("FLASK_ENV", "").lower() == "production"
)
app.config["SESSION_COOKIE_SECURE"] = cookie_secure
app.config["REMEMBER_COOKIE_SECURE"] = cookie_secure

# Защита всех изменяющих запросов, включая маршруты не на FlaskForm.
csrf = CSRFProtect(app)

@app.after_request
def add_security_headers(response):
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "img-src 'self' data:; "
        "style-src 'self'; "
        "style-src-attr 'unsafe-inline'; "
        "script-src 'self'; "
        "font-src 'self' data:"
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response

@app.after_request
def add_gzip_compression(response):
    """Сжатие ответов (gzip) для текстовых ресурсов — пункт «Сжатие» чек-листа.

    Сжимаем HTML, CSS, JS и JSON, если клиент передал Accept-Encoding: gzip
    и ответ ещё не сжат выше по конвейеру. Тела меньше 500 байт не трогаем.
    """
    ACCEPTED = {"text/html", "text/css", "application/javascript",
                "application/json", "text/plain", "application/xml"}
    if response.status_code < 200 or response.status_code >= 300:
        return response
    if response.direct_passthrough or response.content_length and response.content_length < 500:
        return response
    ctype = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if ctype not in ACCEPTED:
        return response
    if not response.direct_passthrough and hasattr(response, "get_data"):
        try:
            if "gzip" not in (request.headers.get("Accept-Encoding") or "").lower():
                return response
            data = response.get_data()
            if not data or len(data) < 500:
                return response
            if response.headers.get("Content-Encoding"):
                return response
            gz = gzip.compress(data, compresslevel=6)
            if len(gz) >= len(data):
                return response
            response.set_data(gz)
            response.headers["Content-Encoding"] = "gzip"
            response.headers["Content-Length"] = str(len(gz))
            response.headers["Vary"] = "Accept-Encoding"
        except Exception:
            # Если что-то пошло не так — отдаём исходный ответ.
            pass
    return response

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"          # куда перенаправлять неавторизованных
login_manager.login_message = "Войдите, чтобы продолжить."
login_manager.session_protection = "basic"

# --- Инициализация Limiter для защиты от brute-force ---
limiter = Limiter(
    key_func=get_remote_address,  # Лимит по IP-адресу
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Общие лимиты для всего сайта
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),  # Для нескольких workers задайте Redis.
)


# --- Модели данных ---
# Каждый пользователь владеет своими записями: профиль, мероприятия, занятия,
# заметки, оценки и настройки. Внешние ключи с ondelete="CASCADE" и фильтрация
# по current_user.id не дают увидеть чужие данные (разделение данных).

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    email_verification_code_hash = db.Column(db.String(64), nullable=True)
    email_verification_expires_at = db.Column(db.DateTime, nullable=True)
    email_verification_last_sent_at = db.Column(db.DateTime, nullable=True)

    profile = db.relationship("Profile", back_populates="user", uselist=False,
                              cascade="all, delete-orphan")
    settings = db.relationship("UserSettings", back_populates="user", uselist=False,
                               cascade="all, delete-orphan")
    events = db.relationship("Event", back_populates="user", cascade="all, delete-orphan")
    lessons = db.relationship("Lesson", back_populates="user", cascade="all, delete-orphan")
    grades = db.relationship("Grade", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def display_name(self) -> str:
        if self.profile and self.profile.full_name:
            return self.profile.full_name
        return self.email.split("@")[0]

    @property
    def initials(self) -> str:
        name = self.display_name.strip()
        parts = [p for p in name.replace(".", " ").split() if p]
        if len(parts) >= 2:
            return (parts[0][0] + parts[1][0]).upper()
        return name[:2].upper() if name else "SS"

    def profile_or_create(self) -> "Profile":
        if not self.profile:
            self.profile = Profile()
            db.session.add(self.profile)
            db.session.commit()
        return self.profile

    def settings_or_create(self) -> "UserSettings":
        if not self.settings:
            self.settings = UserSettings()
            db.session.add(self.settings)
            db.session.commit()
        return self.settings


class Profile(db.Model):
    """Профиль студента: персональные данные хранятся отдельной таблицей."""
    __tablename__ = "profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=True)
    group_name = db.Column(db.String(60), nullable=True)
    faculty = db.Column(db.String(120), nullable=True)
    course = db.Column(db.Integer, nullable=True)
    student_id = db.Column(db.String(40), nullable=True)
    moodle_url = db.Column(db.String(255), nullable=True)
    moodle_token = db.Column(db.String(255), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship("User", back_populates="profile")


class UserSettings(db.Model):
    """Общие настройки интерфейса и напоминаний."""
    __tablename__ = "user_settings"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        unique=True, nullable=False, index=True)
    theme = db.Column(db.String(20), nullable=False, default="sand")        # sand | wine | navy
    show_odd_weeks = db.Column(db.Boolean, nullable=False, default=True)
    notify_events = db.Column(db.Boolean, nullable=False, default=True)
    notify_grades = db.Column(db.Boolean, nullable=False, default=True)
    compact_schedule = db.Column(db.Boolean, nullable=False, default=False)
    first_week_parity = db.Column(db.String(10), nullable=False, default="even")  # чётность 1-й недели в семестре

    user = db.relationship("User", back_populates="settings")


EVENT_KINDS = {
    "study": "Учебное",
    "exam": "Экзамен / зачёт",
    "test": "Контрольная",
    "olymp": "Олимпиада",
    "meeting": "Собрание",
    "other": "Другое",
}

EVENT_STATUSES = {
    "planned": "Запланировано",
    "done": "Выполнено",
    "cancelled": "Отменено",
}


class Event(db.Model):
    """Мероприятия: полный CRUD, данные принадлежат пользователю."""
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    title = db.Column(db.String(160), nullable=False)
    kind = db.Column(db.String(20), nullable=False, default="other")
    description = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(160), nullable=True)
    event_date = db.Column(db.Date, nullable=False, index=True)
    start_time = db.Column(db.Time, nullable=True)
    end_time = db.Column(db.Time, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="planned")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship("User", back_populates="events")

    @property
    def kind_label(self) -> str:
        return EVENT_KINDS.get(self.kind, "Другое")

    @property
    def status_label(self) -> str:
        return EVENT_STATUSES.get(self.status, "Запланировано")

    @property
    def time_label(self) -> str:
        if self.start_time and self.end_time:
            return f"{self.start_time:%H:%M}–{self.end_time:%H:%M}"
        if self.start_time:
            return f"{self.start_time:%H:%M}"
        return "весь день"


WEEKDAYS = ["Понедельник", "Вторник", "Среда", "Четверг", "Пятница", "Суббота", "Воскресенье"]


class Lesson(db.Model):
    """Занятие в расписании. parity: all | even | odd — чётность недели."""
    __tablename__ = "lessons"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    subject = db.Column(db.String(160), nullable=False)
    teacher = db.Column(db.String(120), nullable=True)
    room = db.Column(db.String(60), nullable=True)
    weekday = db.Column(db.Integer, nullable=False, default=0)   # 0 = понедельник
    start_time = db.Column(db.Time, nullable=False, default=lambda: time(9, 0))
    end_time = db.Column(db.Time, nullable=True)
    parity = db.Column(db.String(10), nullable=False, default="all")   # all | even | odd
    kind = db.Column(db.String(30), nullable=False, default="lecture")  # lecture | practice | lab | exam
    note = db.Column(db.Text, nullable=True)
    note_updated_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", back_populates="lessons")

    @property
    def weekday_label(self) -> str:
        return WEEKDAYS[self.weekday] if 0 <= self.weekday < 7 else "—"

    @property
    def time_label(self) -> str:
        if self.end_time:
            return f"{self.start_time:%H:%M}–{self.end_time:%H:%M}"
        return f"{self.start_time:%H:%M}"


LESSON_KINDS = {
    "lecture": "Лекция",
    "practice": "Практика",
    "lab": "Лабораторная",
    "exam": "Экзамен / зачёт",
}

PARITY_LABELS = {"all": "каждую неделю", "even": "чётная неделя", "odd": "нечётная неделя"}


class Grade(db.Model):
    """Оценка по дисциплине для отслеживания успеваемости."""
    __tablename__ = "grades"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    subject = db.Column(db.String(160), nullable=False)
    value = db.Column(db.Integer, nullable=False)
    weight = db.Column(db.Integer, nullable=False, default=1)
    control = db.Column(db.String(120), nullable=True)
    graded_on = db.Column(db.Date, nullable=False, default=date.today)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="grades")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def is_safe_next(target):
    """Разрешает перенаправление после входа только на путь внутри этого сайта.

    Отклоняются полные адреса (https://...), адреса без схемы (//host),
    обратные слэши (браузеры считают их за обычные) и управляющие символы.
    """
    if not target or any(ord(ch) < 32 for ch in target):
        return False
    if not target.startswith("/") or target.startswith("//") or target.startswith("/\\"):
        return False
    parts = urlsplit(target)
    return not parts.scheme and not parts.netloc


# --- Формы ---
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Пароль", validators=[DataRequired(), Length(min=8, max=128)])
    confirm = PasswordField("Повторите пароль", validators=[DataRequired(), EqualTo("password", message="Пароли не совпадают")])
    submit = SubmitField("Зарегистрироваться")


class VerifyEmailForm(FlaskForm):
    code = StringField("Код подтверждения", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Подтвердить email")


class ResendVerificationForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    submit = SubmitField("Отправить код")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Пароль", validators=[DataRequired()])
    submit = SubmitField("Войти")


class ProfileForm(FlaskForm):
    full_name = StringField("ФИО", validators=[Optional(), Length(max=120)])
    group_name = StringField("Группа", validators=[Optional(), Length(max=60)])
    faculty = StringField("Факультет / отделение", validators=[Optional(), Length(max=120)])
    course = IntegerField("Курс", validators=[Optional(), NumberRange(min=1, max=6)])
    student_id = StringField("Номер студенческого", validators=[Optional(), Length(max=40)])
    bio = TextAreaField("О себе", validators=[Optional(), Length(max=2000)])
    submit = SubmitField("Сохранить профиль")


class SettingsForm(FlaskForm):
    theme = SelectField("Оформление", choices=[("sand", "Песочная"), ("wine", "Винная"), ("navy", "Тёмно-синяя")])
    first_week_parity = SelectField("Первая неделя семестра", choices=[("even", "Чётная"), ("odd", "Нечётная")])
    show_odd_weeks = BooleanField("Показывать нечётные недели")
    notify_events = BooleanField("Напоминать о мероприятиях")
    notify_grades = BooleanField("Сообщать о новых оценках")
    compact_schedule = BooleanField("Компактное расписание")
    submit = SubmitField("Сохранить настройки")


class EmailForm(FlaskForm):
    email = StringField("Новый email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Текущий пароль", validators=[DataRequired()])
    submit = SubmitField("Изменить email")


class PasswordForm(FlaskForm):
    current = PasswordField("Текущий пароль", validators=[DataRequired()])
    password = PasswordField("Новый пароль", validators=[DataRequired(), Length(min=8, max=128)])
    confirm = PasswordField("Повторите пароль", validators=[DataRequired(), EqualTo("password", message="Пароли не совпадают")])
    submit = SubmitField("Изменить пароль")


class MoodleForm(FlaskForm):
    moodle_url = StringField("Адрес Moodle", validators=[Optional(), Length(max=255)])
    moodle_token = StringField("Токен доступа", validators=[Optional(), Length(max=255)])
    submit = SubmitField("Сохранить связку")


class EventForm(FlaskForm):
    title = StringField("Название", validators=[DataRequired(), Length(max=160)])
    kind = SelectField("Тип", choices=[(k, v) for k, v in EVENT_KINDS.items()])
    event_date = DateField("Дата", validators=[DataRequired()])
    start_time = TimeField("Начало", validators=[Optional()])
    end_time = TimeField("Окончание", validators=[Optional()])
    location = StringField("Место", validators=[Optional(), Length(max=160)])
    status = SelectField("Статус", choices=[(k, v) for k, v in EVENT_STATUSES.items()])
    description = TextAreaField("Описание", validators=[Optional(), Length(max=2000)])
    submit = SubmitField("Сохранить")


class LessonForm(FlaskForm):
    subject = StringField("Дисциплина", validators=[DataRequired(), Length(max=160)])
    teacher = StringField("Преподаватель", validators=[Optional(), Length(max=120)])
    room = StringField("Аудитория", validators=[Optional(), Length(max=60)])
    weekday = SelectField("День недели", choices=[(str(i), n) for i, n in enumerate(WEEKDAYS)], default="0")
    start_time = TimeField("Начало", validators=[DataRequired()])
    end_time = TimeField("Окончание", validators=[Optional()])
    parity = SelectField("Чётность недели", choices=[(k, v) for k, v in PARITY_LABELS.items()])
    kind = SelectField("Тип занятия", choices=[(k, v) for k, v in LESSON_KINDS.items()])
    submit = SubmitField("Сохранить")


class GradeForm(FlaskForm):
    subject = StringField("Дисциплина", validators=[DataRequired(), Length(max=160)])
    value = IntegerField("Оценка", validators=[DataRequired(), NumberRange(min=2, max=5)])
    weight = IntegerField("Вес", validators=[Optional(), NumberRange(min=1, max=10)])
    control = StringField("За что", validators=[Optional(), Length(max=120)])
    graded_on = DateField("Дата", validators=[Optional()])
    submit = SubmitField("Добавить оценку")


# --- Отправка кода подтверждения ---
def send_verification_email(user, code):
    """Отправляет одноразовый код. SMTP-параметры задаются только через окружение."""
    host = os.environ.get("SMTP_HOST")
    username = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("SMTP_FROM") or username
    port = int(os.environ.get("SMTP_PORT", "587"))
    use_tls = os.environ.get("SMTP_USE_TLS", "1").strip().lower() in {"1", "true", "yes", "on"}

    if not host or not sender:
        raise RuntimeError("SMTP_HOST и SMTP_FROM (или SMTP_USER) должны быть настроены")

    message = EmailMessage()
    message["Subject"] = "Код подтверждения электронной почты"
    message["From"] = sender
    message["To"] = user.email
    message.set_content(
        f"Ваш код подтверждения: {code}\n"
        "Код действует 10 минут. Если вы не регистрировались, проигнорируйте это письмо."
    )

    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as server:
            if username:
                server.login(username, password or "")
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            if use_tls:
                server.starttls(context=context)
                server.ehlo()
            if username:
                server.login(username, password or "")
            server.send_message(message)


def create_and_send_verification_code(user):
    code = f"{secrets.randbelow(1_000_000):06d}"
    user.email_verification_code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    user.email_verification_expires_at = datetime.utcnow() + timedelta(minutes=10)
    user.email_verification_last_sent_at = datetime.utcnow()
    db.session.commit()
    send_verification_email(user, code)


# --- Вспомогательные функции расписания ---
def week_parity_on(day: date, first_parity: str) -> str:
    """Чётность недели для конкретной даты относительно начала семестра.

    Точкой отсчёта служит понедельник текущей ISO-недели даты создания аккаунта
    (условное начало семестра), затем считается число недель между датами.
    """
    return "even" if _week_index(day, first_parity) % 2 == 0 else "odd"


SEMESTER_START = date(2026, 9, 1)


def _week_index(day: date, first_parity: str = "even") -> int:
    delta_days = (day - SEMESTER_START).days
    idx = delta_days // 7
    if first_parity == "odd":
        idx += 1
    return max(idx, 0)


def parity_label_for(day: date, first_parity: str) -> str:
    return "чётная" if week_parity_on(day, first_parity) == "even" else "нечётная"


# --- Маршруты ---
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
# Не более 4 попыток регистрации в минуту с одного IP.
@limiter.limit("4 per minute", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        existing = User.query.filter_by(email=email).first()
        if existing:
            if not existing.email_verified:
                flash("Этот адрес уже зарегистрирован, но не подтверждён. Запросите новый код.", "warning")
                return redirect(url_for("resend_verification", email=email))
            flash("Пользователь с таким email уже существует.", "danger")
        else:
            user = User(email=email)
            user.set_password(form.password.data)
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash("Пользователь с таким email уже существует.", "danger")
            else:
                try:
                    create_and_send_verification_code(user)
                except Exception:
                    app.logger.exception("Не удалось отправить код подтверждения")
                    flash("Аккаунт создан, но письмо отправить не удалось. Попробуйте запросить код повторно.", "warning")
                    return redirect(url_for("resend_verification", email=email))
                flash("Код подтверждения отправлен на вашу почту.", "success")
                return redirect(url_for("verify_email", email=email))
    return render_template("register.html", form=form)


@app.route("/verify-email", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def verify_email():
    email = request.args.get("email", "").strip().lower()
    user = User.query.filter_by(email=email).first() if email else None
    if not user:
        flash("Аккаунт не найден. Зарегистрируйтесь ещё раз.", "danger")
        return redirect(url_for("register"))
    if user.email_verified:
        flash("Электронная почта уже подтверждена. Теперь можно войти.", "info")
        return redirect(url_for("login"))

    form = VerifyEmailForm()
    if form.validate_on_submit():
        code = form.code.data.strip()
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        if (not user.email_verification_code_hash
                or not user.email_verification_expires_at
                or datetime.utcnow() > user.email_verification_expires_at
                or not hmac.compare_digest(code_hash, user.email_verification_code_hash)):
            flash("Неверный или просроченный код. Запросите новый код.", "danger")
        else:
            user.email_verified = True
            user.email_verification_code_hash = None
            user.email_verification_expires_at = None
            db.session.commit()
            flash("Почта подтверждена. Теперь можно войти.", "success")
            return redirect(url_for("login"))
    return render_template("verify_email.html", form=form, email=user.email)


@app.route("/resend-verification", methods=["GET", "POST"])
@limiter.limit("1 per minute", methods=["POST"])
@limiter.limit("5 per hour", methods=["POST"])
def resend_verification():
    form = ResendVerificationForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        if user and not user.email_verified:
            try:
                create_and_send_verification_code(user)
            except Exception:
                app.logger.exception("Не удалось повторно отправить код подтверждения")
        flash("Если аккаунт с этим адресом существует и ожидает подтверждения, код будет отправлен.", "info")
        return redirect(url_for("verify_email", email=email))
    return render_template("resend_verification.html", form=form)


@app.route("/login", methods=["GET", "POST"])
# Не более 4 попыток входа в минуту с одного IP.
# Считаем только отправки формы (POST), чтобы обновление страницы не вело к ошибке 429.
@limiter.limit("4 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            if not user.email_verified:
                flash("Сначала подтвердите электронную почту. При необходимости запросите новый код.", "warning")
                return redirect(url_for("verify_email", email=user.email))
            login_user(user)
            flash("Вы вошли в аккаунт.", "success")
            next_page = request.args.get("next")
            return redirect(next_page if is_safe_next(next_page) else url_for("profile"))
        flash("Неверный email или пароль.", "danger")
    return render_template("login.html", form=form)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Вы вышли из аккаунта.", "info")
    return redirect(url_for("index"))


# --- Главная страница ---
@app.route("/home")
@login_required
def home():
    today = date.today()
    settings = current_user.settings_or_create()
    parity = week_parity_on(today, settings.first_week_parity)

    events = (Event.query.filter_by(user_id=current_user.id)
              .order_by(Event.event_date.asc(), Event.start_time.asc()).all())
    upcoming = [e for e in events if e.event_date >= today and e.status != "cancelled"][:5]
    recent = [e for e in events if e.event_date < today][-4:][::-1]

    lessons_today = (Lesson.query.filter_by(user_id=current_user.id, weekday=today.weekday())
                     .order_by(Lesson.start_time.asc()).all())
    lessons_today = [l for l in lessons_today if l.parity in ("all", parity)]

    grades = Grade.query.filter_by(user_id=current_user.id).all()
    average = round(sum(g.value for g in grades) / len(grades), 2) if grades else None
    done_events = len([e for e in events if e.status == "done"])

    return render_template(
        "home.html",
        events=upcoming,
        past_events=recent,
        lessons_today=lessons_today,
        parity=parity,
        parity_text="чётная" if parity == "even" else "нечётная",
        today=today,
        average=average,
        grades_count=len(grades),
        events_count=len(events),
        done_events=done_events,
        profile=current_user.profile,
    )


# --- Мероприятия: CRUD ---
@app.route("/events")
@login_required
def events():
    kind = request.args.get("kind") or ""
    query = Event.query.filter_by(user_id=current_user.id)
    if kind in EVENT_KINDS:
        query = query.filter_by(kind=kind)
    items = query.order_by(Event.event_date.desc(), Event.start_time.desc()).all()
    return render_template("events.html", events=items, kinds=EVENT_KINDS,
                           statuses=EVENT_STATUSES, active_kind=kind, today=date.today())


@app.route("/events/new", methods=["GET", "POST"])
@login_required
def event_create():
    form = EventForm()
    if request.method == "GET":
        form.event_date.data = date.today()
    if form.validate_on_submit():
        item = Event(
            user_id=current_user.id,
            title=form.title.data.strip(),
            kind=form.kind.data,
            description=(form.description.data or "").strip() or None,
            location=(form.location.data or "").strip() or None,
            event_date=form.event_date.data,
            start_time=form.start_time.data,
            end_time=form.end_time.data,
            status=form.status.data,
        )
        db.session.add(item)
        db.session.commit()
        flash("Мероприятие добавлено.", "success")
        return redirect(url_for("events"))
    return render_template("event_form.html", form=form, title="Новое мероприятие", mode="create")


@app.route("/events/<int:event_id>/edit", methods=["GET", "POST"])
@login_required
def event_edit(event_id):
    item = Event.query.filter_by(id=event_id, user_id=current_user.id).first_or_404()
    form = EventForm(obj=item)
    if form.validate_on_submit():
        item.title = form.title.data.strip()
        item.kind = form.kind.data
        item.description = (form.description.data or "").strip() or None
        item.location = (form.location.data or "").strip() or None
        item.event_date = form.event_date.data
        item.start_time = form.start_time.data
        item.end_time = form.end_time.data
        item.status = form.status.data
        db.session.commit()
        flash("Мероприятие обновлено.", "success")
        return redirect(url_for("events"))
    return render_template("event_form.html", form=form, title="Изменить мероприятие",
                           mode="edit", item=item)


@app.route("/events/<int:event_id>/delete", methods=["POST"])
@login_required
def event_delete(event_id):
    item = Event.query.filter_by(id=event_id, user_id=current_user.id).first_or_404()
    db.session.delete(item)
    db.session.commit()
    flash("Мероприятие удалено.", "info")
    return redirect(url_for("events"))


# --- Профиль ---
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    profile_obj = current_user.profile_or_create()
    form = ProfileForm(obj=profile_obj)
    if form.validate_on_submit():
        profile_obj.full_name = (form.full_name.data or "").strip() or None
        profile_obj.group_name = (form.group_name.data or "").strip() or None
        profile_obj.faculty = (form.faculty.data or "").strip() or None
        profile_obj.course = form.course.data
        profile_obj.student_id = (form.student_id.data or "").strip() or None
        profile_obj.bio = (form.bio.data or "").strip() or None
        db.session.commit()
        flash("Данные профиля сохранены.", "success")
        return redirect(url_for("profile"))

    grades = Grade.query.filter_by(user_id=current_user.id).order_by(Grade.graded_on.desc()).all()
    average = round(sum(g.value for g in grades) / len(grades), 2) if grades else None
    events_count = Event.query.filter_by(user_id=current_user.id).count()
    lessons_count = Lesson.query.filter_by(user_id=current_user.id).count()
    return render_template("profile.html", form=form, profile=profile_obj, user=current_user,
                           grades=grades[:5], average=average,
                           events_count=events_count, lessons_count=lessons_count)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    settings_obj = current_user.settings_or_create()
    settings_form = SettingsForm(obj=settings_obj)
    email_form = EmailForm()
    password_form = PasswordForm()
    moodle_form = MoodleForm(obj=current_user.profile_or_create())

    action = request.form.get("action", "general")

    if action == "general" and settings_form.validate_on_submit():
        settings_obj.theme = settings_form.theme.data
        settings_obj.first_week_parity = settings_form.first_week_parity.data
        settings_obj.show_odd_weeks = bool(settings_form.show_odd_weeks.data)
        settings_obj.notify_events = bool(settings_form.notify_events.data)
        settings_obj.notify_grades = bool(settings_form.notify_grades.data)
        settings_obj.compact_schedule = bool(settings_form.compact_schedule.data)
        db.session.commit()
        flash("Настройки сохранены.", "success")
        return redirect(url_for("settings"))

    if action == "email" and email_form.validate_on_submit():
        if not current_user.check_password(email_form.password.data):
            flash("Текущий пароль указан неверно.", "danger")
        else:
            new_email = email_form.email.data.strip().lower()
            if new_email == current_user.email:
                flash("Это уже ваш адрес.", "info")
            elif User.query.filter_by(email=new_email).first():
                flash("Этот адрес уже занят другим аккаунтом.", "danger")
            else:
                current_user.email = new_email
                current_user.email_verified = False
                try:
                    db.session.commit()
                    create_and_send_verification_code(current_user)
                    flash("Адрес изменён. Подтвердите новый email кодом из письма.", "success")
                    return redirect(url_for("verify_email", email=new_email))
                except Exception:
                    db.session.commit()
                    app.logger.exception("Не удалось отправить код на новый адрес")
                    flash("Адрес изменён, но письмо отправить не удалось. Запросите код повторно.", "warning")
                    return redirect(url_for("resend_verification"))
        return redirect(url_for("settings") + "#security")

    if action == "password" and password_form.validate_on_submit():
        if not current_user.check_password(password_form.current.data):
            flash("Текущий пароль указан неверно.", "danger")
        else:
            current_user.set_password(password_form.password.data)
            db.session.commit()
            flash("Пароль изменён.", "success")
        return redirect(url_for("settings") + "#security")

    if action == "moodle" and moodle_form.validate_on_submit():
        profile_obj = current_user.profile_or_create()
        profile_obj.moodle_url = (moodle_form.moodle_url.data or "").strip() or None
        profile_obj.moodle_token = (moodle_form.moodle_token.data or "").strip() or None
        db.session.commit()
        flash("Связка с Moodle сохранена.", "success")
        return redirect(url_for("settings") + "#moodle")

    return render_template("settings.html", settings_form=settings_form, email_form=email_form,
                           password_form=password_form, moodle_form=moodle_form,
                           settings=settings_obj, user=current_user)


# --- Расписание ---
@app.route("/schedule")
@login_required
def schedule():
    settings_obj = current_user.settings_or_create()
    today = date.today()
    parity = week_parity_on(today, settings_obj.first_week_parity)

    lessons = (Lesson.query.filter_by(user_id=current_user.id)
               .order_by(Lesson.start_time.asc()).all())
    visible = [l for l in lessons if l.parity in ("all", parity)]

    by_day = {}
    for lesson in visible:
        by_day.setdefault(lesson.weekday, []).append(lesson)
    for day_lessons in by_day.values():
        day_lessons.sort(key=lambda x: x.start_time)

    day_dates = {}
    for offset in range(7):
        d = today + timedelta(days=offset)
        day_dates[offset] = d

    events = (Event.query.filter_by(user_id=current_user.id)
              .filter(Event.event_date >= today)
              .filter(Event.event_date < today + timedelta(days=7))
              .order_by(Event.event_date.asc(), Event.start_time.asc()).all())
    events_by_date = {}
    for event in events:
        events_by_date.setdefault(event.event_date, []).append(event)

    return render_template("schedule.html", by_day=by_day, day_dates=day_dates,
                           parity=parity, parity_text="чётная" if parity == "even" else "нечётная",
                           today=today, events_by_date=events_by_date,
                           weekdays=WEEKDAYS, kinds=LESSON_KINDS,
                           parity_labels=PARITY_LABELS, settings=settings_obj)


@app.route("/schedule/lesson/new", methods=["GET", "POST"])
@login_required
def lesson_create():
    form = LessonForm()
    if request.method == "GET":
        form.weekday.data = str(date.today().weekday())
    if form.validate_on_submit():
        lesson = Lesson(
            user_id=current_user.id,
            subject=form.subject.data.strip(),
            teacher=(form.teacher.data or "").strip() or None,
            room=(form.room.data or "").strip() or None,
            weekday=int(form.weekday.data),
            start_time=form.start_time.data,
            end_time=form.end_time.data,
            parity=form.parity.data,
            kind=form.kind.data,
        )
        db.session.add(lesson)
        db.session.commit()
        flash("Занятие добавлено в расписание.", "success")
        return redirect(url_for("schedule"))
    return render_template("lesson_form.html", form=form, title="Новое занятие", mode="create")


@app.route("/schedule/lesson/<int:lesson_id>/edit", methods=["GET", "POST"])
@login_required
def lesson_edit(lesson_id):
    lesson = Lesson.query.filter_by(id=lesson_id, user_id=current_user.id).first_or_404()
    form = LessonForm(obj=lesson)
    if request.method == "GET":
        form.weekday.data = str(lesson.weekday)
    if form.validate_on_submit():
        lesson.subject = form.subject.data.strip()
        lesson.teacher = (form.teacher.data or "").strip() or None
        lesson.room = (form.room.data or "").strip() or None
        lesson.weekday = int(form.weekday.data)
        lesson.start_time = form.start_time.data
        lesson.end_time = form.end_time.data
        lesson.parity = form.parity.data
        lesson.kind = form.kind.data
        db.session.commit()
        flash("Занятие обновлено.", "success")
        return redirect(url_for("schedule"))
    return render_template("lesson_form.html", form=form, title="Изменить занятие",
                           mode="edit", lesson=lesson)


@app.route("/schedule/lesson/<int:lesson_id>/delete", methods=["POST"])
@login_required
def lesson_delete(lesson_id):
    lesson = Lesson.query.filter_by(id=lesson_id, user_id=current_user.id).first_or_404()
    db.session.delete(lesson)
    db.session.commit()
    flash("Занятие удалено.", "info")
    return redirect(url_for("schedule"))


@app.route("/schedule/lesson/<int:lesson_id>/note", methods=["POST"])
@login_required
def lesson_note(lesson_id):
    lesson = Lesson.query.filter_by(id=lesson_id, user_id=current_user.id).first_or_404()
    text = (request.form.get("note") or "").strip()
    lesson.note = text or None
    lesson.note_updated_at = datetime.utcnow() if text else None
    db.session.commit()
    flash("Заметка сохранена." if text else "Заметка удалена.", "success")
    return redirect(url_for("schedule"))


# --- Календарь ---
@app.route("/calendar")
@login_required
def calendar_view():
    today = date.today()
    year = request.args.get("year", type=int) or today.year
    month = request.args.get("month", type=int) or today.month
    if month < 1:
        month, year = 12, year - 1
    if month > 12:
        month, year = 1, year + 1

    settings_obj = current_user.settings_or_create()
    first_day = date(year, month, 1)
    days_in_month = pycalendar.monthrange(year, month)[1]
    last_day = date(year, month, days_in_month)

    events = (Event.query.filter_by(user_id=current_user.id)
              .filter(Event.event_date >= first_day)
              .filter(Event.event_date <= last_day)
              .order_by(Event.start_time.asc()).all())
    events_by_date = {}
    for event in events:
        events_by_date.setdefault(event.event_date, []).append(event)

    lessons = Lesson.query.filter_by(user_id=current_user.id).all()
    week = []
    start_offset = first_day.weekday()
    cursor = first_day - timedelta(days=start_offset)
    while cursor <= last_day or len(week) % 7 != 0 or cursor.weekday() != 0:
        week.append(cursor)
        cursor += timedelta(days=1)
        if len(week) > 42:
            break
    cells = []
    for day in week:
        parity = week_parity_on(day, settings_obj.first_week_parity)
        day_lessons = [l for l in lessons if l.weekday == day.weekday() and l.parity in ("all", parity)]
        cells.append({
            "date": day,
            "in_month": day.month == month,
            "is_today": day == today,
            "events": events_by_date.get(day, []),
            "lessons": len(day_lessons),
        })

    prev_month = first_day - timedelta(days=1)
    next_month = last_day + timedelta(days=1)
    month_names = ["Январь", "Февраль", "Март", "Апрель", "Май", "Июнь",
                   "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"]

    return render_template("calendar.html", cells=cells, month=month, year=year,
                           month_title=f"{month_names[month - 1]} {year}",
                           prev_link={"year": prev_month.year, "month": prev_month.month},
                           next_link={"year": next_month.year, "month": next_month.month},
                           today=today, weekdays_short=["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"])


# --- Успеваемость ---
@app.route("/grades", methods=["GET", "POST"])
@login_required
def grades():
    form = GradeForm()
    if request.method == "GET":
        form.graded_on.data = date.today()
    if form.validate_on_submit():
        grade = Grade(
            user_id=current_user.id,
            subject=form.subject.data.strip(),
            value=form.value.data,
            weight=form.weight.data or 1,
            control=(form.control.data or "").strip() or None,
            graded_on=form.graded_on.data or date.today(),
        )
        db.session.add(grade)
        db.session.commit()
        flash("Оценка добавлена.", "success")
        return redirect(url_for("grades"))

    rows = Grade.query.filter_by(user_id=current_user.id).order_by(Grade.graded_on.desc()).all()

    weighted_sum = sum(g.value * g.weight for g in rows)
    weight_total = sum(g.weight for g in rows)
    average = round(weighted_sum / weight_total, 2) if weight_total else None

    by_subject = {}
    for grade in rows:
        item = by_subject.setdefault(grade.subject, {"sum": 0, "weight": 0, "count": 0, "values": []})
        item["sum"] += grade.value * grade.weight
        item["weight"] += grade.weight
        item["count"] += 1
        item["values"].append(grade.value)

    subjects = []
    for name, item in sorted(by_subject.items()):
        avg = round(item["sum"] / item["weight"], 2) if item["weight"] else None
        subjects.append({"name": name, "average": avg, "count": item["count"],
                         "values": item["values"],
                         "percent": int(round((avg or 0) / 5 * 100))})

    distribution = {mark: len([g for g in rows if g.value == mark]) for mark in (5, 4, 3, 2)}
    risk = [s for s in subjects if s["average"] is not None and s["average"] < 3.5]

    return render_template("grades.html", form=form, rows=rows, average=average,
                           subjects=subjects, distribution=distribution,
                           total=len(rows), risk=risk)


@app.route("/grades/<int:grade_id>/delete", methods=["POST"])
@login_required
def grade_delete(grade_id):
    grade = Grade.query.filter_by(id=grade_id, user_id=current_user.id).first_or_404()
    db.session.delete(grade)
    db.session.commit()
    flash("Оценка удалена.", "info")
    return redirect(url_for("grades"))


# --- Объединение с Moodle ---
@app.route("/moodle")
@login_required
def moodle():
    profile_obj = current_user.profile_or_create()
    connected = bool(profile_obj.moodle_url and profile_obj.moodle_token)
    lessons = Lesson.query.filter_by(user_id=current_user.id).all()
    return render_template("moodle.html", profile=profile_obj, connected=connected,
                           lessons=lessons, kinds=LESSON_KINDS)


@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("429.html"), 429


@app.errorhandler(404)
def not_found_handler(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    # Debugger is off by default. Enable only for local development with FLASK_DEBUG=1.
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
