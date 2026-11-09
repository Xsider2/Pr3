from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import IntegrityError
from urllib.parse import urlsplit
import os
from dotenv import load_dotenv

load_dotenv()  # читает .env и кладёт переменные в os.environ

app = Flask(__name__)

# Для тестов можно задать DATABASE_URL (например, sqlite:///test.db),
# тогда MySQL не нужен. Без этой переменной подключение собирается из DB_* как раньше.
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
else:
    DB_USER = os.environ["DB_USER"]
    DB_PASSWORD = os.environ["DB_PASSWORD"]
    DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
    DB_PORT = os.environ.get("DB_PORT", "3306")
    DB_NAME = os.environ["DB_NAME"]

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        "?charset=utf8mb4"
    )
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

# --- Безопасность cookie сессии ---
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"

# Secure cookie работает только по HTTPS.
# В локальной разработке (http://127.0.0.1) флаг нужно отключить,
# иначе браузер не будет отправлять cookie и вход сломается.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
app.config["REMEMBER_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"

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
    storage_uri="memory://",  # Хранилище в памяти (подходит для разработки)
)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


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


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Пароль", validators=[DataRequired()])
    submit = SubmitField("Войти")


# --- Маршруты ---
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
# Не более 4 попыток регистрации в минуту с одного IP.
# Считаем только отправки формы (POST), чтобы обновление страницы не вело к ошибке 429.
@limiter.limit("4 per minute", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("Пользователь с таким email уже существует.", "danger")
        else:
            user = User(email=email)
            user.set_password(form.password.data)
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:
                # Два запроса с одним email могли пройти проверку одновременно:
                # уникальный индекс в базе не даст создать дубликат.
                db.session.rollback()
                flash("Пользователь с таким email уже существует.", "danger")
            else:
                flash("Регистрация успешна. Теперь можно войти.", "success")
                return redirect(url_for("login"))
    return render_template("register.html", form=form)


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
            login_user(user)
            flash("Вы вошли в аккаунт.", "success")
            next_page = request.args.get("next")
            return redirect(next_page if is_safe_next(next_page) else url_for("profile"))
        flash("Неверный email или пароль.", "danger")
    return render_template("login.html", form=form)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Вы вышли из аккаунта.", "info")
    return redirect(url_for("index"))

from flask import render_template

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("429.html"), 429

if __name__ == "__main__":
    app.run(debug=True)