from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from datetime import datetime, timedelta
import hashlib
import hmac
import secrets
import smtplib
import ssl
from email.message import EmailMessage
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
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' data: https://cdn.jsdelivr.net"
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
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
    storage_uri="memory://",  # Хранилище в памяти (подходит для разработки)
)


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
        f"Ваш код подтверждения: {code}\\n"
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


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Вы вышли из аккаунта.", "info")
    return redirect(url_for("index"))


@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("429.html"), 429


if __name__ == "__main__":
    # Debugger is off by default. Enable only for local development with FLASK_DEBUG=1.
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
