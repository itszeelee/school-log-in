"""Lauwak is a small local login app built with Flask and SQLite.

It covers sign-up, login, password reset, and a protected home page for a
simple local demo.
"""

import os
import re
import secrets
import sqlite3
from functools import wraps

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

# Site settings
APP_NAME = "Lauwak"  # Used in the logo and page headings.
APP_TAGLINE = "Your study sidekick & flashcard generator"  # A short tagline under the brand name.
HOST = "127.0.0.1"  # Keep the app local to this computer.
PORT = 5000         # Change this if port 5000 is already in use.

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "database.db")  # SQLite database file.

# These rules stay in sync with the browser-side validation.
MAX_NAME_LENGTH = 60
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 30
USERNAME_CHARACTERS = re.compile(r"[a-z0-9_]+")
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128

# PBKDF2-SHA256 is a strong standard for hashing passwords.
# Werkzeug adds a fresh salt automatically for each hash.
PASSWORD_HASH_METHOD = "pbkdf2:sha256"

app = Flask(__name__)
app.config.update(
    # This is fine for local testing, but a real app should use a custom secret key.
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-key-change-me"),
    SESSION_COOKIE_HTTPONLY=True,   # Keeps the session cookie out of JavaScript.
    SESSION_COOKIE_SAMESITE="Lax",  # Helps reduce cross-site request risk.
    SESSION_COOKIE_SECURE=False,    # HTTPS would require this to be true.
)


# Database helpers
def get_db():
    """Open the SQLite connection once per request and return it."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row  # lets us write user["name"]
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    """Close the connection when the request is finished."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create database.db and the users table if they do not exist yet."""
    db = sqlite3.connect(DATABASE_PATH)
    try:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL,
                username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL
            )
            """
        )
        db.commit()
    finally:
        db.close()


def get_user_by_username(username):
    return get_db().execute(
        "SELECT id, name, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def get_user_by_id(user_id):
    return get_db().execute(
        "SELECT id, name, username FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def create_user(name, username, password):
    """Save a new account. Only the password hash is stored, never the password itself."""
    db = get_db()
    db.execute(
        "INSERT INTO users (name, username, password_hash) VALUES (?, ?, ?)",
        (name, username, generate_password_hash(password, method=PASSWORD_HASH_METHOD)),
    )
    db.commit()


def update_password(user_id, new_password):
    """Replace an account's stored password hash with a hash of the new password."""
    db = get_db()
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password, method=PASSWORD_HASH_METHOD), user_id),
    )
    db.commit()


# Input validation helpers
def normalize_username(raw_username):
    """Trim spaces and lower-case so 'Alice ' and 'alice' count as the same username.
    Registration, login, and reset all use this same check."""
    return (raw_username or "").strip().lower()


def clean_name(raw_name):
    """Trim the name and collapse repeated spaces: '  Ana   Cruz ' -> 'Ana Cruz'."""
    return " ".join((raw_name or "").split())


def check_name(name):
    """Return an error message, or None if the name is valid."""
    if not name:
        return "Enter your name."
    if len(name) > MAX_NAME_LENGTH:
        return f"Name must be {MAX_NAME_LENGTH} characters or fewer."
    return None


def check_new_username(username):
    """Return an error message, or None if the username is valid."""
    if not username:
        return "Choose a username."
    if not USERNAME_MIN_LENGTH <= len(username) <= USERNAME_MAX_LENGTH:
        return (
            f"Username must be {USERNAME_MIN_LENGTH}\u2013{USERNAME_MAX_LENGTH} "
            "characters long."
        )
    if not USERNAME_CHARACTERS.fullmatch(username):
        return "Username can only contain letters, numbers, and underscores."
    return None


def check_new_password(password, confirm_password):
    """Used for both registration and password reset. Returns {field_name: message}."""
    errors = {}
    if not password:
        errors["password"] = "Enter a password."
    elif len(password) < PASSWORD_MIN_LENGTH:
        errors["password"] = f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    elif len(password) > PASSWORD_MAX_LENGTH:
        errors["password"] = f"Password must be {PASSWORD_MAX_LENGTH} characters or fewer."

    if not confirm_password:
        errors["confirm_password"] = "Confirm your password."
    elif password != confirm_password:
        errors["confirm_password"] = "Passwords do not match."
    return errors


# Security helpers
def current_user():
    """Return the logged-in user (id, name, username), or None."""
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_user_by_id(user_id)


def login_required(view):
    """Use @login_required on routes that should only be visible to signed-in users."""

    @wraps(view)
    def protected_view(*args, **kwargs):
        user = current_user()
        if user is None:
            session.pop("user_id", None)  # clear any stale login state
            flash("Log in to continue.", "info")
            return redirect(url_for("login"))
        g.user = user
        return view(*args, **kwargs)

    return protected_view


def get_csrf_token():
    """Create a one-off form token for each visitor the first time it is needed."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.before_request
def check_csrf_token():
    """Reject form submissions that do not include the expected token."""
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(sent.encode(), expected.encode()):
            flash("That form expired. Reload the page and try again.", "error")
            return redirect(url_for("login"))


@app.after_request
def add_response_headers(response):
    """Add a few basic safety headers to every response."""
    if request.endpoint != "static":
        # This stops stale pages from lingering after logout.
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; form-action 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@app.context_processor
def inject_template_values():
    """Expose shared values to templates."""
    return {
        "app_name": APP_NAME,
        "app_tagline": APP_TAGLINE,
        "csrf_token": get_csrf_token,  # used as {{ csrf_token() }}
        "limits": {
            "name_max": MAX_NAME_LENGTH,
            "username_min": USERNAME_MIN_LENGTH,
            "username_max": USERNAME_MAX_LENGTH,
            "password_min": PASSWORD_MIN_LENGTH,
            "password_max": PASSWORD_MAX_LENGTH,
        },
    }


# ---------------------------------------------------------------------------
# 5. PAGES (ROUTES)
# ---------------------------------------------------------------------------
@app.route("/")
def start():
    """Send visitors straight to the page they can access."""
    return redirect(url_for("home" if current_user() else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Create a new account or show validation errors."""
    if current_user():
        return redirect(url_for("home"))

    form = {"name": "", "username": ""}
    errors = {}

    if request.method == "POST":
        name = clean_name(request.form.get("name"))
        username = normalize_username(request.form.get("username"))
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        form = {"name": name, "username": username}  # keep the values visible if validation fails

        name_error = check_name(name)
        if name_error:
            errors["name"] = name_error

        username_error = check_new_username(username)
        if username_error:
            errors["username"] = username_error

        errors.update(check_new_password(password, confirm_password))

        # Usernames must be unique, but names do not need to be.
        if "username" not in errors and get_user_by_username(username):
            errors["username"] = "That username is already taken. Choose a different one."

        if not errors:
            try:
                create_user(name, username, password)
            except sqlite3.IntegrityError:
                # Another request may have created the same username in the meantime.
                errors["username"] = "That username is already taken. Choose a different one."
            else:
                flash("Account created. Log in with your username and password.", "success")
                return redirect(url_for("login", username=username))

    return render_template("register.html", form=form, errors=errors)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Handle sign-in and keep the session in sync."""
    if current_user():
        return redirect(url_for("home"))

    # The username box is normally empty. After registration or a reset, we send
    # ?username=... so the user only needs to type the password.
    form = {"username": normalize_username(request.args.get("username"))[:USERNAME_MAX_LENGTH]}
    errors = {}

    if request.method == "POST":
        username = normalize_username(request.form.get("username"))
        password = request.form.get("password", "")
        form["username"] = username[:USERNAME_MAX_LENGTH]

        if not username:
            errors["username"] = "Enter your username."
        if not password:
            errors["password"] = "Enter your password."

        if not errors:
            user = get_user_by_username(username)
            if user is not None and check_password_hash(user["password_hash"], password):
                session.clear()  # start with a clean session and drop any stale data
                session["user_id"] = user["id"]
                return redirect(url_for("home"))
            # We use one message for both missing and wrong credentials to avoid
            # revealing which usernames are already in the system.
            flash("That username and password don't match. Check them and try again.", "error")

    return render_template("login.html", form=form, errors=errors)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Ask for a username before starting a password reset."""
    if current_user():
        return redirect(url_for("home"))

    form = {"username": ""}
    errors = {}

    if request.method == "GET":
        session.pop("reset_username", None)  # always start the flow from the beginning
    else:
        username = normalize_username(request.form.get("username"))
        form["username"] = username[:USERNAME_MAX_LENGTH]
        if not username:
            errors["username"] = "Enter your username."
        elif get_user_by_username(username) is None:
            errors["username"] = (
                "No account has that username. Check the spelling, or create a new account."
            )
        else:
            session["reset_username"] = username  # store it for the next step
            return redirect(url_for("reset_password"))

    return render_template("forgot_password.html", form=form, errors=errors)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Let the user set a new password for a known local account."""
    if current_user():
        return redirect(url_for("home"))

    username = session.get("reset_username")
    user = get_user_by_username(username) if username else None
    if user is None:
        session.pop("reset_username", None)
        flash("Enter your username first.", "info")
        return redirect(url_for("forgot_password"))

    errors = {}
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        errors = check_new_password(password, confirm_password)

        if not errors:
            update_password(user["id"], password)
            session.pop("reset_username", None)
            flash("Password changed. Log in with your new password.", "success")
            return redirect(url_for("login", username=user["username"]))

    return render_template("reset_password.html", username=user["username"], errors=errors)


@app.route("/home")
@login_required
def home():
    """Protected home page for logged-in users."""
    return render_template("home.html", user=g.user)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """Clear the session and send the user back to the login page."""
    if request.method == "POST":
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))
    # Typing /logout into the browser address bar should not log anyone out.
    return redirect(url_for("home"))


# Start-up
# Create the SQLite database and user table if this is the first run.
init_db()

if __name__ == "__main__":
    # Debug mode is useful while building locally, but it should not stay on in production.
    app.run(host=HOST, port=PORT, debug=True)