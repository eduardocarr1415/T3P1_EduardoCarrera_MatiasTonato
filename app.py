import os

import bcrypt
import pymysql
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from pymysql.cursors import DictCursor

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # True en producción con HTTPS
)

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "oauth_practica"),
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False,
    )


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    connection = get_db()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, email, google_sub
                FROM users
                WHERE id = %s
                """,
                (user_id,),
            )
            return cursor.fetchone()
    finally:
        connection.close()


@app.get("/")
def index():
    return render_template("index.html", user=current_user())


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not username or not email or not password:
        flash("Completa todos los campos.", "error")
        return redirect(url_for("register"))

    if len(password) < 8:
        flash("La contraseña debe tener al menos 8 caracteres.", "error")
        return redirect(url_for("register"))

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    connection = get_db()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (%s, %s, %s)
                """,
                (username, email, password_hash),
            )

        connection.commit()
        flash("Usuario registrado correctamente.", "success")
        return redirect(url_for("login"))

    except pymysql.err.IntegrityError:
        connection.rollback()
        flash("El usuario o correo ya está registrado.", "error")
        return redirect(url_for("register"))

    finally:
        connection.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    connection = get_db()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, email, password_hash
                FROM users
                WHERE email = %s
                """,
                (email,),
            )
            user = cursor.fetchone()

    finally:
        connection.close()

    if not user or not user["password_hash"]:
        flash("Correo o contraseña incorrectos.", "error")
        return redirect(url_for("login"))

    valid = bcrypt.checkpw(
        password.encode("utf-8"),
        user["password_hash"].encode("utf-8"),
    )

    if not valid:
        flash("Correo o contraseña incorrectos.", "error")
        return redirect(url_for("login"))

    session.clear()
    session["user_id"] = user["id"]

    flash("Inicio de sesión correcto.", "success")
    return redirect(url_for("index"))


@app.get("/login/google")
def login_google():
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.get("/auth/google/callback")
def google_callback():
    token = google.authorize_access_token()
    info = token.get("userinfo")

    if not info:
        flash("Google no devolvió información del usuario.", "error")
        return redirect(url_for("login"))

    google_sub = info.get("sub")
    email = (info.get("email") or "").strip().lower()
    email_verified = bool(info.get("email_verified"))
    name = (info.get("name") or email.split("@")[0]).strip()

    if not google_sub or not email or not email_verified:
        flash("No se pudo verificar el correo de Google.", "error")
        return redirect(url_for("login"))

    connection = get_db()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, email, google_sub
                FROM users
                WHERE google_sub = %s
                """,
                (google_sub,),
            )
            user = cursor.fetchone()

            if not user:
                cursor.execute(
                    """
                    SELECT id, username, email, google_sub
                    FROM users
                    WHERE email = %s
                    """,
                    (email,),
                )
                user = cursor.fetchone()

                if user:
                    if user["google_sub"] and user["google_sub"] != google_sub:
                        flash(
                            "Este correo ya está vinculado a otra cuenta de Google.",
                            "error",
                        )
                        return redirect(url_for("login"))

                    cursor.execute(
                        """
                        UPDATE users
                        SET google_sub = %s
                        WHERE id = %s
                        """,
                        (google_sub, user["id"]),
                    )

                    connection.commit()

                else:
                    base_username = name[:60] or "usuario_google"
                    username = f"{base_username}_{google_sub[-6:]}"[:80]

                    cursor.execute(
                        """
                        INSERT INTO users (username, email, google_sub)
                        VALUES (%s, %s, %s)
                        """,
                        (username, email, google_sub),
                    )

                    connection.commit()

                    user = {
                        "id": cursor.lastrowid,
                        "username": username,
                        "email": email,
                        "google_sub": google_sub,
                    }

        session.clear()
        session["user_id"] = user["id"]

        flash("Inicio de sesión con Google correcto.", "success")
        return redirect(url_for("index"))

    except pymysql.MySQLError:
        connection.rollback()
        app.logger.exception("Error de base de datos durante OAuth")
        flash("No se pudo completar el inicio de sesión.", "error")
        return redirect(url_for("login"))

    finally:
        connection.close()


@app.post("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
