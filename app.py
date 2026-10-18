
# Librerías utilizadas
import os
import bcrypt
import pymysql
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from pymysql.cursors import DictCursor


# Carga las variables de entorno del archivo .env
load_dotenv()

# Configuración inicial de Flask
app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

# Configuración de seguridad para las sesiones
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Se usa True cuando se trabaja con HTTPS
)

# Configuración del inicio de sesión con Google
oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


# Conexión a la base de datos MySQL
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


# Obtiene los datos del usuario que tiene una sesión activa
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


# Muestra la página principal
@app.get("/")
def index():
    return render_template("index.html", user=current_user())


# Registro de nuevos usuarios
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    # Se obtienen los datos ingresados en el formulario
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    # Se verifica que los campos estén completos
    if not username or not email or not password:
        flash("Completa todos los campos.", "error")
        return redirect(url_for("register"))

    if len(password) < 8:
        flash("La contraseña debe tener al menos 8 caracteres.", "error")
        return redirect(url_for("register"))

    # Se utiliza bcrypt para proteger la contraseña antes de guardarla
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    connection = get_db()

    try:
        # Se guarda el usuario con su contraseña protegida
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

    # Se controla cuando el usuario o correo ya existen
    except pymysql.err.IntegrityError:
        connection.rollback()
        flash("El usuario o correo ya está registrado.", "error")
        return redirect(url_for("register"))

    finally:
        connection.close()


# Inicio de sesión con correo y contraseña
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    connection = get_db()

    try:
        # Se busca el correo ingresado en la base de datos
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

    # Se comprueba que el usuario exista y tenga una contraseña registrada
    if not user or not user["password_hash"]:
        flash("Correo o contraseña incorrectos.", "error")
        return redirect(url_for("login"))

    # bcrypt compara la contraseña ingresada con la que está protegida
    valid = bcrypt.checkpw(
        password.encode("utf-8"),
        user["password_hash"].encode("utf-8"),
    )

    if not valid:
        flash("Correo o contraseña incorrectos.", "error")
        return redirect(url_for("login"))

    # Se guarda la sesión del usuario después de iniciar correctamente
    session.clear()
    session["user_id"] = user["id"]

    flash("Inicio de sesión correcto.", "success")
    return redirect(url_for("index"))


# Redirige al usuario a Google para iniciar sesión
@app.get("/login/google")
def login_google():
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


# Recibe la respuesta de Google después de iniciar sesión
@app.get("/auth/google/callback")
def google_callback():
    token = google.authorize_access_token()
    info = token.get("userinfo")

    if not info:
        flash("Google no devolvió información del usuario.", "error")
        return redirect(url_for("login"))

    # Se obtienen los datos de la cuenta de Google
    google_sub = info.get("sub")
    email = (info.get("email") or "").strip().lower()
    email_verified = bool(info.get("email_verified"))
    name = (info.get("name") or email.split("@")[0]).strip()

    # Se comprueba que Google haya verificado el correo
    if not google_sub or not email or not email_verified:
        flash("No se pudo verificar el correo de Google.", "error")
        return redirect(url_for("login"))

    connection = get_db()

    try:
        with connection.cursor() as cursor:
            # Se busca si la cuenta de Google ya está registrada
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
                # Si no existe, se revisa si el correo ya está registrado
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
                    # Se evita vincular un correo con otra cuenta de Google
                    if user["google_sub"] and user["google_sub"] != google_sub:
                        flash(
                            "Este correo ya está vinculado a otra cuenta de Google.",
                            "error",
                        )
                        return redirect(url_for("login"))

                    # Se vincula la cuenta existente con Google
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
                    # Si el usuario es nuevo, se crea su cuenta con los datos de Google
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

        # Se inicia la sesión del usuario que ingresó con Google
        session.clear()
        session["user_id"] = user["id"]

        flash("Inicio de sesión con Google correcto.", "success")
        return redirect(url_for("index"))

    # Se controlan los errores que pueden ocurrir con la base de datos
    except pymysql.MySQLError:
        connection.rollback()
        app.logger.exception("Error de base de datos durante OAuth")
        flash("No se pudo completar el inicio de sesión.", "error")
        return redirect(url_for("login"))

    finally:
        connection.close()


# Cierra la sesión del usuario
@app.post("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "success")
    return redirect(url_for("index"))


# Ejecuta la aplicación Flask de manera local
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
