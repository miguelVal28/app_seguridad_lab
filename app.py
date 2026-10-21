"""
app.py  -  Sistema de Gestion Academica para el laboratorio de S-SDLC.

Correcciones aplicadas:
  - Control de autenticacion y roles en rutas sensibles
  - Clave secreta aleatoria (variable de entorno o archivo local)
  - Cierre de sesion por POST y proteccion CSRF
  - Verificacion de contrasenas con hash (Werkzeug)
  - Validacion de extensiones de archivos
"""

import os
import secrets
from functools import wraps

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from database import get_connection, init_db
from flask_session import Session
from rbac import RBAC, load_current_user
from session_manager import login_required

TODOS = ["estudiante", "docente", "admin"]
DOCENTES = ["docente", "admin"]
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg", ".gif"}


def load_secret_key():
    """Usa SECRET_KEY del entorno o crea una clave aleatoria persistida."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret_key")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as archivo:
            stored = archivo.read().strip()
        if stored:
            return stored

    key = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as archivo:
        archivo.write(key)
    return key


app = Flask(__name__)
app.config["RBAC_USE_WHITE"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["ALLOWED_EXTENSIONS"] = ALLOWED_EXTENSIONS
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.secret_key = load_secret_key()

rbac = RBAC(app, user_loader=load_current_user)
Session(app)
csrf = CSRFProtect(app)

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def role_required(*roles):
    """Exige inicio de sesion y un rol adecuado."""

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("username"):
                return redirect(url_for("login"))
            if session.get("rol") not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def redirigir_acceso_denegado():
    if "username" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("acceso_denegado"))


rbac.set_hook(redirigir_acceso_denegado)


@app.route("/acceso-denegado")
@rbac.allow(["anonymous"], methods=["GET"])
def acceso_denegado():
    return render_template("acceso_denegado.html"), 403


@app.route("/")
@rbac.allow(["anonymous"], methods=["GET"])
def inicio():
    return render_template("index.html", usuario=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
@rbac.allow(["anonymous"], methods=["GET", "POST"])
def login():
    """Inicio de sesion con consulta parametrizada y hash."""
    error = None
    if request.method == "POST":
        usuario = request.form.get("username", "").strip()
        clave = request.form.get("password", "")

        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM usuarios WHERE username = ?",
            (usuario,),
        )
        fila = cur.fetchone()
        conn.close()

        if fila and check_password_hash(fila["password"], clave):
            session["username"] = fila["username"]
            session["rol"] = fila["rol"]
            session["estudiante_id"] = fila["estudiante_id"]
            return redirect(url_for("inicio"))
        error = "Credenciales invalidas"

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("inicio"))


@app.route("/buscar")
@rbac.allow(TODOS, methods=["GET"])
@login_required
def buscar():
    termino = request.args.get("q", "")
    resultados = []
    if termino:
        conn = get_connection()
        cur = conn.cursor()
        query = (
            "SELECT id, nombre, carrera, biografia FROM estudiantes "
            "WHERE nombre LIKE ?"
        )
        cur.execute(query, (f"%{termino}%",))
        resultados = cur.fetchall()
        conn.close()
    return render_template("buscar.html", resultados=resultados, termino=termino)


@app.route("/perfil/<int:user_id>")
@rbac.allow(TODOS, methods=["GET"])
@login_required
def perfil(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM estudiantes WHERE id = ?", (user_id,))
    estudiante = cur.fetchone()
    cur.execute("SELECT * FROM calificaciones WHERE estudiante_id = ?", (user_id,))
    notas = cur.fetchall()
    conn.close()
    if not estudiante:
        return "Estudiante no encontrado", 404
    return render_template("perfil.html", estudiante=estudiante, notas=notas)


@app.route("/perfil/<int:id>/editar", methods=["GET", "POST"])
@rbac.allow(TODOS, methods=["GET", "POST"])
@login_required
def editar_biografia(id):
    if session.get("rol") == "estudiante" and session.get("estudiante_id") != id:
        abort(403)

    conn = get_connection()
    cur = conn.cursor()
    if request.method == "POST":
        bio = request.form.get("biografia", "")
        cur.execute(
            "UPDATE estudiantes SET biografia = ? WHERE id = ?", (bio, id)
        )
        conn.commit()
        conn.close()
        return redirect(url_for("perfil", user_id=id))
    cur.execute("SELECT * FROM estudiantes WHERE id = ?", (id,))
    estudiante = cur.fetchone()
    conn.close()
    if not estudiante:
        return "Estudiante no encontrado", 404
    return render_template("editar_biografia.html", estudiante=estudiante)


@app.route("/nota/editar/<int:id>", methods=["GET", "POST"])
@rbac.allow(DOCENTES, methods=["GET", "POST"])
@login_required
def editar_nota(id):
    conn = get_connection()
    cur = conn.cursor()
    if request.method == "POST":
        nueva_nota = request.form.get("nota", "0")
        cur.execute(
            "UPDATE calificaciones SET nota = ? WHERE id = ?", (nueva_nota, id)
        )
        conn.commit()
        conn.close()
        return redirect(url_for("buscar"))
    cur.execute("SELECT * FROM calificaciones WHERE id = ?", (id,))
    calificacion = cur.fetchone()
    conn.close()
    if not calificacion:
        return "Calificacion no encontrada", 404
    return render_template("editar_nota.html", calificacion=calificacion)


@app.route("/subir", methods=["GET", "POST"])
@rbac.allow(TODOS, methods=["GET", "POST"])
@login_required
def subir():
    mensaje = None
    if request.method == "POST":
        archivo = request.files.get("archivo")
        if archivo and archivo.filename:
            nombre_seguro = secure_filename(archivo.filename)
            extension = os.path.splitext(nombre_seguro)[1].lower()
            if extension not in app.config["ALLOWED_EXTENSIONS"]:
                mensaje = "Tipo de archivo no permitido. Solo se aceptan PDF, TXT, PNG, JPG, JPEG y GIF."
            else:
                nombre_guardado = f"{secrets.token_hex(8)}_{nombre_seguro}"
                ruta = os.path.join(app.config["UPLOAD_FOLDER"], nombre_guardado)
                archivo.save(ruta)

                conn = get_connection()
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO archivos (nombre_archivo, ruta, subido_por) VALUES (?, ?, ?)",
                    (nombre_seguro, ruta, session.get("username")),
                )
                conn.commit()
                conn.close()
                mensaje = f"Archivo '{nombre_seguro}' subido correctamente."
    return render_template("subir.html", mensaje=mensaje)


if __name__ == "__main__":
    if not os.path.exists("academia.db"):
        init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
