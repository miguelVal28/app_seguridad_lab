"""
app_segura.py  -  VERSION SEGURA (REMEDIADA)
===========================================
Sistema de Gestion Academica para el laboratorio de S-SDLC.

Estado de las vulnerabilidades del laboratorio:
  1. Inyeccion SQL (SQLi) mitigada   -> /login y /buscar parametrizados
  2. Cross-Site Scripting (XSS)      -> /perfil/<id>
  3. Control de acceso roto (IDOR)   -> /nota/editar/<id>
  4. Carga de archivos sin restriccion -> /subir

USAR SOLO EN UN ENTORNO LOCAL Y AISLADO CON FINES EDUCATIVOS.
"""

import os

from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for
)
from flask_session import Session

from database import get_connection, init_db
from rbac import RBAC, load_current_user
from session_manager import login_required

TODOS = ["estudiante", "docente", "admin"]
DOCENTES = ["docente", "admin"]
app = Flask(__name__, template_folder="templates_segura")

app.config["RBAC_USE_WHITE"] = True  # debe ir antes de RBAC(app)
rbac = RBAC(app, user_loader=load_current_user)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

Session(app)

app.secret_key = "clave-insegura-de-laboratorio"  # MALA PRACTICA: clave debil y fija

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def redirigir_acceso_denegado():
    # Sin sesion -> al login; con sesion pero sin rol suficiente -> pagina 403.
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
    """Pagina de inicio con el banner del laboratorio."""
    return render_template("index.html", usuario=session.get("username"))


# ======================================================================
# SQLi MITIGADA: consulta parametrizada en el login
# ======================================================================
@app.route("/login", methods=["GET", "POST"])
@rbac.allow(["anonymous"], methods=["GET", "POST"])
def login():
    """Inicio de sesion con consulta parametrizada."""
    error = None
    if request.method == "POST":
        usuario = request.form.get("username", "")
        clave = request.form.get("password", "")

        conn = get_connection()
        cur = conn.cursor()

        # Los parametros se interpretan como datos, no como codigo SQL.
        cur.execute(
            "SELECT * FROM usuarios WHERE username = ? AND password = ?",
            (usuario, clave),
        )
        fila = cur.fetchone()
        conn.close()

        if fila:
            session["username"] = fila["username"]
            session["rol"] = fila["rol"]
            session["estudiante_id"] = fila["estudiante_id"]
            return redirect(url_for("inicio"))
        error = "Credenciales invalidas"

    return render_template("login.html", error=error)


@app.route("/logout")
@rbac.allow(["anonymous"], methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("inicio"))


# ======================================================================
# SQLi MITIGADA: consulta parametrizada en el buscador de estudiantes
# ======================================================================
@app.route("/buscar")
@rbac.allow(TODOS, methods=["GET"])
@login_required
def buscar():
    """Buscador de estudiantes con consulta parametrizada."""
    termino = request.args.get("q", "")
    resultados = []
    if termino:
        conn = get_connection()
        cur = conn.cursor()
        # El patron LIKE se pasa como parametro separado de la consulta.
        query = (
            "SELECT id, nombre, carrera, biografia FROM estudiantes "
            "WHERE nombre LIKE ?"
        )
        cur.execute(query, (f"%{termino}%",))
        resultados = cur.fetchall()
        conn.close()
    return render_template(
        "buscar.html", resultados=resultados, termino=termino
    )


# ======================================================================
# VULNERABILIDAD 2: CROSS-SITE SCRIPTING (XSS) ALMACENADO
# ======================================================================
@app.route("/perfil/<int:user_id>")
@rbac.allow(TODOS, methods=["GET"])
@login_required
def perfil(user_id):
    """Muestra el perfil de un estudiante SIN escapar la biografia."""

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM estudiantes WHERE id = ?", (user_id,))
    estudiante = cur.fetchone()
    cur.execute("SELECT * FROM calificaciones WHERE estudiante_id = ?", (user_id,))
    notas = cur.fetchall()
    conn.close()
    if not estudiante:
        return "Estudiante no encontrado", 404
    # La plantilla perfil.html imprime la biografia con "| safe",
    # desactivando el autoescape de Jinja2 -> XSS almacenado.
    return render_template("perfil.html", estudiante=estudiante, notas=notas)


@app.route("/perfil/<int:id>/editar", methods=["GET", "POST"])
@rbac.allow(TODOS, methods=["GET", "POST"])
@login_required
def editar_biografia(id):
    """Permite editar la biografia (fuente del XSS almacenado)."""
    # Un estudiante solo puede editar su propia biografia.
    if session.get("rol") == "estudiante" and session.get("estudiante_id") != id:
        return redirect(url_for("acceso_denegado"))
    conn = get_connection()
    cur = conn.cursor()
    if request.method == "POST":
        bio = request.form.get("biografia", "")
        # Se guarda la biografia tal cual, sin sanear el contenido.
        cur.execute(
            "UPDATE estudiantes SET biografia = ? WHERE id = ?", (bio, id)
        )
        conn.commit()
        conn.close()
        return redirect(url_for("perfil", user_id=id))
    cur.execute("SELECT * FROM estudiantes WHERE id = ?", (id,))
    estudiante = cur.fetchone()
    conn.close()
    return render_template("editar_biografia.html", estudiante=estudiante)


# ======================================================================
# VULNERABILIDAD 3: CONTROL DE ACCESO ROTO (IDOR)
# ======================================================================
@app.route("/nota/editar/<int:id>", methods=["GET", "POST"])
@rbac.allow(DOCENTES, methods=["GET", "POST"])
@login_required
def editar_nota(id):
    """
    Edita una calificacion identificada por su ID en la URL.
    VULNERABLE: no verifica que el usuario haya iniciado sesion, ni su rol,
    ni si la calificacion le pertenece. Cualquiera puede cambiar
    /nota/editar/5 por /nota/editar/6 y modificar la nota de otro.
    """
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


# ======================================================================
# VULNERABILIDAD 4: CARGA DE ARCHIVOS SIN RESTRICCION
# ======================================================================
@app.route("/subir", methods=["GET", "POST"])
@rbac.allow(TODOS, methods=["GET", "POST"])
@login_required
def subir():
    """Sube un archivo SIN validar extension ni tipo -> permite .py, .php, etc."""
    mensaje = None
    if request.method == "POST":
        archivo = request.files.get("archivo")
        if archivo and archivo.filename:
            # VULNERABLE: se acepta cualquier nombre/extension y se guarda
            # el archivo directamente. No hay lista blanca ni validacion.
            ruta = os.path.join(app.config["UPLOAD_FOLDER"], archivo.filename)
            archivo.save(ruta)

            conn = get_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO archivos (nombre_archivo, ruta, subido_por) "
                "VALUES (?, ?, ?)",
                (archivo.filename, ruta, session.get("username")),
            )
            conn.commit()
            conn.close()
            mensaje = f"Archivo '{archivo.filename}' subido a {ruta}"
    return render_template("subir.html", mensaje=mensaje)


if __name__ == "__main__":
    if not os.path.exists("academia.db"):
        init_db()
    # debug=True tambien es una mala practica en produccion (expone la consola)
    app.run(host="127.0.0.1", port=5001)
