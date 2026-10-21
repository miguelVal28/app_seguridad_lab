"""
database.py
-----------
Crea la base de datos SQLite del laboratorio y carga datos de ejemplo.

Las contrasenas se guardan con hash de Werkzeug.
"""

import os
import shutil
import sqlite3

from werkzeug.security import generate_password_hash

DB_NAME = "academia.db"


def get_connection():
    """Devuelve una conexion a la base de datos SQLite."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def _parece_hash(password):
    """Detecta hashes de Werkzeug para no volver a hashear lo ya migrado."""
    if not password:
        return False
    return password.startswith(("pbkdf2:", "scrypt:", "argon2:"))


def backup_database():
    """Copia de seguridad antes de migrar."""
    if not os.path.exists(DB_NAME):
        return
    backup_path = DB_NAME + ".bak"
    if os.path.exists(backup_path):
        return
    shutil.copy2(DB_NAME, backup_path)
    print(f"Copia de seguridad creada en '{backup_path}'.")


def migrate_plaintext_passwords():
    """Convierte contrasenas en texto plano a hash sin recrear tablas."""
    if not os.path.exists(DB_NAME):
        return

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, password FROM usuarios")
    filas = cur.fetchall()
    actualizados = 0
    for fila in filas:
        if _parece_hash(fila["password"]):
            continue
        cur.execute(
            "UPDATE usuarios SET password = ? WHERE id = ?",
            (generate_password_hash(fila["password"]), fila["id"]),
        )
        actualizados += 1
    conn.commit()
    conn.close()
    if actualizados:
        print(f"Migradas {actualizados} contrasenas de texto plano a hash.")


def init_db():
    """Crea las tablas y carga los datos de ejemplo solo si la base no existe."""
    if os.path.exists(DB_NAME):
        print(f"Base de datos '{DB_NAME}' ya existe. No se recrea ni se borran tablas.")
        return

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE usuarios (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL,
            password      TEXT NOT NULL,
            rol           TEXT NOT NULL,
            estudiante_id INTEGER,
            FOREIGN KEY (estudiante_id) REFERENCES estudiantes (id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE estudiantes (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre    TEXT NOT NULL,
            carrera   TEXT NOT NULL,
            biografia TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE calificaciones (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            estudiante_id INTEGER NOT NULL,
            materia       TEXT NOT NULL,
            nota          REAL NOT NULL,
            FOREIGN KEY (estudiante_id) REFERENCES estudiantes (id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE archivos (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre_archivo TEXT NOT NULL,
            ruta          TEXT NOT NULL,
            subido_por    TEXT
        )
        """
    )

    usuarios = [
        ("admin", generate_password_hash("admin123"), "admin", None),
        ("profesor", generate_password_hash("clave456"), "docente", None),
        ("estudiante", generate_password_hash("1234"), "estudiante", 1),
    ]
    cur.executemany(
        "INSERT INTO usuarios (username, password, rol, estudiante_id) VALUES (?, ?, ?, ?)",
        usuarios,
    )

    estudiantes = [
        ("Ana Torres", "Ingenieria de Sistemas", "Estudiante de septimo semestre."),
        ("Luis Gomez", "Ciberseguridad", "Interesado en pentesting."),
        ("Maria Ruiz", "Ciencia de Datos", "Le gusta el machine learning."),
    ]
    cur.executemany(
        "INSERT INTO estudiantes (nombre, carrera, biografia) VALUES (?, ?, ?)",
        estudiantes,
    )

    calificaciones = [
        (1, "Redes", 4.2),
        (1, "Bases de Datos", 3.8),
        (2, "Criptografia", 4.7),
        (3, "Estadistica", 3.5),
    ]
    cur.executemany(
        "INSERT INTO calificaciones (estudiante_id, materia, nota) VALUES (?, ?, ?)",
        calificaciones,
    )

    conn.commit()
    conn.close()
    print(f"Base de datos '{DB_NAME}' creada con contrasenas hasheadas.")


if __name__ == "__main__":
    init_db()
    backup_database()
    migrate_plaintext_passwords()
