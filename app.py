"""
FocusFlow - Servicio web de registro e inicio de sesión
Evidencia: GA7-220501096-AA5-EV01
Autor: Luis Angel Guisado Gorredo
"""
import sqlite3
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
DB_ARCHIVO = "usuarios.db"  # base de datos SQLite (se crea sola)


def obtener_conexion():
    """Abre una conexión a la base de datos."""
    conexion = sqlite3.connect(DB_ARCHIVO)
    conexion.row_factory = sqlite3.Row
    return conexion


def crear_tabla():
    """Crea la tabla usuarios si no existe."""
    with obtener_conexion() as conexion:
        conexion.execute(
            """CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT NOT NULL UNIQUE,
                contrasena TEXT NOT NULL)"""
        )


def leer_credenciales():
    """Lee usuario y contraseña del JSON recibido."""
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario", "")).strip()
    contrasena = str(datos.get("contrasena", ""))
    if not usuario or not contrasena:
        return None, None
    return usuario, contrasena


@app.route("/", methods=["GET"])
def inicio():
    """Confirma que el servicio está activo."""
    return jsonify({"mensaje": "Servicio web FocusFlow activo"}), 200


@app.route("/registro", methods=["POST"])
def registro():
    """Registra un usuario nuevo (201 creado, 400 faltan datos, 409 repetido)."""
    usuario, contrasena = leer_credenciales()
    if usuario is None:
        return jsonify({"error": "Debe enviar usuario y contrasena"}), 400

    # La contraseña se guarda cifrada (hash), nunca en texto plano
    contrasena_hash = generate_password_hash(contrasena)
    try:
        with obtener_conexion() as conexion:
            conexion.execute(
                "INSERT INTO usuarios (usuario, contrasena) VALUES (?, ?)",
                (usuario, contrasena_hash),
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "El usuario ya está registrado"}), 409

    return jsonify({"mensaje": "Usuario registrado correctamente"}), 201


@app.route("/login", methods=["POST"])
def login():
    """Valida credenciales (200 satisfactoria, 401 error en la autenticación)."""
    usuario, contrasena = leer_credenciales()
    if usuario is None:
        return jsonify({"error": "Error en la autenticación"}), 401

    with obtener_conexion() as conexion:
        fila = conexion.execute(
            "SELECT contrasena FROM usuarios WHERE usuario = ?", (usuario,)
        ).fetchone()

    # Si no existe o la contraseña no coincide, se rechaza
    if fila is None or not check_password_hash(fila["contrasena"], contrasena):
        return jsonify({"error": "Error en la autenticación"}), 401

    return jsonify({"mensaje": "Autenticación satisfactoria"}), 200


if __name__ == "__main__":
    crear_tabla()
    app.run(debug=True, port=5000)