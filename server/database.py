"""
Gestión de base de datos y usuarios corporativos
Cumple con los requisitos RF1 (Registro y vinculación PKI), RF2 y RF5 (Precarga de cuentas)
"""

import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

# añadir ruta base para importar el gestor de PKI
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from pki.pki_manager import issue_client_certificate  # noqa: E402

DB_PATH = Path(__file__).resolve().parent / "u_secure.db"


def get_db_connection() -> sqlite3.Connection:
    # establece y devuelve una conexión a la base de datos SQLite
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    # inicializa el esquema de tablas para la plataforma
    # garantiza la inmutabilidad de la clave pública vinculada a la identidad (RF1)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('PDI', 'PAS', 'Investigador')),
            cert_path TEXT NOT NULL,
            public_key TEXT NOT NULL,
            is_revoked INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    print("[+] Base de datos inicializada correctamente.")


def hash_password(password: str, salt: bytes) -> str:
    # herivación robusta mediante PBKDF2-HMAC-SHA256 con 100.000 iteraciones (RS1)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000).hex()


def extract_public_key(cert_path: str) -> str:
    # extrae la clave pública en formato PEM desde el certificado X.509 emitido (RF1)
    # garantiza la vinculación inmutable con el registro del usuario

    cmd = ["openssl", "x509", "-in", cert_path, "-pubkey", "-noout"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def register_user(username: str, password: str, role: str) -> bool:
    """
    registra un nuevo usuario y emite su certificado digital X.509v3 para dispositivo BYOD (RF1)

    :param username: nombre de usuario único
    :param password: contraseña corporativa
    :param role: rol universitario ('PDI', 'PAS' o 'Investigador')
    :return: true si el registro fue exitoso, false si el usuario ya existe
    """

    conn = get_db_connection()
    cursor = conn.cursor()

    # comprobación de duplicados
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        print(f"[-] El usuario '{username}' ya existe.")
        conn.close()
        return False

    # emisión de certificado de cliente mediante la CA corporativa
    cert_path, key_path = issue_client_certificate(username=username, role=role)
    public_key = extract_public_key(cert_path)

    # derivación de clave y almacenamiento seguro de contraseña
    salt = os.urandom(16)
    pwd_hash = hash_password(password, salt)

    # almacenamiento inmutable en base de datos
    cursor.execute("""
        INSERT INTO users (username, password_hash, salt, role, cert_path, public_key)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (username, pwd_hash, salt.hex(), role, cert_path, public_key))

    conn.commit()
    conn.close()
    print(f"[+] Usuario '{username}' ({role}) registrado con éxito.")
    print(f"    Certificado emitido: {cert_path}")
    print(f"    Clave privada: {key_path}")
    return True


def preload_initial_users() -> None:
    # RF5: precarga de cuentas corporativas iniciales para pruebas de roles

    usuarios_prueba = [
        ("profesor_paul", "verySecurePassword", "PDI"),
        ("admin_andy", "verySecurePassword", "PAS"),
        ("investigador_ines", "verySecurePassword*2026", "Investigador")
    ]

    for username, password, role in usuarios_prueba:
        register_user(username, password, role)


if __name__ == "__main__":
    init_db()
    preload_initial_users()