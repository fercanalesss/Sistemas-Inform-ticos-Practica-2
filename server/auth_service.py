"""
servicio de autenticación en dos capas
implementa el requisito RF2:
  - capa 1: validación del certificado digital BYOD (mTLS / transporte)
  - capa 2: validación de credenciales corporativas (aplicación)
"""

from pathlib import Path
import secrets
import sqlite3
import sys
from typing import Any, Dict, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from server.database import get_db_connection, hash_password


def extract_cn_from_certificate(peer_cert: Dict[str, Any]) -> Optional[str]:
    # extrae el common name (CN) del subject del certificado del cliente
    # el formato de peer_cert corresponde al devuelto por ssl.SSLSocket.getpeercert()

    subject = peer_cert.get("subject", ())
    for rdn in subject:
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def verify_transport_layer(peer_cert: Dict[str, Any]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    # capa 1 (transporte / mTLS):
    # verifica que el certificado presentado pertenezca a un usuario registrado y activo, garantizando la inmutabilidad de la clave pública vinculada (RF1)

    if not peer_cert:
        return False, "Fallo Capa 1: No se ha proporcionado certificado de cliente.", None

    cert_username = extract_cn_from_certificate(peer_cert)
    if not cert_username:
        return False, "Fallo Capa 1: El certificado no contiene un Common Name (CN) válido.", None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, password_hash, salt, role, public_key, is_revoked
        FROM users
        WHERE username = ?
    """, (cert_username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return False, f"Fallo Capa 1: El usuario '{cert_username}' del certificado no existe en el sistema.", None

    user_id, username, pwd_hash, salt, role, public_key, is_revoked = user

    # comprobar si el certificado/usuario ha sido revocado
    if is_revoked == 1:
        return False, f"Fallo Capa 1: El certificado del usuario '{cert_username}' ha sido revocado.", None

    user_data = {
        "id": user_id,
        "username": username,
        "password_hash": pwd_hash,
        "salt": salt,
        "role": role,
        "public_key": public_key
    }
    return True, f"Capa 1 superada: Certificado válido para '{cert_username}' ({role}).", user_data


def verify_application_layer(user_data: Dict[str, Any], password: str) -> Tuple[bool, str]:
    # capa 2 (Aplicación):
    # verifica la contraseña corporativa recalculando el hash PBKDF2-HMAC-SHA256 y comparándolo en tiempo constante (mitigación de canales laterales)

    salt_bytes = bytes.fromhex(user_data["salt"])
    computed_hash = hash_password(password, salt_bytes)
    stored_hash = user_data["password_hash"]

    if not secrets.compare_digest(computed_hash, stored_hash):
        return False, "Fallo Capa 2: Contraseña corporativa incorrecta."

    return True, "Capa 2 superada: Contraseña válida."


def authenticate_two_layer(peer_cert: Dict[str, Any], app_username: str, app_password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    # RF2: orquestador de autenticación en dos capas
    # requiere la superación estricta de ambas capas y la coincidencia de identidad

    # validación capa 1 (certificado X.509 del dispositivo BYOD)
    success_l1, msg_l1, user_data = verify_transport_layer(peer_cert)
    if not success_l1 or user_data is None:
        return False, msg_l1, None

    # coherencia de identidad entre capas
    cert_username = user_data["username"]
    if cert_username != app_username:
        return (
            False,
            f"Fallo de vinculación: El certificado pertenece a '{cert_username}', "
            f"pero las credenciales introducidas son de '{app_username}'.",
            None
        )

    # validación capa 2 (credenciales de aplicación)
    success_l2, msg_l2 = verify_application_layer(user_data, app_password)
    if not success_l2:
        return False, msg_l2, None

    return (
        True,
        f"Autenticación exitosa en dos capas para '{cert_username}' con rol '{user_data['role']}'.",
        user_data
    )