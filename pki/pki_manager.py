import os
import subprocess
from pathlib import Path

#obtener rutas y definir las carpetas del proyecto
BASE_DIR = Path(__file__).resolve().parent
CA_DIR = BASE_DIR / "ca"
SERVER_DIR = BASE_DIR / "server"
CLIENTS_DIR = BASE_DIR / "clients"
#rutas para los certificados
CA_KEY = CA_DIR / "ca.key"
CA_CRT = CA_DIR / "ca.crt"
SERVER_KEY = SERVER_DIR / "server.key"
SERVER_CRT = SERVER_DIR / "server.crt"


def init_root_ca() -> None:
    # crea la autoridad de certificación (Root-CA) autofirmada de U-Secure
    # genera un par de claves RSA de 4096 bits con una validez de 10 años (RS1)
    if CA_KEY.exists() and CA_CRT.exists():
        print("=> La Root-CA ya existe en el sistema.")
        return

    print("[+] Generando Root-CA corporativa para U-Secure...")
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "3650",
        "-nodes",
        "-keyout", str(CA_KEY),
        "-out", str(CA_CRT),
        "-subj", "/C=ES/ST=Sevilla/O=Universidad U-Secure/CN=U-Secure Root CA"
    ]
    subprocess.run(cmd, check=True)
    print(f"[+] Root-CA creada exitosamente: {CA_CRT}")


def issue_server_certificate() -> None:
    #Genera y firma el certificado digital X.509v3 del servidor VPN
    #Incluye extensiones obligatorias para TLS 1.3:
    #serverAuth (Extended Key Usage)
    #SAN (Subject Alternative Name) para 127.0.0.1 y localhost
    
    if SERVER_KEY.exists() and SERVER_CRT.exists():
        print("=> El certificado del servidor VPN ya existe.")
        return

    print("=> Generando certificado para el servidor VPN...")
    csr_file = SERVER_DIR / "server.csr"
    ext_file = SERVER_DIR / "server.ext"

    # generar clave privada RSA de 2048 bits y CSR
    cmd_req = [
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(SERVER_KEY),
        "-out", str(csr_file),
        "-subj", "/C=ES/ST=Sevilla/O=Universidad U-Secure/CN=vpn.u-secure.es"
    ]
    subprocess.run(cmd_req, check=True)

    # definir extensiones X.509v3 (SAN y serverAuth)
    ext_content = (
        "basicConstraints = CA:FALSE\n"
        "keyUsage = digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectAltName = @alt_names\n\n"
        "[alt_names]\n"
        "DNS.1 = localhost\n"
        "DNS.2 = vpn.u-secure.es\n"
        "IP.1 = 127.0.0.1\n"
    )
    with open(ext_file, "w") as f:
        f.write(ext_content)

    # firmar el certificado con la Root-CA
    cmd_sign = [
        "openssl", "x509", "-req", "-in", str(csr_file),
        "-CA", str(CA_CRT), "-CAkey", str(CA_KEY),
        "-CAcreateserial", "-out", str(SERVER_CRT),
        "-days", "825", "-sha256",
        "-extfile", str(ext_file)
    ]
    subprocess.run(cmd_sign, check=True)

    # limpiar archivos temporales
    csr_file.unlink(missing_ok=True)
    ext_file.unlink(missing_ok=True)
    print(f"[+] Certificado del servidor firmado exitosamente: {SERVER_CRT}")


def issue_client_certificate(username: str, role: str = "PDI") -> tuple[str, str]:
    #emite un certificado digital X.509v3 individual para un dispositivo BYOD (RF1)
    #:param username: identificador único del usuario corporativo
    #:param role: rol universitario
    #:return: tupla con la ruta al certificado (.crt) y la clave privada (.key)
    client_key = CLIENTS_DIR / f"{username}.key"
    client_crt = CLIENTS_DIR / f"{username}.crt"
    csr_file = CLIENTS_DIR / f"{username}.csr"
    ext_file = CLIENTS_DIR / f"{username}.ext"

    # generar clave privada y solicitud de firma (CSR)
    cmd_req = [
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(client_key),
        "-out", str(csr_file),
        "-subj", f"/C=ES/ST=Sevilla/O=Universidad U-Secure/OU={role}/CN={username}"
    ]
    subprocess.run(cmd_req, check=True)

    # definir extensiones X.509v3 para cliente (clientAuth)
    ext_content = (
        "basicConstraints = CA:FALSE\n"
        "keyUsage = digitalSignature\n"
        "extendedKeyUsage = clientAuth\n"
    )
    with open(ext_file, "w") as f:
        f.write(ext_content)

    # firmar el certificado del cliente con la Root-CA corporativa
    cmd_sign = [
        "openssl", "x509", "-req", "-in", str(csr_file),
        "-CA", str(CA_CRT), "-CAkey", str(CA_KEY),
        "-CAcreateserial", "-out", str(client_crt),
        "-days", "365", "-sha256",
        "-extfile", str(ext_file)
    ]
    subprocess.run(cmd_sign, check=True)

    # limpiar archivos temporales
    csr_file.unlink(missing_ok=True)
    ext_file.unlink(missing_ok=True)

    return str(client_crt), str(client_key)


if __name__ == "__main__":
    init_root_ca()
    issue_server_certificate()  