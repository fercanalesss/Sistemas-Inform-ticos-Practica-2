"""
pruebas unitarias para validar la autenticación en dos capas (RF2)
"""

from auth_service import authenticate_two_layer

# simulación del formato que entrega ssl.SSLSocket.getpeercert() tras el handshake mTLS
dummy_peer_cert_paul = {
    "subject": (
        (("countryName", "ES"),),
        (("stateOrProvinceName", "Sevilla"),),
        (("organizationName", "Universidad U-Secure"),),
        (("organizationalUnitName", "PDI"),),
        (("commonName", "profesor_paul"),),
    )
}

print("=== TEST 1: Credenciales y certificado correctos (Debe pasar) ===")
ok, msg, data = authenticate_two_layer(
    peer_cert=dummy_peer_cert_paul,
    app_username="profesor_paul",
    app_password="verySecurePassword"
)
print(f"Resultado: {ok} | Mensaje: {msg}\n")

print("=== TEST 2: Certificado correcto pero contraseña incorrecta (Debe fallar) ===")
ok, msg, data = authenticate_two_layer(
    peer_cert=dummy_peer_cert_paul,
    app_username="profesor_paul",
    app_password="veryWrongPassword"
)
print(f"Resultado: {ok} | Mensaje: {msg}\n")

print("=== TEST 3: Suplantación de identidad entre capas (Debe fallar) ===")
ok, msg, data = authenticate_two_layer(
    peer_cert=dummy_peer_cert_paul,
    app_username="admin_andy",
    app_password="verySecurePassword"
)
print(f"Resultado: {ok} | Mensaje: {msg}\n")