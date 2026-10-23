import socket
import ssl

# Configurar un contexto TLS con un certificado falso/autofirmado cualquiera
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# Generamos o usamos un certificado de prueba no confiable
context.load_cert_chain(certfile="pki/clients/user_pdi_001.crt", keyfile="pki/clients/user_pdi_001.key") 
# (Usamos un certificado de cliente como certificado de servidor falso para forzar el fallo de CA)

bind_ip = '127.0.0.1'
bind_port = 8443

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_sock.bind((bind_ip, bind_port))
server_sock.listen(1)

print(f"[*] Servidor falso/malicioso activo en {bind_ip}:{bind_port}...")

while True:
    client_sock, addr = server_sock.accept()
    try:
        secure_conn = context.wrap_socket(client_sock, server_side=True)
    except Exception as e:
        print(f"[!] Intento de conexión interceptado y abortado por la seguridad TLS: {e}")
    break