from pathlib import Path
import socket
import ssl

BASE_DIR = Path(__file__).resolve().parent #Buscar directamente la raiz del proyecto
def RunVpnClient():
    #RS2
    #Misma confguracion que el archivo vpn.py, solo cambia de server a client
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    #comprobar que el Servidor es autentico
    ca_path = BASE_DIR / "pki" / "ca" / "ca.crt"
    context.load_verify_locations(cafile=str(ca_path))
    #Cargar el certificado y clave
    client_cert = BASE_DIR / "pki" / "clients" / "profesor_paul.crt"
    client_key = BASE_DIR / "pki" / "clients" / "profesor_paul.key"
    context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    #Desactivar el hostname para pruebas locales
    context.check_hostname = False

    server_host = '127.0.0.1'
    server_port = 8443
    #conectar al servidor
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_sock = context.wrap_socket(raw_sock, server_hostname="vpn.u-secure.es")
    
    try:
        secure_sock.connect((server_host, server_port))
        print("Canal seguro TLS1.3 y mTLS establecido")
        #enviar credenciales
        credentials = "profesor_paul:verySecurePassword"
        secure_sock.sendall(credentials.encode('utf-8'))
        #Respuesta
        response = secure_sock.recv(1024).decode('utf-8')
        print(f"[Servidor]: {response.strip()}")
        if "AUTH_SUCCESS" in response:
            #simular el uso de la vpn
            secure_sock.sendall(b"Hola U-Secure")
            tunnel_response = secure_sock.recv(1024).decode('utf-8')
            #RF4
            #desconectar de la vpn
            secure_sock.sendall(b"LOGOUT")
            logout_response = secure_sock.recv(1024).decode('utf-8')

    except Exception as e:
        print(f"Error de conexion: {e}")
    finally:
        # Cerrar el socket y destruir las claves
        secure_sock.close()
        print("Conexion cerrada")

if __name__ == "__main__":
    RunVpnClient()