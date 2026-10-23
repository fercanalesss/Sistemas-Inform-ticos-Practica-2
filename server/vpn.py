import socket
import ssl
import threading  # Importado para permitir concurrencia (múltiples conexiones simultáneas)
from auth_service import authenticate_two_layer #Del archivo auth_service en esta misma carpeta, se importa la funcion que ya estaba programada

def handle_client(secure_sock, addr):
    """Función para gestionar la sesión de cada cliente de forma independiente en un hilo."""
    try:
        #Extraer el certificado del cliente
        peer_cert = secure_sock.getpeercert()
        #Recibir credenciales
        credentials_bytes = secure_sock.recv(1024)
        if not credentials_bytes:
            secure_sock.close()
            return
        parts = credentials_bytes.decode('utf-8').split(":")
        if len(parts) != 2:
            secure_sock.sendall(b"Formato invalido.\n")
            secure_sock.close()
            return
        app_username, app_password = parts[0], parts[1]

        #RF2
        #Validar el mensaje con autenticacion de 2 capas 
        success, message, user_data = authenticate_two_layer(peer_cert, app_username, app_password)
        
        if not success:
            print(f"[{addr}] Autenticacion fallida: {message}")
            secure_sock.sendall(f"AUTH_FAIL: {message}\n".encode('utf-8'))
            secure_sock.close()
            return
        
        print(f"[{addr}] {message}")
        secure_sock.sendall(b"AUTH_SUCCESS: Tunel establecido correctamente\n")
        
        #RF4
        #Cierre de sesion y cierre del tunel
        while True:
            data = secure_sock.recv(1024)
            if not data:
                break
            
            message_str = data.decode('utf-8').strip()
            #Si se envia la palabra LOGOUT el servidor debe detectar la orden de cierre
            if message_str.upper() == "LOGOUT":
                print(f"[{addr}] Solicitud de cierre recibida de {app_username}")
                secure_sock.sendall(b"SESSION_CLOSED\n")
                break
            
            print(f"[{addr}] Datos recibidos por el tunel: {message_str}")
            secure_sock.sendall(f"ECHO: {message_str}\n".encode('utf-8'))
            
    except ssl.SSLError as e:
        print(f"[{addr}] Error de Handshake: {e}")
    except Exception as e:
        print(f"[{addr}] Error en la sesion del cliente: {e}")
    finally:
        #Revisar que si se haya desmontado el tunel
        secure_sock.close()
        print(f"[{addr}] Tunel desmontado")

def RunVpnServer():
    #RS2:
    #Para lo que se pide en el Rs2 en las siguientes lineas se fuerza que la version minima de tls sea la 1.3 y no usar obsoletos
    #funciones de los ciphers obtenidas de https://docs.python.org/3/library/ssl.html
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3 #Version minima
    context.maximum_version = ssl.TLSVersion.TLSv1_3 #Version maxima
    
    #RS1
    #Cargar el certificado y clave privada del servidor VPN, load cert le entrega su propio certificado y clave
    context.load_cert_chain(certfile="pki/server/server.crt", keyfile="pki/server/server.key")
    #Configurar mTLS y verificar el certificado del cliente BYOD
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile="pki/ca/ca.crt")

    #configuracion del socket
    bind_ip = '127.0.0.1'
    bind_port = 8443
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((bind_ip, bind_port)) #Asociar el servidor a la ip local y al puerto
    server_sock.listen(100) # Se incrementa la cola de espera para soportar múltiples conexiones concurrentes
    print(f"Servidor VPN TLS 1.3 escuchando en {bind_ip}:{bind_port}: ")

    try:
        while True:
            client_sock, addr = server_sock.accept()
            print(f"Conexion TCP entrante desde: {addr}")
            try:
                #convertir el socket en un canal cifrado TLS1.3
                #https://docs.python.org/3/library/ssl.html
                secure_sock = context.wrap_socket(client_sock, server_side=True)
                
                # Lanzar un hilo independiente para atender a este cliente de forma concurrente
                client_thread = threading.Thread(target=handle_client, args=(secure_sock, addr))
                client_thread.daemon = True
                client_thread.start()
                
            except ssl.SSLError as e:
                print(f"Error de Handshake con {addr}: {e}")
                client_sock.close()
            except Exception as e:
                print(f"Error en la sesion del cliente con {addr}: {e}")
                client_sock.close()
                
    except KeyboardInterrupt:
        print("\nApagando servidor")
    finally:
        server_sock.close()

if __name__ == "__main__":
    RunVpnServer()