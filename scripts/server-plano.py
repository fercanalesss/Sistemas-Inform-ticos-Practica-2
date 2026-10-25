import socket
import threading

def handle_plain_client(client_sock):
    try:
        # Simular lectura de credenciales y respuesta
        client_sock.recv(1024)
        client_sock.sendall(b"AUTH_SUCCESS\n")
        # Simular cierre (RF4)
        client_sock.recv(1024)
        client_sock.sendall(b"SESSION_CLOSED\n")
    finally:
        client_sock.close()

def run_plain_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('127.0.0.1', 8444))
    server_sock.listen(100)
    print("Servidor TCP en texto plano escuchando en 127.0.0.1:8444")
    
    while True:
        client_sock, _ = server_sock.accept()
        threading.Thread(target=handle_plain_client, args=(client_sock,), daemon=True).start()

if __name__ == "__main__":
    run_plain_server()