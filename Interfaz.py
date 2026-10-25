import socket
import ssl
import sys
import os

#funciones de la base de datos y pki
from server.database import register_user
from pki import pki_manager

HOST = '127.0.0.1'
PORT =8443
CA_CERT='pki/ca/ca.crt'

def menu_registro():
    print("\n === Nuevo usuario ===")
    username = input("Nuevo usuario: ")
    password = input("Contrasena: ")
    rol = input("Rol - PDI, PAS, Investigador: ")
    
    #guardar datos del usuario y crear su certificado
    register_user(username, password, rol)
    pki_manager.issue_client_certificate(username, rol)
    print(f" => Usuario '{username}' registrado")

def menu_sesion():
    print("\n === Inicio de sesion ===")
    username=input("Usuario: ").strip()
    password=input("Contrasena: ")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3 #Exigir TLS 1.3 como version minima
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(CA_CERT) #Validar la identidad del servidor
    
    cert_path = os.path.join("pki", "clients", f"{username}.crt")
    key_path = os.path.join("pki", "clients", f"{username}.key")

    try:
        # Cargar el certificado y clave privada 
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    except FileNotFoundError:
        print(f"=> Error: No se encontraron los certificados en la ruta: {cert_path}")
        return

    try:
        # Crear canal de comunicacion
        with socket.create_connection((HOST, PORT)) as sock:
            #envolver el socket y verificar el nombre del servidor
            with context.wrap_socket(sock, server_hostname='vpn.u-secure.es') as ssock:
                credenciales = f"{username}:{password}"
                ssock.sendall(credenciales.encode('utf-8'))
                respuesta = ssock.recv(1024).decode('utf-8') #Leer la respuesta de el servidor
                
                #Comprobar si el servidor acepta el acceso
                if "AUTH_SUCCESS" in respuesta or "Autenticacion exitosa" in respuesta:
                    print("=> Autenticacion exitosa y tunel establecido")
                    menu_activo(ssock)
                else:
                    print(f"=> Error de autenticacion en Capa 2: {respuesta}")
    except Exception as e:
        print(f"=> Error de conexion: {e}")

def menu_activo(ssock):
    #Meno para la sesion abierta
    while True:
        print("\n=== Sesion abierta ===")
        print("1. Enviar mensaje de prueba")
        print("2. Cerrar sesion - LOGOUT")
        opcion = input("Seleccionar una opcion: ")

        if opcion == '1':
            msg = input("Escriba su mensaje: ")
            #enviar el mensaje cifrado por el tunel
            ssock.sendall(msg.encode('utf-8'))
            print("=> Mensaje cifrado enviado.")
        elif opcion == '2':
            #enviar comando de salida
            ssock.sendall(b'LOGOUT')
            print("=> Cerrando sesion: Destruyendo tunel y claves")
            break

def main():
    #Muestra el menu principal de la consola de manera repetitiva
    while True:
        print("\n=== U-secure ===")
        print("1. Registrar nuevo usuario")
        print("2. Iniciar sesion")
        print("3. Salir")
        opcion = input("Seleccione una opcion: ")

        if opcion == '1':
            menu_registro()
        elif opcion == '2':
            menu_sesion()
        elif opcion == '3':
            sys.exit(0)
        else:
            print("Seleccionar solo una opcion valida")

if __name__ == "__main__":
    main()