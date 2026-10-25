import socket
import time
import concurrent.futures

def simulate_plain_client(i):
    start = time.time() #Medir el tiempo
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Crear socket tradicional
        sock.connect(('127.0.0.1', 8444))
        #credenciales de prueba
        sock.sendall(b"dummy_user:dummy_password")
        sock.recv(1024)
        sock.sendall(b"LOGOUT")
        sock.recv(1024)
        sock.close()
        #retornar el tiempo total que llevo la peticion en milisegundos
        return (time.time() - start) * 1000
    except Exception:
        return None

def run_plain_test():
    print("=> Iniciando prueba texto plano para 300 usuarios")
    start_total = time.time()
    #crear hilos para ejecutar hasta 100 tareas
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        latencies = list(executor.map(simulate_plain_client, range(300)))
    valid = [l for l in latencies if l is not None]#filtar lista solo para sesiones completadas
    print(f"=> Tiempo total: {time.time() - start_total:.4f} segundos")
    print(f"=> Latencia media: {sum(valid)/len(valid):.2f} ms")

if __name__ == "__main__":
    run_plain_test()