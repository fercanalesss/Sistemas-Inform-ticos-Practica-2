import socket
import ssl
import concurrent.futures
import time
import threading

# Configuración del servidor VPN U-Secure
SERVER_IP = '127.0.0.1'
SERVER_PORT = 8443
CA_CERT = 'pki/ca/ca.crt'

# Almacén de métricas globales para el informe (RS3)
results = {
    "success": 0,
    "failure": 0,
    "latencies": []
}
results_lock = threading.Lock()

def simulate_client(client_index):
    """Simula un cliente individual conectándose por mTLS y TLS 1.3 con credenciales dinámicas"""
    
    # Asignación de roles y credenciales dinámicas según la base de datos
    if client_index <= 100:
        role = "PDI"
        username = f"user_pdi_{client_index:03d}"
        password = f"U-Secure_{role}_{client_index:03d}#Pass2026"
    elif client_index <= 200:
        pas_idx = client_index - 100
        role = "PAS"
        username = f"user_pas_{pas_idx:03d}"
        password = f"U-Secure_{role}_{pas_idx:03d}#Pass2026"
    else:
        inv_idx = client_index - 200
        role = "Investigador"
        username = f"user_investigador_{inv_idx:03d}"
        password = f"U-Secure_{role}_{inv_idx:03d}#Pass2026"
        
    cert_path = f"pki/clients/{username}.crt"
    key_path = f"pki/clients/{username}.key"

    start_time = time.time()
    try:
        # Configuración del contexto TLS 1.3 estricto
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Cargar CA corporativa para verificar la identidad del servidor
        context.load_verify_locations(cafile=CA_CERT)
        
        # Cargar certificado y clave privada del cliente (mTLS)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        context.check_hostname = False 

        # Establecer socket TCP seguro
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_sock = context.wrap_socket(raw_sock, server_hostname="localhost")
        
        secure_sock.connect((SERVER_IP, SERVER_PORT))
        
        # Enviar credenciales (Capa 2)
        credentials = f"{username}:{password}"
        secure_sock.sendall(credentials.encode('utf-8'))
        
        response = secure_sock.recv(1024).decode('utf-8')
        
        end_time = time.time()
        latency = (end_time - start_time) * 1000  # Latencia (RTT) en ms

        if "AUTH_SUCCESS" in response:
            with results_lock:
                results["success"] += 1
                results["latencies"].append(latency)
            
            # Cierre limpio de sesión (RF4)
            secure_sock.sendall(b"LOGOUT\n")
            secure_sock.recv(1024)
        else:
            with results_lock:
                results["failure"] += 1
                
        secure_sock.close()

    except Exception as e:
        with results_lock:
            results["failure"] += 1

def run_load_test(total_clients=300):
    """Ejecuta la prueba de carga gestionando bloques eficientes de concurrencia"""
    print(f"Iniciando prueba de carga con {total_clients} clientes concurrentes (RS3)...")
    
    start_total = time.time()
    
    # max_workers=100 gestiona lotes simultáneos estables para evitar saturar los sockets del SO
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(simulate_client, i) for i in range(1, total_clients + 1)]
        concurrent.futures.wait(futures)
        
    end_total = time.time()
    total_time = end_total - start_total
    
    # Métricas cuantitativas finales para el informe PDF (RS3)
    print("\n--- RESULTADOS DEL BENCHMARKING (RS3) ---")
    print(f"Total de clientes simulados: {total_clients}")
    print(f"Conexiones mTLS + TLS 1.3 exitosas: {results['success']}")
    print(f"Conexiones fallidas: {results['failure']}")
    print(f"Tiempo total de ejecución: {total_time:.4f} segundos")
    
    if results["latencies"]:
        avg_latency = sum(results["latencies"]) / len(results["latencies"])
        print(f"Latencia (RTT) promedio: {avg_latency:.2f} ms")
        print(f"Latencia mínima: {min(results['latencies']):.2f} ms")
        print(f"Latencia máxima: {max(results['latencies']):.2f} ms")

if __name__ == "__main__":
    run_load_test(total_clients=300)