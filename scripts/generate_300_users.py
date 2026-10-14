"""
generación masiva de 300 usuarios precargados y certificados digitales X.509
satisface el requisito RF5 y habilita las pruebas de concurrencia de RS3
"""

from pathlib import Path
import sys

# añadir la raíz del proyecto para importar módulos del servidor
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from server.database import register_user


def generate_benchmark_users(total_users: int = 300) -> None:
    # crea cuentas corporativas distribuidas entre PDI, PAS e Investigadores,emitiendo sus certificados individuales mediante la CA

    roles = ["PDI", "PAS", "Investigador"]
    users_per_role = 100

    print(f"[+] Iniciando generación de {total_users} cuentas para pruebas de carga...")

    created = 0
    for role_idx, role in enumerate(roles):
        for i in range(1, users_per_role + 1):
            username = f"user_{role.lower()}_{i:03d}"
            password = f"U-Secure_{role}_{i:03d}#Pass2026"

            success = register_user(username=username, password=password, role=role)
            if success:
                created += 1

    print(f"\n[+] Proceso completado: {created}/{total_users} usuarios listos para el benchmark.")


if __name__ == "__main__":
    generate_benchmark_users(300)