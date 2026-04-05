"""
============================================================
scripts/log_collector.py
------------------------------------------------------------
RECOLECTOR Y NORMALIZADOR DE LOGS
------------------------------------------------------------
¿Para qué sirve?
  Lee los logs de los tres honeypots (Cowrie, Dionaea,
  Suricata), los normaliza a un formato unificado y los
  guarda en un archivo JSON central que será consumido
  por el motor de análisis y el módulo de ML.

Flujo:
  [Cowrie JSON] ──┐
  [Dionaea JSON]──┼──► [Normalizador] ──► data/events_normalized.json
  [Suricata log]──┘
============================================================
"""

import json
import os
import re
import hashlib
from datetime import datetime
from typing import Generator


# ── Normalizador base ────────────────────────────────────────

def _make_event_id(event: dict) -> str:
    """
    Crea un ID único por evento para evitar duplicados.
    Basado en hash MD5 de los campos principales.
    """
    key = f"{event.get('timestamp','')}{event.get('src_ip','')}{event.get('source','')}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


def normalize_event(raw: dict, source: str) -> dict:
    """
    Estructura de evento normalizado (común para todos los honeypots):
    {
      id, timestamp, source, src_ip, dst_port, protocol,
      attack_type, username, password, command, malware,
      raw_event
    }
    Esto permite que el motor de análisis trate todos
    los eventos de la misma forma, sin importar el origen.
    """
    now_str = datetime.utcnow().isoformat() + "Z"

    normalized = {
        "id":          _make_event_id(raw),
        "timestamp":   raw.get("timestamp", now_str),
        "source":      source,
        "src_ip":      raw.get("src_ip", "unknown"),
        "dst_port":    int(raw.get("dst_port", 0)),
        "protocol":    raw.get("protocol", "unknown"),
        "attack_type": raw.get("attack_type", "unknown"),  # se sobreescribe abajo
        "username":    raw.get("username", None),
        "password":    raw.get("password", None),
        "command":     raw.get("input",    None),
        "malware":     raw.get("malware",  None),
        "rule_msg":    raw.get("rule_msg", None),
        "payload_size":raw.get("payload_size", 0),
        "sensor":      raw.get("sensor", "honeypot"),
        "raw_event":   raw,                                 # guardamos el original
    }

    # ── Inferir tipo de ataque según la fuente ───────────────
    if source == "cowrie":
        eventid = raw.get("eventid", "")
        if "login.failed" in eventid:
            normalized["attack_type"] = "brute_force"
        elif "login.success" in eventid:
            normalized["attack_type"] = "unauthorized_access"
        elif "command" in eventid:
            normalized["attack_type"] = "command_execution"
        else:
            normalized["attack_type"] = "ssh_probe"

    elif source == "dionaea":
        if raw.get("malware"):
            normalized["attack_type"] = "malware_upload"
        elif "exploit" in raw.get("eventid", ""):
            normalized["attack_type"] = "exploit_attempt"
        else:
            normalized["attack_type"] = "service_probe"

    elif source == "suricata":
        # Suricata ya incluye el tipo en attack_type
        normalized["attack_type"] = raw.get("attack_type", "ids_alert")

    return normalized


# ── Lectores por honeypot ────────────────────────────────────

def read_cowrie_logs(log_path: str) -> Generator[dict, None, None]:
    """
    Lee el archivo JSON lines de Cowrie.
    Cowrie escribe un JSON por línea, cada línea es un evento.
    Ejemplo de línea:
      {"timestamp":"2024-01-01T12:00:00Z","eventid":"cowrie.login.failed",...}
    """
    if not os.path.exists(log_path):
        print(f"[COLLECTOR] ⚠ No se encontró log de Cowrie: {log_path}")
        return

    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                yield normalize_event(raw, source="cowrie")
            except json.JSONDecodeError:
                print(f"[COLLECTOR] ⚠ Línea {line_num} inválida en Cowrie log")


def read_dionaea_logs(log_path: str) -> Generator[dict, None, None]:
    """
    Lee el archivo JSON de Dionaea.
    Similar a Cowrie: un JSON por línea.
    """
    if not os.path.exists(log_path):
        print(f"[COLLECTOR] ⚠ No se encontró log de Dionaea: {log_path}")
        return

    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                yield normalize_event(raw, source="dionaea")
            except json.JSONDecodeError:
                print(f"[COLLECTOR] ⚠ Línea {line_num} inválida en Dionaea log")


def read_suricata_logs(log_path: str) -> Generator[dict, None, None]:
    """
    Lee el archivo fast.log de Suricata (texto plano).
    
    Formato del log:
    01/15/2024-12:30:45.123 [**] [1:2001234:2] ET SCAN Nmap [**]
    [Classification: ...] [Priority: 2] {TCP} 192.168.1.100:4444 -> 10.0.0.1:22
    
    Usamos regex para extraer cada campo.
    """
    if not os.path.exists(log_path):
        print(f"[COLLECTOR] ⚠ No se encontró log de Suricata: {log_path}")
        return

    # Patrón regex para parsear el formato fast.log de Suricata
    pattern = re.compile(
        r"(?P<ts>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)"  # timestamp
        r".*?\[1:(?P<sid>\d+):\d+\]\s+(?P<msg>.+?)\s+\[\*\*\]"  # SID y mensaje
        r".*?Priority:\s*(?P<priority>\d+)\]"                    # prioridad
        r"\s+\{(?P<proto>\w+)\}"                                  # protocolo
        r"\s+(?P<src_ip>[\d.]+):(?P<src_port>\d+)"              # IP:puerto origen
        r"\s+->\s+[\d.]+:(?P<dst_port>\d+)"                     # puerto destino
    )

    # Clasificador básico por palabras clave en el mensaje
    def classify_suricata(msg: str) -> str:
        msg_lower = msg.lower()
        if "scan" in msg_lower or "nmap" in msg_lower:
            return "port_scan"
        if "brute" in msg_lower or "ssh" in msg_lower:
            return "brute_force"
        if "malware" in msg_lower or "trojan" in msg_lower or "botnet" in msg_lower:
            return "malware"
        if "exploit" in msg_lower or "eternal" in msg_lower:
            return "exploit_attempt"
        if "dos" in msg_lower or "flood" in msg_lower:
            return "dos"
        return "ids_alert"

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = pattern.search(line)
            if m:
                raw = {
                    "timestamp":   m.group("ts"),
                    "src_ip":      m.group("src_ip"),
                    "src_port":    int(m.group("src_port")),
                    "dst_port":    int(m.group("dst_port")),
                    "protocol":    m.group("proto").lower(),
                    "rule_msg":    m.group("msg"),
                    "attack_type": classify_suricata(m.group("msg")),
                    "priority":    int(m.group("priority")),
                    "sensor":      "honeypot-rpi",
                }
                yield normalize_event(raw, source="suricata")


# ── Recolector principal ─────────────────────────────────────

def collect_all_logs(config: dict) -> list:
    """
    Recolecta eventos de los tres honeypots, elimina duplicados
    y devuelve una lista unificada de eventos normalizados.
    
    Parámetro config: diccionario cargado desde config.yaml
    """
    events     = []
    seen_ids   = set()  # Para evitar procesar el mismo evento dos veces

    sources = [
        ("cowrie",   read_cowrie_logs,   config["logs"]["cowrie"]),
        ("dionaea",  read_dionaea_logs,  config["logs"]["dionaea"]),
        ("suricata", read_suricata_logs, config["logs"]["suricata"]),
    ]

    for name, reader_fn, path in sources:
        count = 0
        for event in reader_fn(path):
            if event["id"] not in seen_ids:
                seen_ids.add(event["id"])
                events.append(event)
                count += 1
        print(f"[COLLECTOR] ✓ {name:10s} → {count:4d} eventos cargados")

    print(f"[COLLECTOR] Total eventos únicos: {len(events)}")
    return events


def save_normalized_events(events: list, output_path: str):
    """
    Guarda todos los eventos normalizados en un archivo JSON.
    Este archivo es la 'base de datos' del sistema.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Cargar eventos previos si el archivo ya existe
    existing = []
    if os.path.exists(output_path):
        with open(output_path, "r") as f:
            try:
                existing = json.load(f)
            except json.JSONDecodeError:
                existing = []

    # Combinar y deduplicar
    existing_ids = {e["id"] for e in existing}
    new_events   = [e for e in events if e["id"] not in existing_ids]

    all_events = existing + new_events

    with open(output_path, "w") as f:
        json.dump(all_events, f, indent=2, default=str)

    print(f"[COLLECTOR] ✓ Guardados {len(new_events)} nuevos eventos en {output_path}")
    print(f"[COLLECTOR] ✓ Total acumulado: {len(all_events)} eventos")
    return all_events


# ── Punto de entrada para pruebas ────────────────────────────
if __name__ == "__main__":
    import yaml

    with open("config/config.yaml") as f:
        config = yaml.safe_load(f)

    events = collect_all_logs(config)
    save_normalized_events(events, config["output"]["normalized_json"])
