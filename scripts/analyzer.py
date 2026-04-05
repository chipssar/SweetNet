"""
============================================================
scripts/analyzer.py
------------------------------------------------------------
MOTOR DE ANÁLISIS DE PATRONES
------------------------------------------------------------
¿Para qué sirve?
  Toma los eventos normalizados y busca patrones peligrosos:
  - Fuerza bruta (muchos intentos desde la misma IP)
  - Escaneo de puertos (una IP toca muchos puertos)
  - Actividad de malware (intentos de descarga o exploit)
  - Anomalías temporales (picos de actividad inusuales)
  
  También extrae "features" (características numéricas) que
  el módulo de ML usará para clasificar ataques.
============================================================
"""

import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Tuple


# ── Extractor de características (Features) ─────────────────

def extract_features(events: list) -> list:
    """
    Extrae características numéricas de cada evento.
    
    ¿Por qué necesitamos esto?
    Los modelos de ML no entienden texto ("ssh", "brute_force").
    Necesitan números. Convertimos cada evento en un vector
    de números que represente sus propiedades.
    
    Features extraídas por evento:
      - dst_port:        puerto destino (número)
      - src_ip_oct3:     tercer octeto de la IP (ej: 192.168.X.1)
      - src_ip_oct4:     cuarto octeto
      - protocol_num:    protocolo codificado como número
      - hour_of_day:     hora del día (0-23) — ataques más nocturnos
      - has_credentials: ¿tenía usuario/contraseña? (0 o 1)
      - has_command:     ¿ejecutó un comando? (0 o 1)
      - has_malware:     ¿involucra malware? (0 o 1)
      - payload_size:    tamaño del payload en bytes
      - source_num:      honeypot de origen codificado
    """
    # Codificación de protocolos a números
    proto_map = {
        "ssh": 0, "telnet": 1, "ftp": 2, "http": 3,
        "https": 4, "smb": 5, "tcp": 6, "udp": 7,
        "icmp": 8, "mssql": 9, "mysql": 10, "sip": 11,
        "unknown": 99,
    }

    # Codificación de honeypot de origen
    source_map = {"cowrie": 0, "dionaea": 1, "suricata": 2}

    # Codificación del tipo de ataque (etiqueta para ML supervisado)
    attack_label_map = {
        "brute_force":         0,
        "port_scan":           1,
        "malware":             2,
        "malware_upload":      2,
        "exploit_attempt":     3,
        "unauthorized_access": 4,
        "command_execution":   5,
        "dos":                 6,
        "ssh_probe":           7,
        "service_probe":       7,
        "ids_alert":           8,
        "unknown":             9,
    }

    feature_vectors = []

    for ev in events:
        # Parsear IP para extraer octetos
        try:
            octets = ev.get("src_ip", "0.0.0.0").split(".")
            oct3 = int(octets[2]) if len(octets) >= 3 else 0
            oct4 = int(octets[3]) if len(octets) >= 4 else 0
        except (ValueError, IndexError):
            oct3, oct4 = 0, 0

        # Parsear hora del evento
        try:
            ts = ev.get("timestamp", "")
            dt = datetime.fromisoformat(ts.replace("Z", ""))
            hour = dt.hour
        except (ValueError, TypeError):
            hour = 0

        # Construir vector de características
        feature_vec = {
            # Características del evento
            "dst_port":        ev.get("dst_port", 0),
            "src_ip_oct3":     oct3,
            "src_ip_oct4":     oct4,
            "protocol_num":    proto_map.get(ev.get("protocol", "unknown"), 99),
            "hour_of_day":     hour,
            "has_credentials": 1 if ev.get("username") and ev.get("password") else 0,
            "has_command":     1 if ev.get("command") else 0,
            "has_malware":     1 if ev.get("malware") else 0,
            "payload_size":    min(ev.get("payload_size", 0), 100000),  # cap a 100KB
            "source_num":      source_map.get(ev.get("source", ""), 99),

            # Etiqueta (para entrenamiento supervisado)
            "label": attack_label_map.get(ev.get("attack_type", "unknown"), 9),

            # Metadatos (no entran al modelo, solo para referencia)
            "_id":          ev.get("id"),
            "_src_ip":      ev.get("src_ip"),
            "_attack_type": ev.get("attack_type"),
            "_timestamp":   ev.get("timestamp"),
        }

        feature_vectors.append(feature_vec)

    return feature_vectors


# ── Detector de patrones ─────────────────────────────────────

class PatternDetector:
    """
    Analiza el flujo de eventos y detecta patrones de ataque
    usando reglas heurísticas (sin ML).
    
    Complementa al ML: las reglas son rápidas y deterministas,
    el ML clasifica casos ambiguos.
    """

    def __init__(self, config: dict):
        # Umbrales desde el archivo de configuración
        self.bf_threshold   = config["thresholds"]["brute_force_attempts"]
        self.scan_threshold = config["thresholds"]["port_scan_ports"]
        self.time_window    = config["thresholds"]["time_window_seconds"]

    def detect_brute_force(self, events: list) -> List[Dict]:
        """
        Detecta fuerza bruta: una IP hace N intentos fallidos
        en una ventana de tiempo corta.
        
        Ejemplo real: Hydra probando 1000 contraseñas en 60 segundos.
        """
        alerts = []

        # Agrupar intentos de login fallido por IP
        # ip → [(timestamp, evento), ...]
        ip_attempts: Dict[str, list] = defaultdict(list)

        for ev in events:
            if ev.get("attack_type") == "brute_force":
                ip_attempts[ev["src_ip"]].append(ev)

        for ip, attempts in ip_attempts.items():
            # Ordenar por tiempo
            attempts.sort(key=lambda e: e.get("timestamp", ""))

            # Ventana deslizante: contar intentos en window_seconds
            for i, ev in enumerate(attempts):
                try:
                    t0 = datetime.fromisoformat(ev["timestamp"].replace("Z", ""))
                except (ValueError, KeyError):
                    continue

                # Contar eventos en la ventana temporal
                window_count = sum(
                    1 for e in attempts[i:]
                    if abs((datetime.fromisoformat(
                        e.get("timestamp", t0.isoformat()).replace("Z", "")
                    ) - t0).total_seconds()) <= self.time_window
                )

                if window_count >= self.bf_threshold:
                    alerts.append({
                        "type":        "BRUTE_FORCE_DETECTED",
                        "severity":    "HIGH",
                        "src_ip":      ip,
                        "count":       window_count,
                        "window_sec":  self.time_window,
                        "first_seen":  ev["timestamp"],
                        "description": (
                            f"IP {ip} realizó {window_count} intentos de login "
                            f"en {self.time_window}s"
                        ),
                    })
                    break  # Una alerta por IP es suficiente

        return alerts

    def detect_port_scan(self, events: list) -> List[Dict]:
        """
        Detecta escaneo de puertos: una IP toca N puertos distintos
        en poco tiempo. Patrón típico de Nmap.
        """
        alerts = []
        ip_ports: Dict[str, set] = defaultdict(set)

        for ev in events:
            if ev.get("attack_type") in ("port_scan", "ids_alert"):
                ip_ports[ev["src_ip"]].add(ev.get("dst_port", 0))

        for ip, ports in ip_ports.items():
            if len(ports) >= self.scan_threshold:
                alerts.append({
                    "type":        "PORT_SCAN_DETECTED",
                    "severity":    "MEDIUM",
                    "src_ip":      ip,
                    "ports_count": len(ports),
                    "ports":       sorted(list(ports))[:20],  # primeros 20
                    "description": (
                        f"IP {ip} escaneó {len(ports)} puertos distintos"
                    ),
                })

        return alerts

    def detect_malware_activity(self, events: list) -> List[Dict]:
        """
        Detecta actividad de malware: intentos de upload,
        exploits conocidos, conexiones a servicios de malware.
        """
        alerts = []
        malware_events = [
            e for e in events
            if e.get("attack_type") in ("malware_upload", "exploit_attempt", "malware")
        ]

        # Agrupar por IP atacante
        by_ip: Dict[str, list] = defaultdict(list)
        for ev in malware_events:
            by_ip[ev["src_ip"]].append(ev)

        for ip, evs in by_ip.items():
            malware_names = [e["malware"] for e in evs if e.get("malware")]
            alerts.append({
                "type":        "MALWARE_ACTIVITY",
                "severity":    "CRITICAL",
                "src_ip":      ip,
                "event_count": len(evs),
                "malware_detected": list(set(malware_names)) if malware_names else [],
                "description": (
                    f"IP {ip} intentó {len(evs)} actividades de malware"
                ),
            })

        return alerts

    def analyze_all(self, events: list) -> Dict:
        """
        Ejecuta todos los detectores y devuelve un resumen completo.
        """
        bf_alerts     = self.detect_brute_force(events)
        scan_alerts   = self.detect_port_scan(events)
        malware_alerts= self.detect_malware_activity(events)

        all_alerts = bf_alerts + scan_alerts + malware_alerts

        # Estadísticas generales
        attack_counts  = Counter(e.get("attack_type", "unknown") for e in events)
        top_attackers  = Counter(e.get("src_ip", "?") for e in events).most_common(10)
        top_ports      = Counter(e.get("dst_port", 0) for e in events).most_common(10)
        def safe_hour(ts):
            """Parsea distintos formatos de timestamp y devuelve la hora."""
            ts = ts.replace("Z", "")
            # Formato ISO estándar: 2024-01-01T12:00:00
            try:
                return datetime.fromisoformat(ts).hour
            except ValueError:
                pass
            # Formato Suricata fast.log: 04/04/2026-14:51:17.646
            try:
                return datetime.strptime(ts, "%m/%d/%Y-%H:%M:%S.%f").hour
            except ValueError:
                pass
            return 0

        events_by_hour = Counter(
            safe_hour(e.get("timestamp", "2000-01-01T00:00:00"))
            for e in events
        )

        return {
            "summary": {
                "total_events":    len(events),
                "total_alerts":    len(all_alerts),
                "unique_ips":      len(set(e.get("src_ip") for e in events)),
                "attack_types":    dict(attack_counts),
                "top_attackers":   top_attackers,
                "top_ports":       top_ports,
                "events_by_hour":  dict(events_by_hour),
            },
            "alerts": all_alerts,
            "severity_count": {
                "CRITICAL": sum(1 for a in all_alerts if a.get("severity") == "CRITICAL"),
                "HIGH":     sum(1 for a in all_alerts if a.get("severity") == "HIGH"),
                "MEDIUM":   sum(1 for a in all_alerts if a.get("severity") == "MEDIUM"),
            },
        }


# ── Punto de entrada para pruebas ────────────────────────────
if __name__ == "__main__":
    import yaml

    with open("config/config.yaml") as f:
        config = yaml.safe_load(f)

    with open(config["output"]["normalized_json"]) as f:
        events = json.load(f)

    print(f"[ANALYZER] Analizando {len(events)} eventos...")
    detector = PatternDetector(config)
    results  = detector.analyze_all(events)

    print("\n── RESUMEN DE ANÁLISIS ──────────────────────────────")
    print(f"  Total eventos   : {results['summary']['total_events']}")
    print(f"  IPs únicas      : {results['summary']['unique_ips']}")
    print(f"  Alertas totales : {results['summary']['total_alerts']}")
    print(f"  Críticas        : {results['severity_count']['CRITICAL']}")
    print(f"  Altas           : {results['severity_count']['HIGH']}")
    print(f"  Medias          : {results['severity_count']['MEDIUM']}")

    print("\n── TOP ATACANTES ────────────────────────────────────")
    for ip, count in results["summary"]["top_attackers"]:
        print(f"  {ip:20s} → {count:4d} eventos")

    print("\n── ALERTAS DETECTADAS ───────────────────────────────")
    for alert in results["alerts"][:5]:
        print(f"  [{alert['severity']:8s}] {alert['type']}: {alert['description']}")
