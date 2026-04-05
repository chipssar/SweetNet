"""
============================================================
scripts/dashboard_integration.py
------------------------------------------------------------
INTEGRACIÓN CON DASHBOARDS EXTERNOS
------------------------------------------------------------
¿Para qué sirve?
  Envía los eventos y métricas procesados a sistemas
  de visualización externos:
  
  - Elasticsearch + Kibana:
    Almacena eventos como documentos JSON indexados.
    Kibana los visualiza en dashboards interactivos.
    
  - Prometheus + Grafana:
    Expone métricas numéricas en formato texto plano.
    Grafana las grafica en tiempo real.
    
  - Dashboard local (Flask):
    Servidor web ligero incluido en el sistema.
    No requiere instalación adicional.
============================================================
"""

import json
import os
import time
import threading
from datetime import datetime
from collections import Counter
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request
from urllib.error import URLError


# ──────────────────────────────────────────────────────────────
# MÓDULO 1: Integración con Elasticsearch
# ──────────────────────────────────────────────────────────────

class ElasticsearchExporter:
    """
    Envía eventos al índice de Elasticsearch.
    
    Elasticsearch almacena documentos JSON en índices.
    Kibana luego los consulta para mostrar gráficas y tablas.
    
    Requisito: tener Elasticsearch corriendo en localhost:9200
    Instalación rápida: docker run -p 9200:9200 elasticsearch:8.0.0
    """

    def __init__(self, host: str = "localhost", port: int = 9200,
                 index: str = "honeypot-events"):
        self.base_url = f"http://{host}:{port}"
        self.index    = index

    def check_connection(self) -> bool:
        """Verifica si Elasticsearch está disponible."""
        try:
            req = Request(f"{self.base_url}/_cluster/health")
            resp = urlopen(req, timeout=3)
            data = json.loads(resp.read())
            status = data.get("status", "red")
            print(f"[ES] Elasticsearch status: {status}")
            return status in ("green", "yellow")
        except (URLError, Exception) as e:
            print(f"[ES] ✗ No se puede conectar a Elasticsearch: {e}")
            return False

    def create_index_mapping(self):
        """
        Crea el índice con el mapping correcto.
        Mapping = esquema de campos (similar a esquema SQL).
        """
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp":    {"type": "date"},
                    "src_ip":       {"type": "ip"},
                    "dst_port":     {"type": "integer"},
                    "protocol":     {"type": "keyword"},
                    "attack_type":  {"type": "keyword"},
                    "source":       {"type": "keyword"},
                    "username":     {"type": "keyword"},
                    "is_anomaly":   {"type": "boolean"},
                    "confidence":   {"type": "float"},
                }
            }
        }

        try:
            data = json.dumps(mapping).encode("utf-8")
            req  = Request(
                f"{self.base_url}/{self.index}",
                data=data,
                method="PUT",
                headers={"Content-Type": "application/json"},
            )
            urlopen(req)
            print(f"[ES] ✓ Índice '{self.index}' creado/verificado")
        except Exception as e:
            # El índice puede ya existir (error 400), está bien
            if "400" not in str(e):
                print(f"[ES] ⚠ Error creando índice: {e}")

    def index_event(self, event: dict) -> bool:
        """
        Envía un evento individual a Elasticsearch.
        Equivale a hacer INSERT en una base de datos SQL.
        """
        try:
            doc  = json.dumps(event, default=str).encode("utf-8")
            req  = Request(
                f"{self.base_url}/{self.index}/_doc/{event.get('id', '')}",
                data=doc,
                method="PUT",
                headers={"Content-Type": "application/json"},
            )
            urlopen(req)
            return True
        except Exception as e:
            print(f"[ES] ✗ Error indexando evento: {e}")
            return False

    def bulk_index(self, events: list) -> int:
        """
        Envía múltiples eventos de una vez (más eficiente).
        La API bulk de ES acepta múltiples documentos en una request.
        """
        if not events:
            return 0

        # Formato bulk: línea de metadata + línea de datos
        bulk_body = ""
        for ev in events:
            meta = json.dumps({"index": {"_index": self.index,
                                         "_id": ev.get("id", "")}})
            doc  = json.dumps(ev, default=str)
            bulk_body += meta + "\n" + doc + "\n"

        try:
            data = bulk_body.encode("utf-8")
            req  = Request(
                f"{self.base_url}/_bulk",
                data=data,
                method="POST",
                headers={"Content-Type": "application/x-ndjson"},
            )
            urlopen(req)
            print(f"[ES] ✓ {len(events)} eventos indexados en Elasticsearch")
            return len(events)
        except Exception as e:
            print(f"[ES] ✗ Error en bulk index: {e}")
            return 0


# ──────────────────────────────────────────────────────────────
# MÓDULO 2: Exportador de métricas Prometheus
# ──────────────────────────────────────────────────────────────

class PrometheusExporter:
    """
    Genera métricas en formato Prometheus (texto plano).
    
    Prometheus hace "scraping" (consulta) periódico a este
    endpoint y almacena las métricas. Grafana las grafica.
    
    Formato Prometheus:
      # HELP metric_name Descripción
      # TYPE metric_name gauge
      metric_name{label="value"} 42
    """

    def __init__(self):
        self.metrics = {}  # nombre → {labels → valor}

    def update_metrics(self, events: list, alerts: list, ml_results: list):
        """
        Calcula y actualiza todas las métricas del sistema.
        """
        # ── Contar por tipo de ataque ─────────────────────────
        attack_counts = Counter(e.get("attack_type", "unknown") for e in events)
        self.metrics["honeypot_attacks_total"] = {
            f'{{type="{k}"}}': v for k, v in attack_counts.items()
        }

        # ── Contar por fuente (honeypot) ──────────────────────
        source_counts = Counter(e.get("source", "unknown") for e in events)
        self.metrics["honeypot_events_by_source"] = {
            f'{{source="{k}"}}': v for k, v in source_counts.items()
        }

        # ── Top 5 IPs atacantes ───────────────────────────────
        top_ips = Counter(e.get("src_ip", "?") for e in events).most_common(5)
        self.metrics["honeypot_top_attacker_events"] = {
            f'{{ip="{ip}"}}': count for ip, count in top_ips
        }

        # ── Alertas por severidad ─────────────────────────────
        alert_counts = Counter(a.get("severity", "UNKNOWN") for a in alerts)
        self.metrics["honeypot_alerts_total"] = {
            f'{{severity="{k}"}}': v for k, v in alert_counts.items()
        }

        # ── Métricas simples (gauge) ──────────────────────────
        n_anomalies = sum(1 for r in ml_results if r.get("is_anomaly"))
        avg_conf    = (sum(r.get("confidence", 0) for r in ml_results) /
                       max(len(ml_results), 1))

        self.metrics["honeypot_total_events"]       = {"": len(events)}
        self.metrics["honeypot_anomalies_detected"] = {"": n_anomalies}
        self.metrics["honeypot_ml_avg_confidence"]  = {"": round(avg_conf, 4)}

    def generate_output(self) -> str:
        """
        Genera el texto en formato Prometheus.
        Este es el texto que Prometheus leerá periódicamente.
        """
        lines = [
            "# Honeypot Portátil - Métricas del sistema",
            f"# Generado: {datetime.utcnow().isoformat()}Z",
            "",
        ]

        for metric_name, labels_dict in self.metrics.items():
            lines.append(f"# TYPE {metric_name} gauge")
            for label_str, value in labels_dict.items():
                lines.append(f"{metric_name}{label_str} {value}")
            lines.append("")

        return "\n".join(lines)

    def save_to_file(self, path: str = "dashboard/metrics.prom"):
        """Guarda las métricas en archivo (alternativa al endpoint HTTP)."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(self.generate_output())


# ──────────────────────────────────────────────────────────────
# MÓDULO 3: API REST local (para el dashboard Flask)
# ──────────────────────────────────────────────────────────────

class LocalDashboardAPI:
    """
    Servidor HTTP minimalista que expone los datos del honeypot
    como una API JSON. El dashboard HTML la consume para
    actualizar los gráficos en tiempo real.
    
    No requiere Flask si se prefiere algo más ligero.
    """

    def __init__(self):
        self.data = {
            "events":     [],
            "alerts":     [],
            "ml_results": [],
            "summary":    {},
            "updated_at": "",
        }

    def update(self, events: list, alerts: list,
               ml_results: list, summary: dict):
        """Actualiza el estado interno con los últimos datos."""
        self.data = {
            "events":     events[-100:],    # Últimos 100
            "alerts":     alerts[-50:],     # Últimas 50
            "ml_results": ml_results[-100:],
            "summary":    summary,
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }

    def get_json(self) -> str:
        """Serializa el estado a JSON."""
        return json.dumps(self.data, default=str, indent=2)

    def get_summary_json(self) -> str:
        """Solo el resumen (para polling rápido)."""
        return json.dumps({
            "summary":    self.data["summary"],
            "alerts":     self.data["alerts"][-10:],
            "updated_at": self.data["updated_at"],
        }, default=str)


# Instancia global que el main.py puede usar
local_api = LocalDashboardAPI()
prometheus = PrometheusExporter()


# ── Punto de entrada ─────────────────────────────────────────
if __name__ == "__main__":
    print("[DASHBOARD] Módulo de integración cargado.")
    print("[DASHBOARD] Usa ElasticsearchExporter para enviar a Kibana.")
    print("[DASHBOARD] Usa PrometheusExporter para enviar a Grafana.")
