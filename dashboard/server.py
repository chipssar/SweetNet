"""
============================================================
dashboard/server.py
------------------------------------------------------------
SERVIDOR DEL DASHBOARD LOCAL
------------------------------------------------------------
¿Para qué sirve?
  Servidor Flask que sirve la interfaz web del honeypot.
  Expone endpoints JSON que el frontend HTML consulta
  periódicamente para actualizar las gráficas.
  
  Acceso: http://localhost:5000 (o IP del Raspberry Pi)
============================================================
"""

import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from scripts.dashboard_integration import local_api, prometheus

app = Flask(__name__, static_folder="static")
CORS(app)   # Permite peticiones desde el navegador


# ── Endpoints de la API ───────────────────────────────────────

@app.route("/api/summary")
def api_summary():
    """Resumen ejecutivo: métricas principales."""
    return app.response_class(
        response=local_api.get_summary_json(),
        mimetype="application/json",
    )


@app.route("/api/events")
def api_events():
    """Últimos 100 eventos normalizados."""
    return app.response_class(
        response=local_api.get_json(),
        mimetype="application/json",
    )


@app.route("/api/metrics")
def api_metrics():
    """Métricas en formato Prometheus (para Grafana o monitoreo)."""
    return app.response_class(
        response=prometheus.generate_output(),
        mimetype="text/plain",
    )


@app.route("/api/health")
def api_health():
    """Health check del servidor."""
    return jsonify({"status": "ok", "version": "1.0.0"})


@app.route("/")
def index():
    """Sirve el dashboard HTML principal."""
    dashboard_html = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(dashboard_html):
        with open(dashboard_html) as f:
            return f.read()
    return "<h1>Dashboard no encontrado. Coloca index.html en dashboard/</h1>", 404


# ── Inicio del servidor ───────────────────────────────────────

def start_server(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    """Inicia el servidor Flask."""
    print(f"[DASHBOARD] Servidor iniciando en http://{host}:{port}")
    print(f"[DASHBOARD] Accede desde el navegador: http://localhost:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


def start_server_background(host: str = "0.0.0.0", port: int = 5000):
    """Inicia el servidor en un hilo de fondo (para usar junto con main.py)."""
    thread = threading.Thread(
        target=start_server, args=(host, port), daemon=True
    )
    thread.start()
    return thread


if __name__ == "__main__":
    start_server(debug=False)
