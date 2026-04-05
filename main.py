"""
============================================================
main.py
------------------------------------------------------------
ORQUESTADOR PRINCIPAL DEL HONEYPOT PORTÁTIL
------------------------------------------------------------
¿Para qué sirve?
  Es el punto de entrada único del sistema. Coordina todos
  los módulos en el orden correcto:
  
  1. Carga configuración
  2. Recolecta y normaliza logs
  3. Analiza patrones de ataque
  4. Clasifica con Machine Learning
  5. Dispara alertas
  6. Actualiza el dashboard

  Puede correr en modo continuo (daemon) o una sola vez.
  
Uso:
  python main.py               # Ejecutar una vez
  python main.py --loop        # Modo continuo (cada 30s)
  python main.py --train-only  # Solo entrenar el modelo
  python main.py --simulate    # Generar datos simulados y analizar
============================================================
"""

import argparse
import json
import os
import sys
import time
import yaml
from datetime import datetime

# ── Agregar directorio del proyecto al path ──────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scripts.data_simulator   import write_simulated_logs
from scripts.log_collector    import collect_all_logs, save_normalized_events
from scripts.analyzer         import PatternDetector, extract_features
from scripts.alert_manager    import AlertManager, Color
from scripts.dashboard_integration import (
    ElasticsearchExporter, PrometheusExporter, local_api
)
from ml_model.model import HoneypotMLModel


# ── Banner de inicio ──────────────────────────────────────────

BANNER = f"""
{Color.CYAN}{Color.BOLD}
  ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗
  ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝
  ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║   
  ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║   
  ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║   
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝   
{Color.RESET}
{Color.DIM}  Honeypot Portátil con ML | Raspberry Pi Edition
  Para uso educativo en redes controladas{Color.RESET}
"""


# ── Cargador de configuración ────────────────────────────────

def load_config(config_path: str = "config/config.yaml") -> dict:
    """Carga y valida el archivo de configuración."""
    if not os.path.exists(config_path):
        print(f"[MAIN] ✗ No se encontró {config_path}")
        sys.exit(1)

    with open(config_path) as f:
        config = yaml.safe_load(f)

    return config


# ── Función principal de análisis ───────────────────────────

def run_analysis_cycle(config: dict, ml_model: HoneypotMLModel,
                       alert_mgr: AlertManager,
                       prom_exporter: PrometheusExporter,
                       es_exporter: ElasticsearchExporter = None) -> dict:
    """
    Ejecuta un ciclo completo de análisis:
    Recolección → Análisis → ML → Alertas → Dashboard
    
    Retorna un resumen del ciclo para logging.
    """
    cycle_start = time.time()
    print(f"\n{Color.BOLD}{'═'*60}{Color.RESET}")
    print(f"{Color.BOLD}  Ciclo de análisis: "
          f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC{Color.RESET}")
    print(f"{Color.BOLD}{'═'*60}{Color.RESET}")

    # ── FASE 1: Recolección de logs ──────────────────────────
    print(f"\n{Color.CYAN}[1/5] Recolectando logs...{Color.RESET}")
    events     = collect_all_logs(config)
    all_events = save_normalized_events(events, config["output"]["normalized_json"])

    if not all_events:
        print("[MAIN] ⚠ Sin eventos. Ejecuta con --simulate para generar datos.")
        return {}

    # ── FASE 2: Análisis de patrones ─────────────────────────
    print(f"\n{Color.CYAN}[2/5] Analizando patrones...{Color.RESET}")
    detector = PatternDetector(config)
    analysis  = detector.analyze_all(all_events)
    summary   = analysis["summary"]
    alerts    = analysis["alerts"]

    print(f"       Eventos totales  : {summary['total_events']}")
    print(f"       IPs únicas       : {summary['unique_ips']}")
    print(f"       Alertas detectadas: {len(alerts)}")

    # ── FASE 3: Machine Learning ──────────────────────────────
    print(f"\n{Color.CYAN}[3/5] Clasificando con ML...{Color.RESET}")
    features   = extract_features(all_events)
    ml_results = []

    if ml_model._models_loaded() or os.path.exists(config["ml"]["model_path"]):
        # Predecir con modelo existente
        ml_results = ml_model.predict(features)
        anomalies  = sum(1 for r in ml_results if r.get("is_anomaly"))
        print(f"       Clasificados     : {len(ml_results)} eventos")
        print(f"       Anomalías        : {anomalies}")
    else:
        # Entrenar modelo si no existe
        print("       Entrenando modelo inicial...")
        ml_model.train(features, verbose=False)
        ml_results = ml_model.predict(features)
        print(f"       Modelo entrenado y {len(ml_results)} eventos clasificados")

    # Enriquecer alertas con info de ML
    ml_by_ip = {}
    for r in ml_results:
        ml_by_ip[r.get("src_ip", "")] = r

    for alert in alerts:
        ip  = alert.get("src_ip", "")
        if ip in ml_by_ip:
            alert["ml_classification"] = ml_by_ip[ip].get("attack_type", "")
            alert["ml_confidence"]     = ml_by_ip[ip].get("confidence", 0)
            alert["is_anomaly"]        = ml_by_ip[ip].get("is_anomaly", False)

    # ── FASE 4: Alertas ───────────────────────────────────────
    print(f"\n{Color.CYAN}[4/5] Disparando alertas...{Color.RESET}")
    if alerts:
        alert_mgr.send_bulk_alerts(alerts)
    else:
        print(f"       {Color.GREEN}Sin alertas críticas en este ciclo.{Color.RESET}")

    # ── FASE 5: Dashboard / Integración ──────────────────────
    print(f"\n{Color.CYAN}[5/5] Actualizando dashboard...{Color.RESET}")

    # Actualizar API local
    local_api.update(all_events, alerts, ml_results, summary)

    # Actualizar métricas Prometheus
    prom_exporter.update_metrics(all_events, alerts, ml_results)
    prom_exporter.save_to_file("dashboard/metrics.prom")

    # Guardar resultados ML
    ml_output_path = config["output"]["ml_results"]
    os.makedirs(os.path.dirname(ml_output_path), exist_ok=True)
    with open(ml_output_path, "w") as f:
        json.dump(ml_results[-500:], f, indent=2, default=str)

    # Enviar a Elasticsearch si está configurado
    if es_exporter and config["elasticsearch"].get("enabled"):
        if es_exporter.check_connection():
            es_exporter.bulk_index(all_events[-100:])  # Últimos 100 eventos

    # ── Resumen del ciclo ─────────────────────────────────────
    elapsed = time.time() - cycle_start
    print(f"\n{Color.GREEN}  ✓ Ciclo completado en {elapsed:.2f}s{Color.RESET}")
    alert_mgr.print_summary()

    # Mostrar top atacantes
    if summary.get("top_attackers"):
        print(f"\n  {Color.BOLD}Top atacantes:{Color.RESET}")
        for ip, count in summary["top_attackers"][:5]:
            bar = "█" * min(count, 30)
            print(f"    {ip:20s} {Color.RED}{bar}{Color.RESET} {count}")

    return {
        "total_events":   summary.get("total_events", 0),
        "alerts":         len(alerts),
        "anomalies":      sum(1 for r in ml_results if r.get("is_anomaly")),
        "elapsed_sec":    round(elapsed, 2),
        "timestamp":      datetime.utcnow().isoformat() + "Z",
    }


# ── Retrain periódico ────────────────────────────────────────

def maybe_retrain(ml_model: HoneypotMLModel, config: dict,
                  features: list, last_count: int) -> int:
    """
    Re-entrena el modelo si se han acumulado suficientes
    eventos nuevos desde el último entrenamiento.
    """
    threshold = config["ml"].get("retrain_every", 500)
    current   = len(features)

    if current - last_count >= threshold:
        print(f"\n[ML] Re-entrenando modelo ({current} eventos acumulados)...")
        ml_model.train(features, verbose=False)
        return current

    return last_count


# ── Punto de entrada principal ───────────────────────────────

def main():
    print(BANNER)

    # ── Parsear argumentos ────────────────────────────────────
    parser = argparse.ArgumentParser(
        description="Honeypot Portátil con ML",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--loop",        action="store_true",
                        help="Modo continuo (actualiza cada 30s)")
    parser.add_argument("--simulate",    action="store_true",
                        help="Generar datos simulados antes de analizar")
    parser.add_argument("--train-only",  action="store_true",
                        help="Solo entrenar el modelo ML y salir")
    parser.add_argument("--interval",    type=int, default=30,
                        help="Intervalo en segundos para modo --loop (default: 30)")
    parser.add_argument("--config",      default="config/config.yaml",
                        help="Ruta al archivo de configuración")
    args = parser.parse_args()

    # ── Cargar configuración ──────────────────────────────────
    config = load_config(args.config)
    print(f"[MAIN] Configuración cargada desde {args.config}")

    # ── Inicializar componentes ───────────────────────────────
    ml_model    = HoneypotMLModel(
        os.path.dirname(config["ml"]["model_path"])
    )
    alert_mgr   = AlertManager(config)
    prom_exp    = PrometheusExporter()
    es_exp      = ElasticsearchExporter(
        host  = config["elasticsearch"]["host"],
        port  = config["elasticsearch"]["port"],
        index = config["elasticsearch"]["index"],
    ) if config["elasticsearch"].get("enabled") else None

    # ── Modo: Solo simular datos ──────────────────────────────
    if args.simulate:
        print("[MAIN] Generando datos simulados...")
        write_simulated_logs(
            cowrie_path   = config["logs"]["cowrie"],
            dionaea_path  = config["logs"]["dionaea"],
            suricata_path = config["logs"]["suricata"],
            n_events      = 500,
        )
        print("[MAIN] ✓ Datos simulados generados.")

    # ── Modo: Solo entrenar ───────────────────────────────────
    if args.train_only:
        events_path = config["output"]["normalized_json"]
        if not os.path.exists(events_path):
            print("[MAIN] ✗ No hay eventos normalizados. Corre primero con --simulate")
            sys.exit(1)
        with open(events_path) as f:
            events = json.load(f)
        features = extract_features(events)
        ml_model.train(features, verbose=True)

        print("\n[MAIN] Importancia de características:")
        for item in ml_model.feature_importance():
            bar = "█" * int(item["importance"] * 40)
            print(f"  {item['feature']:20s} {bar} {item['importance']:.4f}")
        sys.exit(0)

    # ── Modo: Un ciclo o continuo ─────────────────────────────
    last_train_count = 0

    if args.loop:
        print(f"[MAIN] Iniciando modo continuo (intervalo: {args.interval}s)")
        print(f"[MAIN] Presiona Ctrl+C para detener.\n")

        cycle = 0
        try:
            while True:
                cycle += 1
                print(f"\n[MAIN] Ciclo #{cycle}")
                result = run_analysis_cycle(
                    config, ml_model, alert_mgr, prom_exp, es_exp
                )

                # Re-entrenar periódicamente
                events_path = config["output"]["normalized_json"]
                if os.path.exists(events_path):
                    with open(events_path) as f:
                        events = json.load(f)
                    features = extract_features(events)
                    last_train_count = maybe_retrain(
                        ml_model, config, features, last_train_count
                    )

                print(f"\n[MAIN] Próximo ciclo en {args.interval}s... (Ctrl+C para salir)")
                time.sleep(args.interval)

        except KeyboardInterrupt:
            print(f"\n\n{Color.YELLOW}[MAIN] Detenido por el usuario.{Color.RESET}")
            alert_mgr.print_summary()

    else:
        # Un solo ciclo
        run_analysis_cycle(config, ml_model, alert_mgr, prom_exp, es_exp)
        print(f"\n[MAIN] Para monitoreo continuo usa: python main.py --loop")
        print(f"[MAIN] Dashboard local disponible si corres: python dashboard/server.py")


if __name__ == "__main__":
    main()
