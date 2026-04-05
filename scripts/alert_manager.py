"""
============================================================
scripts/alert_manager.py
------------------------------------------------------------
SISTEMA DE ALERTAS
------------------------------------------------------------
¿Para qué sirve?
  Notifica al operador cuando se detectan amenazas.
  Soporta:
    - Alertas en consola (con colores)
    - Alertas por email (SMTP)
    - Log de alertas en archivo JSON
============================================================
"""

import json
import os
import smtplib
import socket
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ── Colores ANSI para consola ────────────────────────────────
class Color:
    RESET    = "\033[0m"
    RED      = "\033[91m"
    YELLOW   = "\033[93m"
    GREEN    = "\033[92m"
    CYAN     = "\033[96m"
    MAGENTA  = "\033[95m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"


SEVERITY_COLORS = {
    "CRITICAL": Color.RED    + Color.BOLD,
    "HIGH":     Color.RED,
    "MEDIUM":   Color.YELLOW,
    "LOW":      Color.CYAN,
    "INFO":     Color.GREEN,
}

SEVERITY_ICONS = {
    "CRITICAL": "🚨",
    "HIGH":     "⚠️ ",
    "MEDIUM":   "⚡",
    "LOW":      "ℹ️ ",
    "INFO":     "✅",
}


class AlertManager:
    """
    Gestiona el envío de alertas por múltiples canales.
    Mantiene un historial de alertas enviadas para
    evitar duplicados y tener trazabilidad.
    """

    def __init__(self, config: dict):
        self.config         = config
        self.alert_config   = config.get("alerts", {})
        self.alert_log_path = "logs/alerts.json"
        self.alerts_history = []

        # Cargar historial previo si existe
        if os.path.exists(self.alert_log_path):
            try:
                with open(self.alert_log_path) as f:
                    self.alerts_history = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                self.alerts_history = []

    def send_alert(self, alert: dict):
        """
        Envía una alerta por todos los canales configurados.
        """
        # Agregar timestamp y hostname al alert
        alert["detected_at"] = datetime.utcnow().isoformat() + "Z"
        alert["sensor"]      = socket.gethostname()

        # Guardar en historial
        self.alerts_history.append(alert)
        self._save_alert_log()

        # Enviar por los canales habilitados
        if self.alert_config.get("console", True):
            self._console_alert(alert)

        if self.alert_config.get("email", False):
            self._email_alert(alert)

    def send_bulk_alerts(self, alerts: list):
        """
        Envía múltiples alertas (resultado del análisis completo).
        Las agrupa para evitar spam en el email.
        """
        if not alerts:
            return

        # Mostrar en consola una por una
        if self.alert_config.get("console", True):
            print(f"\n{Color.BOLD}{'─'*60}{Color.RESET}")
            print(f"{Color.BOLD}  🔔 {len(alerts)} ALERTAS DETECTADAS{Color.RESET}")
            print(f"{Color.BOLD}{'─'*60}{Color.RESET}")

            for alert in alerts:
                self._console_alert(alert)

        # Email: un solo mensaje con todas las alertas
        if self.alert_config.get("email", False):
            self._bulk_email_alert(alerts)

        # Guardar todas
        for alert in alerts:
            alert["detected_at"] = datetime.utcnow().isoformat() + "Z"
            alert["sensor"]      = socket.gethostname()
        self.alerts_history.extend(alerts)
        self._save_alert_log()

    def _console_alert(self, alert: dict):
        """
        Imprime alerta en consola con formato y colores.
        """
        severity = alert.get("severity", "INFO")
        color    = SEVERITY_COLORS.get(severity, Color.RESET)
        icon     = SEVERITY_ICONS.get(severity, "  ")

        print(
            f"\n{color}{icon} [{severity:8s}] {alert.get('type', 'ALERT')}{Color.RESET}\n"
            f"  {Color.DIM}Tiempo : {alert.get('detected_at', 'N/A')}{Color.RESET}\n"
            f"  IP     : {Color.CYAN}{alert.get('src_ip', 'N/A')}{Color.RESET}\n"
            f"  Detalle: {alert.get('description', 'N/A')}"
        )

        # Información adicional según tipo
        if alert.get("count"):
            print(f"  Intentos : {alert['count']} en {alert.get('window_sec',0)}s")
        if alert.get("ports"):
            ports_str = ", ".join(str(p) for p in alert["ports"][:8])
            print(f"  Puertos  : {ports_str}{'...' if len(alert.get('ports',[])) > 8 else ''}")
        if alert.get("malware_detected"):
            print(f"  Malware  : {', '.join(alert['malware_detected'])}")

    def _email_alert(self, alert: dict):
        """
        Envía un email con la alerta individual.
        """
        try:
            cfg = self.alert_config
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[HONEYPOT] {alert.get('severity','')} - {alert.get('type','')}"
            msg["From"]    = cfg.get("smtp_user", "")
            msg["To"]      = cfg.get("recipient", "")

            # Cuerpo del email en texto plano
            body = (
                f"ALERTA DE HONEYPOT\n"
                f"{'='*40}\n"
                f"Tipo     : {alert.get('type','N/A')}\n"
                f"Severidad: {alert.get('severity','N/A')}\n"
                f"IP origen: {alert.get('src_ip','N/A')}\n"
                f"Detalle  : {alert.get('description','N/A')}\n"
                f"Tiempo   : {alert.get('detected_at','N/A')}\n"
            )
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
                server.starttls()
                server.login(cfg["smtp_user"], cfg["smtp_password"])
                server.sendmail(cfg["smtp_user"], cfg["recipient"], msg.as_string())

            print(f"[ALERTS] ✓ Email enviado a {cfg['recipient']}")

        except Exception as e:
            print(f"[ALERTS] ✗ Error enviando email: {e}")

    def _bulk_email_alert(self, alerts: list):
        """
        Envía un resumen de múltiples alertas en un solo email.
        """
        try:
            cfg  = self.alert_config
            body = f"RESUMEN DE ALERTAS - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC\n"
            body += "=" * 50 + "\n\n"

            # Agrupar por severidad
            for severity in ("CRITICAL", "HIGH", "MEDIUM"):
                group = [a for a in alerts if a.get("severity") == severity]
                if group:
                    body += f"[{severity}] - {len(group)} alertas\n"
                    for a in group:
                        body += f"  • {a.get('type','')} desde {a.get('src_ip','?')}: "
                        body += f"{a.get('description','')}\n"
                    body += "\n"

            msg             = MIMEMultipart()
            msg["Subject"]  = f"[HONEYPOT] {len(alerts)} alertas detectadas"
            msg["From"]     = cfg.get("smtp_user", "")
            msg["To"]       = cfg.get("recipient", "")
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
                server.starttls()
                server.login(cfg["smtp_user"], cfg["smtp_password"])
                server.sendmail(cfg["smtp_user"], cfg["recipient"], msg.as_string())

        except Exception as e:
            print(f"[ALERTS] ✗ Error enviando email masivo: {e}")

    def _save_alert_log(self):
        """
        Persiste el historial de alertas en un archivo JSON.
        Útil para revisión posterior y generación de reportes.
        """
        os.makedirs(os.path.dirname(self.alert_log_path), exist_ok=True)
        with open(self.alert_log_path, "w") as f:
            json.dump(self.alerts_history[-1000:], f, indent=2)  # Máx 1000 alertas

    def get_recent_alerts(self, n: int = 20) -> list:
        """Devuelve las N alertas más recientes."""
        return self.alerts_history[-n:]

    def print_summary(self):
        """Imprime un resumen del historial de alertas."""
        total = len(self.alerts_history)
        if total == 0:
            print("[ALERTS] No hay alertas registradas.")
            return

        critical = sum(1 for a in self.alerts_history if a.get("severity") == "CRITICAL")
        high     = sum(1 for a in self.alerts_history if a.get("severity") == "HIGH")
        medium   = sum(1 for a in self.alerts_history if a.get("severity") == "MEDIUM")

        print(f"\n[ALERTS] Historial: {total} total | "
              f"{Color.RED}{critical} críticas{Color.RESET} | "
              f"{Color.YELLOW}{high} altas{Color.RESET} | "
              f"{Color.CYAN}{medium} medias{Color.RESET}")
