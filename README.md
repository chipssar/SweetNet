# 🍯 Honeypot Portátil con ML — Raspberry Pi Edition

> Sistema completo de detección y análisis de ataques en redes abiertas,  
> con Machine Learning, alertas en tiempo real y dashboard web.

---

## Índice
1. [Arquitectura del sistema](#arquitectura)
2. [Estructura del proyecto](#estructura)
3. [Instalación rápida](#instalacion)
4. [Uso del sistema](#uso)
5. [Módulos explicados](#modulos)
6. [Dashboard web](#dashboard)
7. [Integración con Kibana / Grafana](#integracion)
8. [Despliegue real en Raspberry Pi](#rpi)
9. [Flujo de datos](#flujo)

---

## 1. Arquitectura del sistema <a name="arquitectura"></a>

```
┌─────────────────────────────────────────────────────────────────┐
│                     HONEYPOT PORTÁTIL                           │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                      │
│  │  COWRIE  │  │ DIONAEA  │  │ SURICATA │  ← Honeypots / IDS   │
│  │SSH/Telnet│  │ Malware  │  │   IDS    │                      │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                      │
│       │              │              │                            │
│       └──────────────┴──────────────┘                           │
│                       │                                          │
│              ┌─────────▼──────────┐                             │
│              │  log_collector.py  │  ← Normalización            │
│              │  Normaliza y       │                             │
│              │  unifica eventos   │                             │
│              └─────────┬──────────┘                             │
│                        │                                         │
│              ┌─────────▼──────────┐                             │
│              │    analyzer.py     │  ← Análisis heurístico      │
│              │  PatternDetector   │                             │
│              │  Brute Force       │                             │
│              │  Port Scan         │                             │
│              │  Malware           │                             │
│              └──────┬──────┬──────┘                             │
│                     │      │                                     │
│            ┌────────▼┐   ┌─▼──────────────┐                    │
│            │ml_model │   │ alert_manager  │  ← Alertas         │
│            │Random   │   │ Consola/Email  │                    │
│            │Forest   │   └────────────────┘                    │
│            │Isolation│                                           │
│            │Forest   │                                           │
│            └────┬────┘                                           │
│                 │                                                 │
│    ┌────────────▼──────────────────────┐                        │
│    │       dashboard_integration       │  ← Exportación         │
│    │  Elasticsearch │ Prometheus       │                        │
│    │  API local REST                   │                        │
│    └───────────────────────────────────┘                        │
│                 │                                                 │
│    ┌────────────▼──────────────────────┐                        │
│    │     dashboard/index.html          │  ← Visualización       │
│    │  Gráficas en tiempo real          │                        │
│    │  Top atacantes / tipos de ataque  │                        │
│    └───────────────────────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

### Tecnologías usadas

| Componente         | Tecnología                              | Propósito                          |
|--------------------|-----------------------------------------|------------------------------------|
| Honeypot SSH       | Cowrie                                  | Captura credenciales y comandos    |
| Honeypot Malware   | Dionaea                                 | Captura exploits y malware         |
| IDS/IPS            | Suricata                                | Alertas por firmas de ataque       |
| Recolección        | Python + `json` + `re`                  | Normalización de logs              |
| Análisis           | Python + `collections.Counter`          | Detección heurística               |
| Machine Learning   | `scikit-learn` (RF + IsolationForest)   | Clasificación y anomalías          |
| Persistencia       | JSON local / Elasticsearch              | Almacenamiento de eventos          |
| Métricas           | Prometheus text format                  | Integración con Grafana            |
| Dashboard          | Flask + HTML/CSS/JS vanilla             | Visualización en tiempo real       |
| Alertas            | Consola ANSI + SMTP                     | Notificaciones                     |
| Despliegue         | Bash + systemd                          | Automatización                     |

---

## 2. Estructura del proyecto <a name="estructura"></a>

```
honeypot-project/
│
├── main.py                          # Orquestador principal
├── setup.sh                         # Script de instalación automática
├── requirements.txt                 # Dependencias Python
│
├── config/
│   └── config.yaml                  # Configuración central
│
├── scripts/
│   ├── data_simulator.py            # Generador de eventos de prueba
│   ├── log_collector.py             # Lector y normalizador de logs
│   ├── analyzer.py                  # Motor de análisis de patrones
│   ├── alert_manager.py             # Sistema de alertas
│   └── dashboard_integration.py    # Exportadores ES / Prometheus
│
├── ml_model/
│   ├── model.py                     # Módulo de ML (entrenamiento/predicción)
│   ├── rf_model.pkl                 # Modelo Random Forest (generado)
│   ├── isolation_forest.pkl         # Modelo Isolation Forest (generado)
│   └── scaler.pkl                   # Normalizador de features (generado)
│
├── dashboard/
│   ├── index.html                   # Dashboard web interactivo
│   ├── server.py                    # Servidor Flask para el dashboard
│   └── metrics.prom                 # Métricas Prometheus (generado)
│
├── data/
│   ├── events_normalized.json       # Base de datos de eventos (generado)
│   └── ml_results.json              # Resultados de clasificación ML (generado)
│
└── logs/
    ├── cowrie/cowrie.json           # Logs del honeypot SSH
    ├── dionaea/dionaea.json         # Logs del honeypot de malware
    ├── suricata/fast.log            # Logs del IDS Suricata
    └── alerts.json                  # Historial de alertas (generado)
```

---

## 3. Instalación rápida <a name="instalacion"></a>

### Opción A — Script automático (recomendado para Raspberry Pi)

```bash
git clone
cd honeypot-project
chmod +x setup.sh
./setup.sh
```

### Opción B — Manual

```bash
# 1. Clonar el proyecto
git clone 
cd honeypot-project

# 2. Crear entorno virtual
python3 -m venv .venv
source .venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Crear directorios
mkdir -p data logs/{cowrie,dionaea,suricata} ml_model
```

### Instalación de herramientas reales (Raspberry Pi OS)

```bash
# ── Cowrie (SSH honeypot) ────────────────────────────────────
sudo apt-get install -y git python3-virtualenv libssl-dev libffi-dev
git clone  /opt/cowrie
cd /opt/cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Redirigir SSH real al puerto 2222, honeypot en 22
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo systemctl restart sshd
bin/cowrie start

# ── Suricata (IDS) ───────────────────────────────────────────
sudo apt-get install -y suricata
sudo suricata-update
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D

# ── Dionaea (Malware honeypot) ───────────────────────────────
sudo apt-get install -y dionaea
sudo systemctl start dionaea
```

---

## 4. Uso del sistema <a name="uso"></a>

```bash
# Activar el entorno virtual
source .venv/bin/activate

# ── Flujo recomendado para la primera vez ─────────────────────

# Paso 1: Generar datos de prueba (sin tráfico real)
python main.py --simulate

# Paso 2: Entrenar el modelo ML
python main.py --train-only

# Paso 3: Ejecutar un ciclo completo
python main.py

# Paso 4: Monitoreo continuo (cada 30 segundos)
python main.py --loop --interval 30

# Paso 5: Abrir el dashboard
python dashboard/server.py
# → Abrir http://localhost:5000 en el navegador

# ── Comandos adicionales ──────────────────────────────────────

# Ver ayuda
python main.py --help

# Cambiar intervalo de actualización
python main.py --loop --interval 60

# Usar configuración personalizada
python main.py --config config/mi_config.yaml
```

---

## 5. Módulos explicados <a name="modulos"></a>

### `data_simulator.py` — Generador de datos

Crea eventos realistas sin necesitar tráfico real. Imprescindible para:
- Probar el sistema en laboratorio
- Entrenar el modelo ML
- Demostrar el funcionamiento

Genera tres tipos de campañas:
- **Eventos aleatorios**: tráfico variado normal
- **Campaña de fuerza bruta**: misma IP, muchos intentos seguidos
- **Escaneo de puertos**: una IP toca 20+ puertos

### `log_collector.py` — Recolector

Lee los tres formatos de log y los normaliza a este esquema unificado:

```json
{
  "id":          "a1b2c3d4e5f6",
  "timestamp":   "2024-01-15T12:30:00Z",
  "source":      "cowrie",
  "src_ip":      "192.168.1.100",
  "dst_port":    22,
  "protocol":    "ssh",
  "attack_type": "brute_force",
  "username":    "root",
  "password":    "admin123",
  "command":     null,
  "malware":     null
}
```

### `analyzer.py` — Motor de análisis

Detecta patrones con reglas heurísticas:

| Detector             | Condición de disparo                            | Severidad |
|----------------------|-------------------------------------------------|-----------|
| `detect_brute_force` | ≥5 intentos de login desde la misma IP en 60s  | HIGH      |
| `detect_port_scan`   | ≥20 puertos distintos desde la misma IP         | MEDIUM    |
| `detect_malware`     | Cualquier evento con malware o exploit          | CRITICAL  |

También extrae **10 features numéricas** por evento para el modelo ML:

```
dst_port, src_ip_oct3, src_ip_oct4, protocol_num,
hour_of_day, has_credentials, has_command,
has_malware, payload_size, source_num
```

### `ml_model/model.py` — Machine Learning

**Modelo 1 — Random Forest (clasificación supervisada)**
- Aprende de eventos etiquetados
- Predice el tipo de ataque con porcentaje de confianza
- 9 clases: Fuerza Bruta, Port Scan, Malware, Exploit, Acceso No Autorizado,
  Ejecución de Comandos, DoS, Sondeo, Alerta IDS

**Modelo 2 — Isolation Forest (detección de anomalías)**
- No necesita etiquetas (no supervisado)
- Detecta eventos rarísimos/inusuales
- Equivale a "esto no parece nada que hayamos visto antes"

**Métricas obtenidas en pruebas:**
```
Accuracy Random Forest:    ~62% (con datos simulados)
Anomalías detectadas:      ~10% del dataset
Ciclo de análisis:         < 0.5s (Raspberry Pi 4)
```

### `alert_manager.py` — Alertas

Soporta dos canales configurables en `config.yaml`:

```yaml
alerts:
  console: true        # Alertas en consola con colores ANSI
  email:   false       # Para habilitar: cambiar a true y configurar SMTP
  smtp_server:   "smtp.gmail.com"
  smtp_port:     587
  smtp_user:     "tu_email@gmail.com"
  smtp_password: "app_password_de_google"
  recipient:     "admin@tu-empresa.com"
```

---

## 6. Dashboard web <a name="dashboard"></a>

El dashboard se sirve en `http://localhost:5000` (o IP del Raspberry Pi).

**Características:**
- Auto-refresh cada 30 segundos
- KPIs en tiempo real (eventos, alertas, IPs, anomalías)
- Feed de eventos en vivo con badges de tipo de ataque
- Panel de alertas activas con severidad
- Gráfica de barras de tipos de ataque
- Top 6 atacantes con barra de actividad
- Funciona en modo DEMO sin servidor (datos simulados en JS)

**Para acceder desde otro dispositivo en la misma red:**
```bash
# El servidor escucha en 0.0.0.0 por defecto
python dashboard/server.py
# Acceder desde tablet/laptop en la misma WiFi:
# http://192.168.X.X:5000
```

---

## 7. Integración con Kibana / Grafana <a name="integracion"></a>

### Elasticsearch + Kibana

```yaml
# config/config.yaml
elasticsearch:
  enabled: true
  host:    "localhost"
  port:    9200
  index:   "honeypot-events"
```

```bash
# Levantar con Docker
docker run -d --name elasticsearch \
  -p 9200:9200 -e "discovery.type=single-node" \
  elasticsearch:8.0.0

docker run -d --name kibana \
  -p 5601:5601 --link elasticsearch \
  kibana:8.0.0

# Acceder a Kibana: http://localhost:5601
# Crear Data View: índice "honeypot-events"
```

### Prometheus + Grafana

```bash
# El sistema exporta métricas en:
# dashboard/metrics.prom  (archivo)
# http://localhost:5000/api/metrics  (endpoint HTTP)

# Instalar Prometheus (apunta al endpoint)
# Instalar Grafana y crear dashboard con las métricas:
#   honeypot_attacks_total{type="brute_force"}
#   honeypot_alerts_total{severity="CRITICAL"}
#   honeypot_anomalies_detected
#   honeypot_top_attacker_events{ip="..."}
```

---

## 8. Despliegue real en Raspberry Pi <a name="rpi"></a>

```bash
# ── Hardware recomendado ─────────────────────────────────────
# Raspberry Pi 4 (2GB RAM mínimo, 4GB recomendado)
# MicroSD 32GB clase 10
# Adaptador WiFi USB (para monitorear red WiFi pública)

# ── Configurar modo monitor WiFi ────────────────────────────
sudo airmon-ng start wlan0      # Activa modo monitor
sudo iwconfig wlan0mon          # Verificar interfaz

# ── Configurar IP estática ───────────────────────────────────
# /etc/dhcpcd.conf:
# interface eth0
# static ip_address=192.168.1.50/24

# ── Servicio systemd (inicio automático) ─────────────────────
sudo nano /etc/systemd/system/honeypot.service
```

```ini
[Unit]
Description=Honeypot Portátil
After=network-online.target

[Service]
User=pi
WorkingDirectory=/home/pi/honeypot-project
ExecStart=/home/pi/honeypot-project/.venv/bin/python main.py --loop
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable honeypot
sudo systemctl start honeypot
sudo journalctl -u honeypot -f   # Ver logs en tiempo real
```

---

## 9. Flujo de datos <a name="flujo"></a>

```
Atacante en red WiFi pública
        │
        ▼
[Puerto 22] → Cowrie captura credenciales y comandos
[Puerto 445] → Dionaea captura exploits SMB
[Todo el tráfico] → Suricata analiza paquetes
        │
        ▼
log_collector.py
  - Lee los tres archivos de log
  - Normaliza al esquema JSON unificado
  - Elimina duplicados
  - Guarda en data/events_normalized.json
        │
        ▼
analyzer.py
  - PatternDetector busca patrones
  - Extrae features numéricas
  - Genera alertas de tipo CRITICAL/HIGH/MEDIUM
        │
        ├──► alert_manager.py → Consola / Email
        │
        ▼
ml_model/model.py
  - Random Forest → clasifica tipo de ataque
  - Isolation Forest → detecta anomalías raras
  - Devuelve {tipo, confianza, is_anomaly}
        │
        ▼
dashboard_integration.py
  - Actualiza API local REST (:5000/api/*)
  - Escribe metrics.prom (Prometheus)
  - Envía a Elasticsearch (si habilitado)
        │
        ▼
dashboard/index.html
  - Consulta /api/events cada 30s
  - Muestra KPIs, feed de eventos, alertas
  - Visualiza top atacantes y tipos de ataque
```

---

## Consideraciones de seguridad

> ⚠️ **IMPORTANTE**: Este sistema es para uso educativo en redes controladas.  
> No desplegar en producción sin revisión de seguridad adicional.

- Ejecutar con usuario sin privilegios de root
- El dashboard no tiene autenticación por defecto — no exponer a internet
- Los logs pueden contener credenciales reales — tratar como datos sensibles
- El honeypot atrae ataques reales cuando se despliega en redes públicas
- Revisar la legislación local antes de desplegar

---

## Créditos

Herramientas de terceros usadas en despliegue real:
- [Cowrie](https://github.com/cowrie/cowrie) — SSH/Telnet Honeypot
- [Dionaea](https://github.com/DinoTools/dionaea) — Malware Honeypot  
- [Suricata](https://suricata.io/) — Network IDS/IPS
- [scikit-learn](https://scikit-learn.org/) — Machine Learning
