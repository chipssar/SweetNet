#!/bin/bash
# ============================================================
# setup.sh — Script de automatización del Honeypot Portátil
# ============================================================
# ¿Para qué sirve?
#   Instala y configura todo el sistema con un solo comando.
#   Pensado para Raspberry Pi OS (Debian/Ubuntu).
#
# Uso:
#   chmod +x setup.sh
#   ./setup.sh              # Instalar todo
#   ./setup.sh --run        # Instalar y ejecutar
#   ./setup.sh --simulate   # Instalar, simular y analizar
# ============================================================

set -e  # Detener si ocurre algún error

# ── Colores ──────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; BLD='\033[1m';    RST='\033[0m'

print_header() { echo -e "\n${CYN}${BLD}══ $1 ══${RST}"; }
print_ok()     { echo -e "  ${GRN}✓${RST} $1"; }
print_warn()   { echo -e "  ${YEL}⚠${RST} $1"; }
print_err()    { echo -e "  ${RED}✗${RST} $1"; }
print_step()   { echo -e "\n${BLD}[$1]${RST} $2"; }

# ── Banner ───────────────────────────────────────────────────
echo -e "${CYN}"
echo "  ┌─────────────────────────────────────────┐"
echo "  │   HONEYPOT PORTÁTIL - Setup Script       │"
echo "  │   Raspberry Pi / Debian / Ubuntu         │"
echo "  └─────────────────────────────────────────┘"
echo -e "${RST}"

# ── Variables ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON="python3"
PIP="pip3"
RUN_MODE=""
SIMULATE=false

# ── Parsear argumentos ────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --run)      RUN_MODE="run";      shift ;;
        --simulate) SIMULATE=true;       shift ;;
        --loop)     RUN_MODE="loop";     shift ;;
        --help|-h)
            echo "Uso: ./setup.sh [--run] [--simulate] [--loop]"
            echo "  --run       Ejecuta el honeypot tras instalar"
            echo "  --simulate  Genera datos de prueba"
            echo "  --loop      Modo monitoreo continuo"
            exit 0
            ;;
    esac
done

# ── 1. Verificar sistema operativo ────────────────────────────
print_header "VERIFICANDO SISTEMA"

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    print_ok "Sistema Linux detectado"
    # Detectar si es Raspberry Pi
    if grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
        print_ok "Raspberry Pi detectado 🍓"
        RPI=true
    else
        RPI=false
    fi
else
    print_warn "Sistema no Linux. Algunas funciones pueden no estar disponibles."
fi

# ── 2. Verificar Python ──────────────────────────────────────
print_header "VERIFICANDO PYTHON"

if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1)
    print_ok "Python encontrado: $PY_VER"
else
    print_err "Python3 no encontrado. Instalando..."
    sudo apt-get update -qq
    sudo apt-get install -y python3 python3-pip python3-venv
fi

# Verificar versión mínima (3.8)
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PY_MINOR" -lt 8 ]; then
    print_err "Se requiere Python 3.8+. Versión actual: 3.$PY_MINOR"
    exit 1
fi

# ── 3. Instalar dependencias del sistema ──────────────────────
print_header "DEPENDENCIAS DEL SISTEMA"
print_step "3/7" "Instalando paquetes del sistema..."

# Solo si tenemos apt (Debian/Ubuntu/Raspberry Pi OS)
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq 2>/dev/null || print_warn "No se pudo actualizar apt"
    sudo apt-get install -y \
        python3-dev \
        python3-venv \
        build-essential \
        libssl-dev \
        libffi-dev \
        git \
        curl \
        --no-install-recommends \
        2>/dev/null && print_ok "Paquetes del sistema instalados" \
        || print_warn "Algunos paquetes no se pudieron instalar"
fi

# ── 4. Crear entorno virtual Python ──────────────────────────
print_header "ENTORNO VIRTUAL PYTHON"
print_step "4/7" "Creando virtualenv en $VENV_DIR..."

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    print_ok "Virtualenv creado"
else
    print_ok "Virtualenv ya existe"
fi

# Activar virtualenv
source "$VENV_DIR/bin/activate"
print_ok "Virtualenv activado"

# Actualizar pip
pip install --quiet --upgrade pip
print_ok "pip actualizado"

# ── 5. Instalar dependencias Python ──────────────────────────
print_header "DEPENDENCIAS PYTHON"
print_step "5/7" "Instalando paquetes desde requirements.txt..."

if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
    print_ok "Dependencias instaladas"
else
    print_warn "No se encontró requirements.txt"
    # Instalar lo mínimo indispensable
    pip install --quiet scikit-learn numpy pandas joblib rich flask flask-cors python-dateutil watchdog pyyaml
    print_ok "Dependencias mínimas instaladas"
fi

# ── 6. Crear estructura de directorios ────────────────────────
print_header "ESTRUCTURA DE DIRECTORIOS"
print_step "6/7" "Creando directorios del proyecto..."

mkdir -p "$SCRIPT_DIR"/{data,logs/{cowrie,dionaea,suricata},ml_model,config,dashboard}
print_ok "Directorios creados"

# Crear archivos de log vacíos si no existen
touch "$SCRIPT_DIR/logs/cowrie/cowrie.json"
touch "$SCRIPT_DIR/logs/dionaea/dionaea.json"
touch "$SCRIPT_DIR/logs/suricata/fast.log"
print_ok "Archivos de log inicializados"

# ── 7. Verificar instalación ──────────────────────────────────
print_header "VERIFICACIÓN FINAL"
print_step "7/7" "Verificando módulos instalados..."

python3 -c "
import sklearn, numpy, pandas, flask, yaml, rich
print('  ✓ scikit-learn:', sklearn.__version__)
print('  ✓ numpy:', numpy.__version__)
print('  ✓ pandas:', pandas.__version__)
print('  ✓ flask:', flask.__version__)
print('  ✓ pyyaml, rich: OK')
"

print_ok "Verificación completada"

# ── 8. Configurar inicio automático (systemd) ─────────────────
if command -v systemctl &>/dev/null && [ "$RPI" = true ]; then
    echo ""
    read -p "  ¿Configurar inicio automático al arrancar? [s/N]: " AUTO_START
    if [[ "$AUTO_START" =~ ^[Ss]$ ]]; then
        SERVICE_FILE="/etc/systemd/system/honeypot.service"
        sudo bash -c "cat > $SERVICE_FILE" << SVCEOF
[Unit]
Description=Honeypot Portátil
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$SCRIPT_DIR
ExecStart=$VENV_DIR/bin/python $SCRIPT_DIR/main.py --loop
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF
        sudo systemctl daemon-reload
        sudo systemctl enable honeypot.service
        print_ok "Servicio systemd configurado (honeypot.service)"
        print_ok "Iniciará automáticamente al arrancar"
    fi
fi

# ── Resumen final ─────────────────────────────────────────────
echo ""
echo -e "${GRN}${BLD}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║     ✓ INSTALACIÓN COMPLETADA               ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${RST}"
echo ""
echo -e "  ${BLD}Comandos disponibles:${RST}"
echo -e "  ${CYN}source .venv/bin/activate${RST}               Activar entorno"
echo -e "  ${CYN}python main.py --simulate${RST}               Generar datos de prueba"
echo -e "  ${CYN}python main.py --train-only${RST}             Entrenar modelo ML"
echo -e "  ${CYN}python main.py --loop --interval 30${RST}     Monitoreo continuo"
echo -e "  ${CYN}python dashboard/server.py${RST}              Dashboard en localhost:5000"
echo ""
echo -e "  ${BLD}Flujo recomendado para primera vez:${RST}"
echo -e "  ${YEL}1.${RST} python main.py --simulate    (generar datos)"
echo -e "  ${YEL}2.${RST} python main.py --train-only  (entrenar ML)"
echo -e "  ${YEL}3.${RST} python main.py --loop         (monitoreo)"
echo -e "  ${YEL}4.${RST} python dashboard/server.py   (abrir :5000)"
echo ""

# ── Ejecutar si se pidió ──────────────────────────────────────
if [ "$SIMULATE" = true ]; then
    echo -e "${CYN}Generando datos simulados...${RST}"
    source "$VENV_DIR/bin/activate"
    cd "$SCRIPT_DIR"
    python3 main.py --simulate
fi

if [ "$RUN_MODE" = "run" ]; then
    echo -e "${CYN}Iniciando honeypot (una vez)...${RST}"
    source "$VENV_DIR/bin/activate"
    cd "$SCRIPT_DIR"
    python3 main.py --simulate
    python3 main.py

elif [ "$RUN_MODE" = "loop" ]; then
    echo -e "${CYN}Iniciando honeypot en modo continuo...${RST}"
    source "$VENV_DIR/bin/activate"
    cd "$SCRIPT_DIR"
    python3 main.py --simulate
    python3 main.py --loop
fi
