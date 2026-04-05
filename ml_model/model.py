"""
============================================================
ml_model/model.py
------------------------------------------------------------
MÓDULO DE MACHINE LEARNING
------------------------------------------------------------
¿Para qué sirve?
  Entrena dos modelos complementarios:

  1. Random Forest (supervisado):
     Aprende de ejemplos etiquetados para clasificar
     el tipo de ataque: fuerza bruta, escaneo, malware, etc.
     → Como un detective que aprende de casos anteriores.

  2. Isolation Forest (no supervisado - detección de anomalías):
     Detecta eventos raros/inusuales sin necesitar etiquetas.
     → Como un guardián que detecta comportamiento extraño.

Flujo:
  features.json ──► [Entrenamiento] ──► rf_model.pkl + scaler.pkl
                                       ↓
  nuevo_evento  ──► [Predicción]   ──► {tipo, confianza, anomalía}
============================================================
"""

import json
import os
import sys
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix


# ── Nombres de las clases (etiquetas numéricas → texto) ──────
ATTACK_LABELS = {
    0: "Fuerza Bruta",
    1: "Escaneo de Puertos",
    2: "Malware",
    3: "Exploit",
    4: "Acceso No Autorizado",
    5: "Ejecución de Comandos",
    6: "DoS / Flood",
    7: "Sondeo de Servicio",
    8: "Alerta IDS",
    9: "Desconocido",
}

# ── Columnas que entran al modelo (features) ─────────────────
FEATURE_COLUMNS = [
    "dst_port",
    "src_ip_oct3",
    "src_ip_oct4",
    "protocol_num",
    "hour_of_day",
    "has_credentials",
    "has_command",
    "has_malware",
    "payload_size",
    "source_num",
]


# ── Clase principal del modelo ────────────────────────────────

class HoneypotMLModel:
    """
    Encapsula el entrenamiento, guardado y predicción de los
    modelos de ML del sistema honeypot.
    """

    def __init__(self, model_dir: str = "ml_model"):
        self.model_dir   = model_dir
        self.rf_path     = os.path.join(model_dir, "rf_model.pkl")
        self.scaler_path = os.path.join(model_dir, "scaler.pkl")
        self.iso_path    = os.path.join(model_dir, "isolation_forest.pkl")

        self.rf_model    = None   # Random Forest
        self.iso_model   = None   # Isolation Forest
        self.scaler      = None   # Normalizador de features

        os.makedirs(model_dir, exist_ok=True)

    # ── Preparación de datos ──────────────────────────────────

    def prepare_data(self, feature_vectors: list):
        """
        Convierte la lista de vectores de features en matrices
        numpy que sklearn puede procesar.
        
        Separa X (entradas) de y (etiquetas a predecir).
        """
        X, y = [], []

        for fv in feature_vectors:
            row = [fv.get(col, 0) for col in FEATURE_COLUMNS]
            X.append(row)
            y.append(fv.get("label", 9))

        return np.array(X, dtype=float), np.array(y, dtype=int)

    # ── Entrenamiento ─────────────────────────────────────────

    def train(self, feature_vectors: list, verbose: bool = True):
        """
        Entrena los dos modelos con los datos disponibles.
        
        ¿Qué hace internamente?
        1. Prepara matrices X e y
        2. Normaliza las features (StandardScaler)
        3. Divide datos en train/test (80/20)
        4. Entrena Random Forest (clasificación)
        5. Entrena Isolation Forest (anomalías)
        6. Muestra métricas de rendimiento
        7. Guarda los modelos en disco
        """
        if len(feature_vectors) < 20:
            print("[ML] ⚠ Muy pocos datos para entrenar. Mínimo recomendado: 20 eventos.")
            return False

        X, y = self.prepare_data(feature_vectors)

        # ── Paso 1: Normalizar features ───────────────────────
        # StandardScaler lleva cada feature al rango [-1, 1]
        # Esto evita que el puerto 443 "pese" más que has_malware
        self.scaler = StandardScaler()
        X_scaled    = self.scaler.fit_transform(X)

        # ── Paso 2: Dividir train/test ────────────────────────
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=None
        )

        if verbose:
            print(f"\n[ML] Dataset: {len(X)} muestras, {X.shape[1]} features")
            print(f"[ML] Entrenamiento: {len(X_train)}, Prueba: {len(X_test)}")

        # ── Paso 3: Entrenar Random Forest ────────────────────
        # n_estimators=100: usa 100 árboles de decisión
        # max_depth=10:     profundidad máxima (evita overfitting)
        # class_weight='balanced': compensa clases desbalanceadas
        if verbose:
            print("\n[ML] Entrenando Random Forest...")

        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,          # Usar todos los núcleos del CPU
        )
        self.rf_model.fit(X_train, y_train)

        # Evaluar en datos de prueba
        y_pred = self.rf_model.predict(X_test)
        accuracy = (y_pred == y_test).mean()

        if verbose:
            print(f"[ML] ✓ Accuracy Random Forest: {accuracy:.2%}")
            # Reporte completo (solo clases que aparecen en test)
            labels_present = sorted(set(y_test))
            label_names = [ATTACK_LABELS.get(l, str(l)) for l in labels_present]
            print("\n[ML] Reporte de clasificación:")
            print(classification_report(
                y_test, y_pred,
                labels=labels_present,
                target_names=label_names,
                zero_division=0,
            ))

        # ── Paso 4: Entrenar Isolation Forest ─────────────────
        # contamination=0.1: esperamos ~10% de datos anómalos
        # n_estimators=100:  100 árboles de aislamiento
        if verbose:
            print("[ML] Entrenando Isolation Forest (detección de anomalías)...")

        self.iso_model = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # 10% esperado de anomalías
            random_state=42,
            n_jobs=-1,
        )
        self.iso_model.fit(X_scaled)  # Entrena con TODOS los datos

        if verbose:
            # Contar cuántos detecta como anómalos
            anomaly_preds = self.iso_model.predict(X_scaled)
            n_anomalies = (anomaly_preds == -1).sum()
            print(f"[ML] ✓ Isolation Forest detectó {n_anomalies} anomalías "
                  f"({n_anomalies/len(X):.1%} del dataset)")

        # ── Paso 5: Guardar modelos ───────────────────────────
        self._save_models()

        if verbose:
            print(f"\n[ML] ✓ Modelos guardados en {self.model_dir}/")

        return True

    # ── Predicción ────────────────────────────────────────────

    def predict(self, feature_vectors: list) -> list:
        """
        Clasifica nuevos eventos usando los modelos entrenados.
        
        Para cada evento devuelve:
          - attack_type:   nombre del tipo de ataque predicho
          - label:         código numérico
          - confidence:    probabilidad de la predicción (0-1)
          - is_anomaly:    True si Isolation Forest lo marca raro
          - anomaly_score: puntuación de rareza (más negativo = más raro)
        """
        if not self._models_loaded():
            self._load_models()

        if not self._models_loaded():
            return [{"error": "Modelos no disponibles"} for _ in feature_vectors]

        X, _ = self.prepare_data(feature_vectors)
        if len(X) == 0:
            return []

        X_scaled = self.scaler.transform(X)

        # ── Predicción de clase (Random Forest) ───────────────
        rf_preds      = self.rf_model.predict(X_scaled)
        rf_proba      = self.rf_model.predict_proba(X_scaled)

        # ── Detección de anomalías (Isolation Forest) ─────────
        iso_preds     = self.iso_model.predict(X_scaled)       # 1=normal, -1=anomalía
        iso_scores    = self.iso_model.score_samples(X_scaled) # puntuación de rareza

        results = []
        for i, fv in enumerate(feature_vectors):
            pred_label  = int(rf_preds[i])
            confidence  = float(rf_proba[i].max())
            is_anomaly  = bool(iso_preds[i] == -1)
            anom_score  = float(iso_scores[i])

            results.append({
                "id":            fv.get("_id", ""),
                "src_ip":        fv.get("_src_ip", ""),
                "timestamp":     fv.get("_timestamp", ""),
                "label":         pred_label,
                "attack_type":   ATTACK_LABELS.get(pred_label, "Desconocido"),
                "confidence":    round(confidence, 4),
                "is_anomaly":    is_anomaly,
                "anomaly_score": round(anom_score, 4),
                "original_type": fv.get("_attack_type", ""),
            })

        return results

    # ── Importancia de features ───────────────────────────────

    def feature_importance(self) -> list:
        """
        Muestra qué features son más importantes para el modelo.
        Útil para entender qué factores determinan el tipo de ataque.
        """
        if not self._models_loaded():
            self._load_models()

        if self.rf_model is None:
            return []

        importances = self.rf_model.feature_importances_
        ranked = sorted(
            zip(FEATURE_COLUMNS, importances),
            key=lambda x: x[1],
            reverse=True,
        )
        return [{"feature": f, "importance": round(v, 4)} for f, v in ranked]

    # ── Persistencia ──────────────────────────────────────────

    def _save_models(self):
        joblib.dump(self.rf_model,  self.rf_path)
        joblib.dump(self.scaler,    self.scaler_path)
        joblib.dump(self.iso_model, self.iso_path)

    def _load_models(self):
        try:
            self.rf_model  = joblib.load(self.rf_path)
            self.scaler    = joblib.load(self.scaler_path)
            self.iso_model = joblib.load(self.iso_path)
            print("[ML] ✓ Modelos cargados desde disco")
        except FileNotFoundError:
            print("[ML] ⚠ No se encontraron modelos guardados")

    def _models_loaded(self) -> bool:
        return all([self.rf_model, self.scaler, self.iso_model])


# ── Punto de entrada para entrenamiento manual ───────────────
if __name__ == "__main__":
    import yaml
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from scripts.analyzer import extract_features

    with open("config/config.yaml") as f:
        config = yaml.safe_load(f)

    # Cargar eventos normalizados
    events_path = config["output"]["normalized_json"]
    if not os.path.exists(events_path):
        print("[ML] ✗ No hay datos normalizados. Ejecuta primero el colector.")
        sys.exit(1)

    with open(events_path) as f:
        events = json.load(f)

    print(f"[ML] Cargados {len(events)} eventos para entrenamiento")

    # Extraer features
    features = extract_features(events)

    # Entrenar modelo
    model = HoneypotMLModel(config["ml"]["model_path"].replace("/rf_model.pkl", ""))
    model.train(features, verbose=True)

    # Mostrar importancia de features
    print("\n[ML] Importancia de características:")
    for item in model.feature_importance():
        bar = "█" * int(item["importance"] * 50)
        print(f"  {item['feature']:20s} {bar} {item['importance']:.4f}")
