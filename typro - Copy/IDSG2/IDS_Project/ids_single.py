# ids_single.py
import os
import joblib
import numpy as np
from flask import Blueprint, render_template, request, current_app, flash

# Blueprint name MUST be unique across your app
ids_bp = Blueprint('ids_single', __name__, template_folder='templates', static_folder='static')

# ----- Configure these filenames to match your saved artifacts -----
MODEL_FILENAME = 'model.joblib'      # preferred: sklearn Pipeline saved via joblib
SCALER_FILENAME = 'scaler.joblib'    # optional
ENCODER_FILENAME = 'encoder.joblib'  # optional: dict of label encoders

# ----- Cached objects -----
_model = None
_scaler = None
_encoders = None

def get_model():
    global _model
    if _model is None:
        model_path = os.path.join(current_app.root_path, MODEL_FILENAME)
        if os.path.exists(model_path):
            try:
                _model = joblib.load(model_path)
                current_app.logger.info("Loaded model from %s", model_path)
            except Exception as e:
                current_app.logger.error("Failed to load model: %s", e)
                _model = None
        else:
            current_app.logger.warning("Model file not found at %s", model_path)
    return _model

def get_scaler():
    global _scaler
    if _scaler is None:
        path = os.path.join(current_app.root_path, SCALER_FILENAME)
        if os.path.exists(path):
            try:
                _scaler = joblib.load(path)
            except Exception as e:
                current_app.logger.error("Failed to load scaler: %s", e)
                _scaler = None
    return _scaler

def get_encoders():
    global _encoders
    if _encoders is None:
        path = os.path.join(current_app.root_path, ENCODER_FILENAME)
        if os.path.exists(path):
            try:
                _encoders = joblib.load(path)
            except Exception as e:
                current_app.logger.error("Failed to load encoders: %s", e)
                _encoders = None
    return _encoders

# If you did NOT save encoders, these example maps are here as fallback.
# IMPORTANT: if you trained with different mappings, replace these accordingly.
protocol_map = {"tcp": 0, "udp": 1, "icmp": 2}
flag_map = {"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "RSTR": 4, "SH": 5,
            "S1": 6, "S2": 7, "S3": 8, "OTH": 9}

# Map model outputs -> readable attack categories (strings).
# If your model returns integers (0/1) or strings, this will normalize.
# Adjust mapping to match your trained labels.
LABEL_NORMALIZATION = {
    # common textual forms
    'normal': 'Normal',
    'dos': 'DoS',
    'probe': 'Probe',
    'r2l': 'R2L',
    'u2r': 'U2R',
    # numeric fallbacks (if model outputs numeric codes)
    0: 'Normal',
    1: 'Attack'
}

def normalize_label(raw):
    """
    Convert model output into human-friendly label string.
    Accepts strings or numeric outputs.
    """
    if raw is None:
        return "Unknown"
    # if numpy types, convert to python native
    try:
        if isinstance(raw, np.generic):
            raw = raw.item()
    except Exception:
        pass

    # if it's numeric (0/1) and you had a multi-class model, adapt mapping accordingly
    if isinstance(raw, (int, float)):
        return LABEL_NORMALIZATION.get(int(raw), str(raw))
    # if string, lowercase and map
    s = str(raw).lower()
    return LABEL_NORMALIZATION.get(s, str(raw).capitalize())

@ids_bp.route('/ids', methods=['GET', 'POST'])
def ids_page():
    detection_label = None
    detection_confidence = None
    packet_data = request.form.get('packet_data', '') if request.method == 'POST' else ''

    if request.method == 'POST':
        # Collect all fields in the same order you used in Django
        raw = []
        # --- Step1 fields ---
        raw.append(request.form.get('duration', '').strip())
        raw.append(request.form.get('protocol_type', '').strip())
        raw.append(request.form.get('flag', '').strip())
        raw.append(request.form.get('src_bytes', '').strip())
        raw.append(request.form.get('dst_bytes', '').strip())
        raw.append(request.form.get('land', '').strip())
        raw.append(request.form.get('wrong_fragment', '').strip())
        raw.append(request.form.get('urgent', '').strip())
        raw.append(request.form.get('hot', '').strip())
        raw.append(request.form.get('num_failed_logins', '').strip())
        raw.append(request.form.get('logged_in', '').strip())
        raw.append(request.form.get('num_compromised', '').strip())

        # --- Step2 fields ---
        raw.append(request.form.get('root_shell', '').strip())
        raw.append(request.form.get('su_attempted', '').strip())
        raw.append(request.form.get('num_file_creations', '').strip())
        raw.append(request.form.get('num_shells', '').strip())
        raw.append(request.form.get('num_access_files', '').strip())
        raw.append(request.form.get('is_guest_login', '').strip())
        raw.append(request.form.get('count', '').strip())
        raw.append(request.form.get('srv_count', '').strip())
        raw.append(request.form.get('serror_rate', '').strip())
        raw.append(request.form.get('rerror_rate', '').strip())
        raw.append(request.form.get('same_srv_rate', '').strip())
        raw.append(request.form.get('diff_srv_rate', '').strip())

        # --- Step3 fields ---
        raw.append(request.form.get('srv_diff_host_rate', '').strip())
        raw.append(request.form.get('dst_host_count', '').strip())
        raw.append(request.form.get('dst_host_srv_count', '').strip())
        raw.append(request.form.get('dst_host_diff_srv_rate', '').strip())
        raw.append(request.form.get('dst_host_same_src_port_rate', '').strip())
        raw.append(request.form.get('dst_host_srv_diff_host_rate', '').strip())

        # Preprocessing & prediction
        try:
            encoders = get_encoders()
            built = []
            for i, v in enumerate(raw):
                # protocol_type index = 1, flag index = 2 (based on collection order)
                if i == 1:  # protocol_type
                    if encoders and 'protocol_type' in encoders:
                        enc = encoders['protocol_type']
                        transformed = enc.transform([v])[0]
                        built.append(float(transformed))
                    else:
                        built.append(float(protocol_map.get(v.lower(), -1)))
                elif i == 2:  # flag
                    if encoders and 'flag' in encoders:
                        enc = encoders['flag']
                        transformed = enc.transform([v])[0]
                        built.append(float(transformed))
                    else:
                        built.append(float(flag_map.get(v.upper(), -1)))
                else:
                    # numeric conversion (raise on invalid)
                    try:
                        built.append(float(v))
                    except ValueError:
                        raise ValueError(f"Invalid numeric value for feature index {i}: '{v}'")

            X = np.array(built, dtype=float).reshape(1, -1)

            # load model (cached)
            model = get_model()
            if model is None:
                raise RuntimeError("Model not loaded. Place model.joblib (pipeline or model) in app root.")

            # If model is a pipeline and handles preprocessing, feed raw numeric X in correct order.
            # If you saved a pipeline, you can also pass a DataFrame with correct column names.
            # Apply scaler if you saved it separately and model isn't a pipeline handling scaling.
            scaler = get_scaler()
            # heuristic: sklearn pipeline has attribute 'steps' (list), if so assume it includes preprocessing
            is_pipeline = hasattr(model, 'steps')
            if scaler is not None and not is_pipeline:
                X = scaler.transform(X)

            # Predict
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(X)
                pred_idx = int(np.argmax(probs, axis=1)[0])
                # If model.classes_ exists, use it to find label
                if hasattr(model, "classes_"):
                    raw_label = model.classes_[pred_idx]
                else:
                    raw_label = pred_idx
                confidence = float(np.max(probs))
                detection_label = normalize_label(raw_label)
                detection_confidence = round(confidence, 3)
            else:
                pred = model.predict(X)
                raw_label = pred[0]
                detection_label = normalize_label(raw_label)
                detection_confidence = None

        except Exception as e:
            current_app.logger.exception("Prediction error")
            detection_label = f"Error: {e}"
            detection_confidence = None

    # Render template with values (template triggers SweetAlert when detection_label present)
    return render_template('ids.html',
                           detection_label=detection_label,
                           detection_confidence=detection_confidence,
                           packet_data=packet_data)
