# ids/detection.py
import os
import joblib
import numpy as np
from flask import Blueprint, render_template, request, current_app

ids_bp = Blueprint('ids', __name__)

# ------------------ Configuration ------------------
# Filename of your saved model (preferably a sklearn Pipeline that includes preprocessing)
MODEL_FILENAME = 'ids_model/model.h5'   # change if your model file has a different name

# If you saved encoders/scaler individually, set their filenames here (optional)
ENCODER_FILENAME = None   # e.g. 'encoders.joblib' or None

# ------------------ Cached objects ------------------
_MODEL = None
_ENCODERS = None

def _load_model():
    """Load model once and cache it in module-level variable."""
    global _MODEL
    if _MODEL is None:
        model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), MODEL_FILENAME)
        # try also app root if that path doesn't exist
        if not os.path.exists(model_path):
            model_path = os.path.join(os.getcwd(), MODEL_FILENAME)
        if os.path.exists(model_path):
            try:
                _MODEL = joblib.load(model_path)
                current_app.logger.info("Loaded IDS model from %s", model_path)
            except Exception as e:
                current_app.logger.exception("Failed to load IDS model from %s: %s", model_path, e)
                _MODEL = None
        else:
            current_app.logger.warning("Model file not found at %s", model_path)
    return _MODEL

def _load_encoders():
    """Load saved encoders if provided (optional)."""
    global _ENCODERS
    if _ENCODERS is None and ENCODER_FILENAME:
        path = os.path.join(os.getcwd(), ENCODER_FILENAME)
        if os.path.exists(path):
            try:
                _ENCODERS = joblib.load(path)
            except Exception:
                current_app.logger.exception("Failed to load encoders from %s", path)
                _ENCODERS = None
    return _ENCODERS

# Fallback encoding maps (ONLY use if you DID NOT save encoders during training)
# Replace these with your real encodings if different.
_PROTOCOL_MAP = {"tcp": 0, "udp": 1, "icmp": 2}
_FLAG_MAP = {"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "RSTR": 4, "SH": 5,
             "S1": 6, "S2": 7, "S3": 8, "OTH": 9}

# Map raw model outputs (strings/numbers) to friendly labels.
_LABEL_NORMALIZATION = {
    'normal': 'Normal',
    'dos': 'DoS',
    'probe': 'Probe',
    'r2l': 'R2L',
    'u2r': 'U2R',
    0: 'Normal',
    1: 'Attack'
}

def _normalize_label(raw):
    """Convert model output into human-friendly label string."""
    if raw is None:
        return "Unknown"
    # convert numpy scalar to python type
    if isinstance(raw, np.generic):
        raw = raw.item()
    # if numeric
    if isinstance(raw, (int, float)):
        return _LABEL_NORMALIZATION.get(int(raw), str(raw))
    s = str(raw).lower()
    return _LABEL_NORMALIZATION.get(s, str(raw).capitalize())

# --------------- Route ---------------
@ids_bp.route('/ids', methods=['GET', 'POST'])
def ids_home():
    detection_label = None
    detection_confidence = None

    if request.method == 'POST':
        # Collect the same fields your ids.html sends (order MUST match model training order)
        fields = [
            'duration','protocol_type','flag','src_bytes','dst_bytes','land',
            'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
            'root_shell','su_attempted','num_file_creations','num_shells','num_access_files','is_guest_login',
            'count','srv_count','serror_rate','rerror_rate','same_srv_rate','diff_srv_rate',
            'srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate'
        ]

        raw_values = []
        for f in fields:
            raw_values.append(request.form.get(f, '').strip())

        # Convert raw_values -> numeric feature vector matching training
        try:
            encoders = _load_encoders()
            features = []
            for idx, val in enumerate(raw_values):
                # protocol_type is at index 1, flag at index 2 (based on list above)
                if idx == 1:  # protocol_type
                    if encoders and 'protocol_type' in encoders:
                        enc = encoders['protocol_type']
                        # enc.transform expects an array-like
                        transformed = enc.transform([val])[0]
                        features.append(float(transformed))
                    else:
                        features.append(float(_PROTOCOL_MAP.get(val.lower(), -1)))
                elif idx == 2:  # flag
                    if encoders and 'flag' in encoders:
                        enc = encoders['flag']
                        transformed = enc.transform([val])[0]
                        features.append(float(transformed))
                    else:
                        features.append(float(_FLAG_MAP.get(val.upper(), -1)))
                else:
                    # numeric conversion for other features
                    try:
                        features.append(float(val))
                    except ValueError:
                        # If empty string, you may want to default to 0.0 or raise error.
                        # We'll treat empty as 0.0 to avoid crashing; change if you need strict checking.
                        if val == '':
                            features.append(0.0)
                        else:
                            raise

            X = np.array(features, dtype=float).reshape(1, -1)

            model = _load_model()
            if model is None:
                raise RuntimeError("IDS model is not loaded. Place '{}' in the app root.".format(MODEL_FILENAME))

            # If model is a sklearn Pipeline, it may accept a 2D array or DataFrame and include preprocessing.
            # Use predict_proba when available to compute confidence.
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(X)
                # choose highest-probability class index
                top_idx = int(np.argmax(probs, axis=1)[0])
                # get class label if available
                if hasattr(model, "classes_"):
                    raw_label = model.classes_[top_idx]
                else:
                    raw_label = top_idx
                confidence = float(np.max(probs, axis=1)[0]) * 100.0
                detection_label = _normalize_label(raw_label)
                detection_confidence = round(confidence, 2)
            else:
                # fallback to predict()
                pred = model.predict(X)
                raw_label = pred[0]
                detection_label = _normalize_label(raw_label)
                detection_confidence = None

        except Exception as e:
            current_app.logger.exception("Error during IDS prediction")
            # Show the error to the template as a label (so SweetAlert displays it).
            detection_label = f"Error: {e}"
            detection_confidence = None

        # Render template with detection variables. Template expects detection_label and detection_confidence.
        return render_template('ids.html',
                               detection_label=detection_label,
                               detection_confidence=detection_confidence)

    # GET: show empty form
    return render_template('ids.html',
                           detection_label=None,
                           detection_confidence=None)
