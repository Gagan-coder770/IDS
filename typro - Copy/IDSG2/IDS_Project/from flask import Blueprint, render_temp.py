from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime
import pandas as pd
import joblib
import os
import json
from io import BytesIO
from database.db import db
from database.models import IDSAlert  # Make sure IDSAlert is in models.py

ids_bp = Blueprint('ids', __name__, url_prefix='/ids')

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ids_model.joblib')

def load_model():
    return joblib.load(MODEL_PATH)

def parse_pcap(file_path):
    # Placeholder: parse pcap and return DataFrame with features
    return pd.read_csv('nsl_kdd_sample.csv').head(10)  # Replace with real parsing

@ids_bp.route('/', methods=['GET'])
@login_required
def dashboard():
    user_id = current_user.id
    total_alerts = IDSAlert.query.filter_by(user_id=user_id).count()
    severe_alerts = IDSAlert.query.filter_by(user_id=user_id, severity='High').count()
    last_alert = IDSAlert.query.filter_by(user_id=user_id).order_by(IDSAlert.timestamp.desc()).first()
    last_scan_time = last_alert.timestamp if last_alert else "Never"
    recent_alerts = IDSAlert.query.filter_by(user_id=user_id).order_by(IDSAlert.timestamp.desc()).limit(10).all()
    chart_data = db.session.query(IDSAlert.timestamp, IDSAlert.severity).filter_by(user_id=user_id).all()
    return render_template('ids_dashboard.html',
        total_alerts=total_alerts,
        severe_alerts=severe_alerts,
        last_scan_time=last_scan_time,
        recent_alerts=recent_alerts,
        chart_data=chart_data
    )

@ids_bp.route('/run', methods=['POST'])
@login_required
def run_ids():
    file = request.files.get('pcap_file')
    if not file:
        flash('No file uploaded.', 'danger')
        return redirect(url_for('ids.dashboard'))
    filename = secure_filename(file.filename)
    file_path = os.path.join('uploads', filename)
    file.save(file_path)
    df = parse_pcap(file_path)
    model = load_model()
    preds = model.predict(df.drop(['label'], axis=1))
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for i, row in df.iterrows():
        pred = 'Attack' if preds[i] else 'Normal'
        severity = 'High' if pred == 'Attack' else 'Low'
        alert = IDSAlert(
            user_id=current_user.id,
            timestamp=now,
            src_ip=row.get('src_ip', 'N/A'),
            dst_ip=row.get('dst_ip', 'N/A'),
            protocol=row.get('protocol', 'TCP'),
            prediction=pred,
            severity=severity
        )
        db.session.add(alert)
    db.session.commit()
    flash('IDS scan complete. Alerts updated.', 'success')
    return redirect(url_for('ids.dashboard'))

@ids_bp.route('/logs', methods=['GET'])
@login_required
def logs():
    user_id = current_user.id
    alerts = IDSAlert.query.filter_by(user_id=user_id).order_by(IDSAlert.timestamp.desc()).all()
    return render_template('ids_logs.html', alerts=alerts)

@ids_bp.route('/clear', methods=['POST'])
@login_required
def clear_logs():
    user_id = current_user.id
    IDSAlert.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    flash('IDS logs cleared.', 'success')
    return redirect(url_for('ids.dashboard'))

@ids_bp.route('/export', methods=['GET'])
@login_required
def export_logs():
    user_id = current_user.id
    alerts = IDSAlert.query.filter_by(user_id=user_id).all()
    data = [
        {
            "timestamp": a.timestamp,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "protocol": a.protocol,
            "prediction": a.prediction,
            "severity": a.severity
        } for a in alerts
    ]
    json_data = json.dumps(data, indent=2)
    return send_file(
        BytesIO(json_data.encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name=f"ids_logs_{current_user.username}.json"
    )