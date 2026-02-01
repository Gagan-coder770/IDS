from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from auth.login import auth_bp, login_manager
from ids.detection import ids_bp as ids_pcap_bp        # existing pcap-based IDS blueprint
from ids_single import ids_bp as ids_ui_bp             # new single-page IDS blueprint
from crypto.crypto_tool import crypto_bp
from scanner.port_scan import scanner_bp
from dashboard.dashboard import dashboard_bp
from database.db import db_init, db, User, IDSAlert  # Import models from database
from password_manager import password_manager_bp
from flask_login import login_required, current_user
from io import BytesIO
import json
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Initialize extensions
db_init(app)
login_manager.init_app(app)

# Register Blueprints (note unique names / objects)
app.register_blueprint(auth_bp)
app.register_blueprint(ids_pcap_bp)       # /ids - pcap upload & parsing blueprint
app.register_blueprint(ids_ui_bp)         # /ids (or whatever url_prefix in ids_single) - single-page UI
app.register_blueprint(crypto_bp)
app.register_blueprint(scanner_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(password_manager_bp, url_prefix='/password-manager')

# Models are now imported from database.db

# Create tables if they don't exist
with app.app_context():
    db.create_all()

@app.route("/")
@login_required
def home():
    # Pass user role to template for navigation
    return render_template("index.html", user=current_user)

@app.route('/profile')
@login_required
def profile():
    # Example data, replace with real user data from your database
    return render_template(
        'profile.html',
        username=current_user.username,
        email=getattr(current_user, 'email', 'user@email.com'),
        created_at=getattr(current_user, 'created_at', '2024-01-01'),
        last_login=getattr(current_user, 'last_login', '2025-09-12 10:23'),
        last_ip='192.168.1.5',
        last_device='Chrome/Windows',
        bio=getattr(current_user, 'bio', 'Cybersecurity enthusiast. Stay safe online!'),
        login_logs=[],        # Replace with real login logs
        ids_alerts=[],        # Replace with real IDS alerts
        passwords_count=0,    # Replace with real count
        crypto_history=[],    # Replace with real crypto history
        port_scans=[]         # Replace with real scan history
    )

@app.route('/edit_bio', methods=['POST'])
@login_required
def edit_bio():
    bio = request.form.get('bio', '').strip()
    current_user.bio = bio
    db.session.commit()
    flash('Bio updated!', 'success')
    return redirect(url_for('profile'))

@app.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    # Check for unique username
    if username != current_user.username and User.query.filter_by(username=username).first():
        flash('Username already taken.', 'danger')
        return redirect(url_for('profile'))
    current_user.username = username
    current_user.email = email
    db.session.commit()
    flash('Profile updated!', 'success')
    return redirect(url_for('profile'))

@app.route('/reset_password', methods=['POST'])
@login_required
def reset_password():
    old_pw = request.form.get('old_password')
    new_pw = request.form.get('new_password')
    confirm_pw = request.form.get('confirm_password')
    if not current_user.check_password(old_pw):
        flash('Old password is incorrect.', 'danger')
    elif new_pw != confirm_pw:
        flash('New passwords do not match.', 'danger')
    elif len(new_pw) < 6:
        flash('New password must be at least 6 characters.', 'danger')
    else:
        current_user.set_password(new_pw)
        db.session.commit()
        flash('Password updated!', 'success')
    return redirect(url_for('profile'))

@app.route('/export_data')
@login_required
def export_data():
    # Example: Collect user data (customize as needed)
    data = {
        "username": current_user.username,
        "email": current_user.email,
        "bio": current_user.bio,
        "saved_passwords": [pw.to_dict() for pw in getattr(current_user, 'passwords', [])],
        "ids_logs": [log.to_dict() for log in getattr(current_user, 'ids_logs', [])],
        "crypto_history": [c.to_dict() for c in getattr(current_user, 'crypto_history', [])],
    }
    json_data = json.dumps(data, indent=2)
    return send_file(
        BytesIO(json_data.encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name=f"my_data_{current_user.username}.json"
    )

# Machine Learning Model Training (Run separately, not on each app start)
def train_ids_model():
    # Placeholder: Load your dataset (e.g., NSL-KDD or CICIDS2017 preprocessed CSV)
    df = pd.read_csv('nsl_kdd_sample.csv')  # Replace with your dataset

    X = df.drop(['label'], axis=1)
    y = df['label'].apply(lambda x: 0 if x == 'normal' else 1)  # 0=Normal, 1=Attack

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X_train, y_train)

    joblib.dump(clf, 'ids_model.joblib')
    print("Model trained and saved as ids_model.joblib")

if __name__ == "__main__":
    app.run(debug=True, port=5050)