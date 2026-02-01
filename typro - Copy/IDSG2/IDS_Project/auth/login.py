from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from database.db import get_db, User

bcrypt = Bcrypt()
auth_bp = Blueprint('auth', __name__)


# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    return User.query.get(int(user_id))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            # Redirect based on role
            if user.role == 'admin':
                return redirect(url_for('home'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form.get('role', 'user')
        db = get_db()
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register_enhanced.html')
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register_enhanced.html')
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register_enhanced.html')
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=password_hash, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        # Auto-login after registration
        login_user(new_user)
        if new_user.role == 'admin':
            return redirect(url_for('home'))
        else:
            return redirect(url_for('home'))
    return render_template('register_enhanced.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('auth.login'))
