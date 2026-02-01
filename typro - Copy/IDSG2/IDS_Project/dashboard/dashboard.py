from flask import Blueprint, render_template, request, jsonify, redirect
from flask_login import login_required, current_user
from database.db import db, IDSAlert, User
from datetime import datetime, timedelta
import random
import json

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def dashboard_home():
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        return redirect('/')
    
    # Get dashboard statistics
    total_alerts = db.session.query(IDSAlert).count()
    high_priority_alerts = db.session.query(IDSAlert).filter(IDSAlert.severity == 'high').count()
    active_users = db.session.query(User).count()
    
    # Get recent alerts (last 10)
    recent_alerts = db.session.query(IDSAlert).order_by(IDSAlert.timestamp.desc()).limit(10).all()
    
    # Generate sample data for charts
    chart_data = generate_chart_data()
    
    return render_template('dashboard_enhanced.html', 
                         total_alerts=total_alerts,
                         high_priority_alerts=high_priority_alerts,
                         active_users=active_users,
                         recent_alerts=recent_alerts,
                         chart_data=chart_data)

@dashboard_bp.route('/api/dashboard/realtime')
@login_required
def get_realtime_data():
    """API endpoint for real-time dashboard updates"""
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Simulate real-time data
    data = {
        'timestamp': datetime.now().isoformat(),
        'cpu_usage': random.randint(20, 80),
        'memory_usage': random.randint(30, 70),
        'network_traffic': random.randint(100, 1000),
        'active_connections': random.randint(50, 200),
        'threat_level': random.choice(['low', 'medium', 'high']),
        'new_alerts': random.randint(0, 5)
    }
    return jsonify(data)

@dashboard_bp.route('/api/dashboard/alerts')
@login_required
def get_alert_data():
    """API endpoint for alert statistics"""
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Get alerts from last 7 days
    week_ago = datetime.now() - timedelta(days=7)
    alerts = db.session.query(IDSAlert).filter(IDSAlert.timestamp >= week_ago).all()
    
    # Group by day
    daily_alerts = {}
    for alert in alerts:
        day = alert.timestamp.strftime('%Y-%m-%d')
        if day not in daily_alerts:
            daily_alerts[day] = {'total': 0, 'high': 0, 'medium': 0, 'low': 0}
        daily_alerts[day]['total'] += 1
        daily_alerts[day][alert.severity] += 1
    
    return jsonify(daily_alerts)

def generate_chart_data():
    """Generate sample data for dashboard charts"""
    # Security metrics over time
    labels = [(datetime.now() - timedelta(days=i)).strftime('%m/%d') for i in range(6, -1, -1)]
    
    return {
        'security_overview': {
            'labels': labels,
            'datasets': [
                {
                    'label': 'Threats Detected',
                    'data': [random.randint(5, 25) for _ in range(7)],
                    'borderColor': '#dc3545',
                    'backgroundColor': 'rgba(220, 53, 69, 0.1)',
                    'tension': 0.4
                },
                {
                    'label': 'Blocked Attempts',
                    'data': [random.randint(15, 40) for _ in range(7)],
                    'borderColor': '#28a745',
                    'backgroundColor': 'rgba(40, 167, 69, 0.1)',
                    'tension': 0.4
                }
            ]
        },
        'threat_types': {
            'labels': ['Malware', 'Phishing', 'DDoS', 'Brute Force', 'SQL Injection', 'XSS'],
            'data': [random.randint(5, 30) for _ in range(6)],
            'backgroundColor': [
                '#dc3545', '#fd7e14', '#ffc107', 
                '#28a745', '#17a2b8', '#6f42c1'
            ]
        },
        'system_performance': {
            'labels': ['CPU', 'Memory', 'Disk', 'Network'],
            'data': [random.randint(20, 80) for _ in range(4)],
            'backgroundColor': ['#007bff', '#28a745', '#ffc107', '#dc3545']
        }
    }
