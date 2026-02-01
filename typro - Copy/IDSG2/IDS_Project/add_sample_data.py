#!/usr/bin/env python3
"""
Add sample data to the database for testing dashboard functionality
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from database.db import db, IDSAlert, User
from datetime import datetime, timedelta
import random

def add_sample_data():
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Check if admin user exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@example.com',
                role='admin'
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            print("Created admin user (username: admin, password: admin123)")
        
        # Add sample alerts
        alert_types = ['Malware Detection', 'Port Scan', 'Brute Force', 'SQL Injection', 'XSS Attack', 'DDoS Attempt']
        severities = ['low', 'medium', 'high']
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS']
        
        # Generate alerts for the last 7 days
        base_date = datetime.now() - timedelta(days=7)
        
        for i in range(50):  # Create 50 sample alerts
            alert_date = base_date + timedelta(
                days=random.randint(0, 7),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            alert = IDSAlert(
                timestamp=alert_date,
                source_ip=f"192.168.1.{random.randint(1, 254)}",
                destination_ip=f"10.0.0.{random.randint(1, 254)}",
                protocol=random.choice(protocols),
                alert_type=random.choice(alert_types),
                severity=random.choice(severities),
                description=f"Detected {random.choice(alert_types)} from suspicious source",
                user_id=admin_user.id
            )
            db.session.add(alert)
        
        db.session.commit()
        print("Added 50 sample alerts to the database")
        print("Dashboard should now show realistic data!")

if __name__ == '__main__':
    add_sample_data()