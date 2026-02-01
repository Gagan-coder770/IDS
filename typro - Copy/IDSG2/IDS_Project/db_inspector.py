#!/usr/bin/env python3
"""
Advanced Database Inspector for IDS Project
"""
import sqlite3
import os
from datetime import datetime

class DatabaseInspector:
    def __init__(self, db_path):
        self.db_path = db_path
        
    def connect(self):
        return sqlite3.connect(self.db_path)
    
    def basic_info(self):
        """Get basic database information"""
        if not os.path.exists(self.db_path):
            print(f"❌ Database file not found at: {self.db_path}")
            return False
            
        file_size = os.path.getsize(self.db_path)
        mod_time = datetime.fromtimestamp(os.path.getmtime(self.db_path))
        
        print(f"📁 Database: {self.db_path}")
        print(f"📊 Size: {file_size:,} bytes ({file_size/1024:.1f} KB)")
        print(f"🕒 Last Modified: {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")
        return True
    
    def list_tables(self):
        """List all tables in the database"""
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            print(f"\n📋 Tables ({len(tables)} found):")
            for table in tables:
                print(f"  • {table[0]}")
            return [table[0] for table in tables]
    
    def analyze_table(self, table_name):
        """Analyze a specific table"""
        with self.connect() as conn:
            cursor = conn.cursor()
            
            print(f"\n🔍 Analyzing table: {table_name}")
            print("=" * 50)
            
            # Table structure
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            
            print("📝 Schema:")
            for col in columns:
                pk = " (PRIMARY KEY)" if col[5] else ""
                null = " NOT NULL" if col[3] else ""
                default = f" DEFAULT {col[4]}" if col[4] else ""
                print(f"  • {col[1]}: {col[2]}{pk}{null}{default}")
            
            # Row count
            cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
            count = cursor.fetchone()[0]
            print(f"\n📊 Total records: {count}")
            
            if count > 0:
                # Sample data
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 3;")
                rows = cursor.fetchall()
                
                print(f"\n📄 Sample data (showing {len(rows)} of {count} records):")
                col_names = [col[1] for col in columns]
                
                for i, row in enumerate(rows, 1):
                    print(f"\n  Record {i}:")
                    for j, value in enumerate(row):
                        if len(str(value)) > 50:
                            value = str(value)[:50] + "..."
                        print(f"    {col_names[j]}: {value}")
            
            print("-" * 50)
    
    def search_users(self, search_term=None):
        """Search users in the database"""
        with self.connect() as conn:
            cursor = conn.cursor()
            
            if search_term:
                cursor.execute("SELECT * FROM user WHERE username LIKE ? OR email LIKE ?", 
                             (f'%{search_term}%', f'%{search_term}%'))
                print(f"\n🔍 Users matching '{search_term}':")
            else:
                cursor.execute("SELECT * FROM user")
                print("\n👥 All users:")
            
            users = cursor.fetchall()
            
            if users:
                for user in users:
                    print(f"  • ID: {user[0]} | Username: {user[1]} | Email: {user[2] or 'N/A'} | Role: {user[6]}")
            else:
                print("  No users found.")
    
    def check_alerts(self):
        """Check IDS alerts"""
        with self.connect() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM ids_alert")
            alert_count = cursor.fetchone()[0]
            
            print(f"\n🚨 IDS Alerts: {alert_count} total")
            
            if alert_count > 0:
                cursor.execute("SELECT * FROM ids_alert ORDER BY timestamp DESC LIMIT 5")
                alerts = cursor.fetchall()
                
                print("Recent alerts:")
                for alert in alerts:
                    print(f"  • {alert[1]} | {alert[2]} → {alert[3]} | {alert[5]} ({alert[6]})")
            else:
                print("  No alerts recorded.")
    
    def full_inspection(self):
        """Run complete database inspection"""
        print("🔍 DATABASE INSPECTION REPORT")
        print("=" * 60)
        
        if not self.basic_info():
            return
            
        try:
            tables = self.list_tables()
            
            for table in tables:
                self.analyze_table(table)
            
            # Special analysis for known tables
            if 'user' in tables:
                self.search_users()
            
            if 'ids_alert' in tables:
                self.check_alerts()
                
        except sqlite3.Error as e:
            print(f"❌ Database error: {e}")
        except Exception as e:
            print(f"❌ Error: {e}")

def main():
    inspector = DatabaseInspector('instance/ids_project.db')
    inspector.full_inspection()

if __name__ == "__main__":
    main()