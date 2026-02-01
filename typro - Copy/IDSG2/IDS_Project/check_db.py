#!/usr/bin/env python3
"""
Database checker script for IDS Project
"""
import sqlite3
import os

def check_database():
    db_path = 'instance/ids_project.db'
    
    if not os.path.exists(db_path):
        print(f"Database file not found at: {db_path}")
        return
    
    print(f"Database file found: {db_path}")
    print(f"File size: {os.path.getsize(db_path)} bytes")
    print("-" * 50)
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print("Tables in database:")
        for table in tables:
            print(f"  - {table[0]}")
        
        print("-" * 50)
        
        # Check each table's structure and data
        for table in tables:
            table_name = table[0]
            print(f"\nTable: {table_name}")
            
            # Get table structure
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            
            print("Columns:")
            for col in columns:
                print(f"  - {col[1]} ({col[2]})")
            
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
            count = cursor.fetchone()[0]
            print(f"Total rows: {count}")
            
            # Show sample data if exists
            if count > 0:
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 5;")
                rows = cursor.fetchall()
                print("Sample data (first 5 rows):")
                for i, row in enumerate(rows, 1):
                    print(f"  Row {i}: {row}")
            
            print("-" * 30)
        
        conn.close()
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_database()