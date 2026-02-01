#!/usr/bin/env python3
"""
SQLite Database Explorer for IDS Project
"""
import sqlite3
import sys

def explore_database(db_path):
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("=" * 50)
        print("IDS PROJECT DATABASE EXPLORER")
        print("=" * 50)
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print(f"\n📊 TABLES IN DATABASE ({len(tables)} total):")
        print("-" * 30)
        for table in tables:
            print(f"• {table[0]}")
        
        # Show schema for each table
        for table in tables:
            table_name = table[0]
            print(f"\n🔍 TABLE: {table_name}")
            print("-" * 30)
            
            # Get table schema
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            
            print("Columns:")
            for col in columns:
                col_id, name, data_type, not_null, default, pk = col
                pk_str = " (PRIMARY KEY)" if pk else ""
                null_str = " NOT NULL" if not_null else ""
                default_str = f" DEFAULT {default}" if default else ""
                print(f"  - {name}: {data_type}{pk_str}{null_str}{default_str}")
            
            # Count records
            cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
            count = cursor.fetchone()[0]
            print(f"Records: {count}")
            
            # Show sample data if any records exist
            if count > 0:
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 3;")
                sample_data = cursor.fetchall()
                print("Sample data (first 3 rows):")
                for i, row in enumerate(sample_data, 1):
                    print(f"  Row {i}: {row}")
        
        conn.close()
        print(f"\n✅ Database exploration complete!")
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    db_path = "instance/ids_project.db"
    explore_database(db_path)