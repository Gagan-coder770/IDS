#!/usr/bin/env python3
"""
Interactive Database Query Tool for IDS Project
"""
import sqlite3
import sys

def execute_query(db_path, query):
    """Execute a SQL query and display results"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute(query)
        
        if query.strip().lower().startswith('select'):
            results = cursor.fetchall()
            
            # Get column names
            columns = [description[0] for description in cursor.description]
            
            if results:
                # Print header
                print("\n" + " | ".join(columns))
                print("-" * (len(" | ".join(columns)) + 10))
                
                # Print results
                for row in results:
                    print(" | ".join(str(item) for item in row))
                
                print(f"\n{len(results)} row(s) returned.")
            else:
                print("No results found.")
        else:
            conn.commit()
            print(f"Query executed successfully. {cursor.rowcount} row(s) affected.")
        
        conn.close()
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")

def interactive_mode(db_path):
    """Interactive query mode"""
    print("🗃️  Interactive Database Query Tool")
    print("=" * 40)
    print("Enter SQL queries (type 'exit' to quit)")
    print("Examples:")
    print("  SELECT * FROM user;")
    print("  SELECT username, role FROM user WHERE role = 'admin';")
    print("  SELECT COUNT(*) FROM ids_alert;")
    print()
    
    while True:
        try:
            query = input("SQL> ").strip()
            
            if query.lower() in ['exit', 'quit', 'q']:
                print("Goodbye!")
                break
            
            if not query:
                continue
                
            execute_query(db_path, query)
            print()
            
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except EOFError:
            print("\nGoodbye!")
            break

def main():
    db_path = 'instance/ids_project.db'
    
    if len(sys.argv) > 1:
        # Execute single query from command line
        query = " ".join(sys.argv[1:])
        execute_query(db_path, query)
    else:
        # Interactive mode
        interactive_mode(db_path)

if __name__ == "__main__":
    main()