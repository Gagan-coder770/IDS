import sqlite3
import os

DB = os.path.join(os.path.dirname(__file__), 'ids_project.db')
if not os.path.exists(DB):
    print(f"Database file not found: {DB}")
    raise SystemExit(1)

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
tables = [r[0] for r in cur.fetchall()]
print('Found tables:', tables)

for t in tables:
    print('\n--- Table:', t, '---')
    cur.execute(f"PRAGMA table_info({t});")
    cols = [r[1] for r in cur.fetchall()]
    print('Columns:', cols)
    cur.execute(f"SELECT * FROM {t} LIMIT 20;")
    rows = cur.fetchall()
    if not rows:
        print('<no rows>')
        continue
    for row in rows:
        print({col: row[col] for col in cols})

conn.close()
