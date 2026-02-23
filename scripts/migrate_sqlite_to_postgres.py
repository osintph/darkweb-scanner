#!/usr/bin/env python3
"""
Migrate existing SQLite database to PostgreSQL.
Run inside the dashboard container:
  PG_PASS=$(grep POSTGRES_PASSWORD .env | cut -d= -f2)
  docker compose cp scripts/migrate_sqlite_to_postgres.py dashboard:/tmp/
  docker compose exec -e POSTGRES_PASSWORD=$PG_PASS dashboard python3 /tmp/migrate_sqlite_to_postgres.py
"""
import sqlite3
import sqlalchemy
from sqlalchemy import text
import os

sqlite_path = '/app/data/results.db'
pg_pass = os.environ.get('POSTGRES_PASSWORD')
pg_url = f"postgresql://scanner:{pg_pass}@postgres:5432/darkweb_scanner"

sqlite_conn = sqlite3.connect(sqlite_path)
sqlite_conn.row_factory = sqlite3.Row
pg_engine = sqlalchemy.create_engine(pg_url)

from darkweb_scanner.storage import Storage
s = Storage(pg_url)
print("✓ Tables created in postgres")

bool_cols_map = {}
with pg_engine.connect() as pg_conn:
    result = pg_conn.execute(text("""
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema='public' AND data_type='boolean'
    """))
    for row in result:
        bool_cols_map.setdefault(row[0], []).append(row[1])
print(f"Boolean columns detected: {bool_cols_map}")

tables = sqlite_conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY rowid"
).fetchall()

with pg_engine.begin() as pg_conn:
    for (table,) in tables:
        if table.startswith('sqlite_'):
            continue
        rows = sqlite_conn.execute(f"SELECT * FROM {table}").fetchall()
        if not rows:
            print(f"  {table}: empty, skipping")
            continue
        cols = [d[0] for d in sqlite_conn.execute(f"SELECT * FROM {table} LIMIT 1").description]
        bool_cols = bool_cols_map.get(table, [])
        placeholders = ', '.join([f':{c}' for c in cols])
        col_names = ', '.join(cols)
        pg_conn.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER ALL"))
        count = 0
        for row in rows:
            row_dict = dict(zip(cols, row))
            for bc in bool_cols:
                if bc in row_dict and row_dict[bc] is not None:
                    row_dict[bc] = bool(row_dict[bc])
            pg_conn.execute(
                text(f"INSERT INTO {table} ({col_names}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"),
                row_dict
            )
            count += 1
        pg_conn.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER ALL"))
        print(f"  ✓ {table}: {count} rows")

print("\n✓ Migration complete")
