import os
import sqlite3
import psycopg2
from psycopg2 import extras
from urllib.parse import urlparse

class ConnectionWrapper:
    def __init__(self, conn, is_postgres):
        self.conn = conn
        self.is_postgres = is_postgres

    def execute(self, query, params=None):
        if self.is_postgres:
            query = query.replace("?", "%s")
            # Intercept SQLite-specific last_insert_rowid()
            if "last_insert_rowid()" in query.lower():
                query = query.lower().replace("last_insert_rowid()", "lastval()")
        
        cur = self.conn.cursor()
        try:
            if params:
                cur.execute(query, params)
            else:
                cur.execute(query)
        except Exception as e:
            if self.is_postgres:
                self.conn.rollback()
            raise
        return cur

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()

    def executescript(self, script):
        if self.is_postgres:
            # PostgreSQL: split by semicolons and execute each statement individually
            # so one failure doesn't abort the entire transaction
            cur = self.conn.cursor()
            statements = [s.strip() for s in script.split(';') if s.strip()]
            for stmt in statements:
                try:
                    cur.execute(stmt)
                except Exception as e:
                    print(f"[DB] Statement skipped (likely already exists): {e}")
                    self.conn.rollback()
            self.conn.commit()
        else:
            self.conn.executescript(script)

    def rollback(self):
        self.conn.rollback()

    def fetchone(self, query, params=None):
        cur = self.execute(query, params)
        return cur.fetchone()

    def fetchall(self, query, params=None):
        cur = self.execute(query, params)
        return cur.fetchall()

class DatabaseAdapter:
    def __init__(self):
        self._is_postgres = False
        
    def get_connection(self):
        db_url = os.getenv("DATABASE_URL")
        self._is_postgres = bool(db_url and (db_url.startswith("postgres://") or db_url.startswith("postgresql://")))
        
        if self._is_postgres:
            try:
                if "[YOUR-PASSWORD]" in db_url:
                    raise ValueError("You must replace [YOUR-PASSWORD] in your .env file with your actual Supabase database password.")
                
                conn = psycopg2.connect(db_url)
                # Use DictCursor to mimic sqlite3.Row behavior (both key and index access)
                conn.cursor_factory = extras.DictCursor
                return ConnectionWrapper(conn, True)
            except Exception as e:
                print(f"[ERROR] PostgreSQL Connection Failed: {e}")
                print("[INFO] Falling back to SQLite for safety (local mode)")
                self._is_postgres = False

        if not os.path.exists("db"):
            os.makedirs("db")
        conn = sqlite3.connect("db/portal.db")
        conn.row_factory = sqlite3.Row
        return ConnectionWrapper(conn, False)

    @property
    def is_postgres(self):
        db_url = os.getenv("DATABASE_URL")
        return bool(db_url and (db_url.startswith("postgres://") or db_url.startswith("postgresql://")))

db_adapter = DatabaseAdapter()
