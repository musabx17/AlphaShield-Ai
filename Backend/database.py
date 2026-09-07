import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alphashield.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Base Table Create Karein
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            scan_type TEXT,
            target_name TEXT,
            risk_score REAL,
            is_threat INTEGER
        )
    """)
    conn.commit()

    # Automatic Column Migration for Legacy Databases
    cursor.execute("PRAGMA table_info(scan_logs)")
    existing_columns = [column[1] for column in cursor.fetchall()]

    if "engine" not in existing_columns:
        cursor.execute("ALTER TABLE scan_logs ADD COLUMN engine TEXT DEFAULT 'AlphaShield Engine'")
        conn.commit()

    if "details" not in existing_columns:
        cursor.execute("ALTER TABLE scan_logs ADD COLUMN details TEXT DEFAULT ''")
        conn.commit()

    conn.close()

def log_scan(scan_type, target_name, risk_score, is_threat, engine, details=""):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_logs (scan_type, target_name, risk_score, is_threat, engine, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_type, target_name, risk_score, 1 if is_threat else 0, engine, details))
    conn.commit()
    conn.close()

def fetch_all_logs():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, scan_type, target_name, risk_score, is_threat, engine, details FROM scan_logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows