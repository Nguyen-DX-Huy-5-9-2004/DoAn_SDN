#!/usr/bin/env python3
"""
Database initialization and management for DOAn_SDN
Handles PostgreSQL setup, schema creation, and data logging
"""

import os
import sys
import time
from pathlib import Path

# Try to import psycopg2, fall back to dummy implementation
try:
    import psycopg2
    from psycopg2 import sql
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False
    print("[DB] Warning: psycopg2 not installed, using mock database")

class DatabaseManager:
    """Manages PostgreSQL database for network monitoring"""
    
    def __init__(self, host='10.0.0.20', port=5432, database='onos_doан', user='postgres', password='postgres'):
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.conn = None
        self.logs_file = Path('/tmp/onos_doан_db.log')
        
    def connect(self):
        """Connect to PostgreSQL"""
        if not HAS_PSYCOPG2:
            print(f"[DB] Connecting to {self.host}:{self.port} (mock mode)")
            self.conn = {'status': 'mock'}
            return
            
        try:
            self.conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                connect_timeout=5
            )
            print(f"[DB] Connected to PostgreSQL at {self.host}:{self.port}/{self.database}")
            return True
        except Exception as e:
            print(f"[DB] Connection failed: {e}")
            print(f"[DB] Using file-based logging to {self.logs_file}")
            return False
    
    def init_schema(self):
        """Create database schema"""
        if not HAS_PSYCOPG2 or not self.conn or isinstance(self.conn, dict):
            print("[DB] Using file-based schema (mock mode)")
            return
            
        try:
            cur = self.conn.cursor()
            
            # Create tables
            create_tables = """
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                alert_type VARCHAR(50),
                severity VARCHAR(20),
                source_ip VARCHAR(15),
                dest_ip VARCHAR(15),
                score FLOAT,
                description TEXT
            );
            
            CREATE TABLE IF NOT EXISTS network_stats (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                device_id VARCHAR(50),
                packets INTEGER,
                bytes BIGINT,
                flows INTEGER
            );
            
            CREATE TABLE IF NOT EXISTS host_activity (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                host_ip VARCHAR(15),
                host_mac VARCHAR(17),
                switch_id VARCHAR(50),
                port INTEGER,
                activity VARCHAR(100)
            );
            
            CREATE TABLE IF NOT EXISTS traffic_analysis (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                src_ip VARCHAR(15),
                dst_ip VARCHAR(15),
                protocol VARCHAR(10),
                src_port INTEGER,
                dst_port INTEGER,
                packet_count INTEGER,
                byte_count BIGINT,
                anomaly_score FLOAT
            );
            """
            
            cur.execute(create_tables)
            self.conn.commit()
            cur.close()
            
            print("[DB] Schema initialized successfully")
        except Exception as e:
            print(f"[DB] Schema creation error: {e}")
    
    def log_alert(self, alert_type, severity, source_ip, dest_ip, score, description):
        """Log an alert to the database"""
        if not HAS_PSYCOPG2 or not self.conn or isinstance(self.conn, dict):
            # File-based logging
            with open(self.logs_file, 'a') as f:
                f.write(f"ALERT|{alert_type}|{severity}|{source_ip}|{dest_ip}|{score}|{description}\n")
            return
            
        try:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO alerts (alert_type, severity, source_ip, dest_ip, score, description) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (alert_type, severity, source_ip, dest_ip, score, description)
            )
            self.conn.commit()
            cur.close()
        except Exception as e:
            print(f"[DB] Log alert error: {e}")
    
    def log_network_stats(self, device_id, packets, bytes_count, flows):
        """Log network statistics"""
        if not HAS_PSYCOPG2 or not self.conn or isinstance(self.conn, dict):
            with open(self.logs_file, 'a') as f:
                f.write(f"STATS|{device_id}|{packets}|{bytes_count}|{flows}\n")
            return
            
        try:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO network_stats (device_id, packets, bytes, flows) "
                "VALUES (%s, %s, %s, %s)",
                (device_id, packets, bytes_count, flows)
            )
            self.conn.commit()
            cur.close()
        except Exception as e:
            print(f"[DB] Log stats error: {e}")
    
    def log_host_activity(self, host_ip, host_mac, switch_id, port, activity):
        """Log host activity"""
        if not HAS_PSYCOPG2 or not self.conn or isinstance(self.conn, dict):
            with open(self.logs_file, 'a') as f:
                f.write(f"ACTIVITY|{host_ip}|{host_mac}|{switch_id}|{port}|{activity}\n")
            return
            
        try:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO host_activity (host_ip, host_mac, switch_id, port, activity) "
                "VALUES (%s, %s, %s, %s, %s)",
                (host_ip, host_mac, switch_id, port, activity)
            )
            self.conn.commit()
            cur.close()
        except Exception as e:
            print(f"[DB] Log activity error: {e}")
    
    def close(self):
        """Close database connection"""
        if self.conn and not isinstance(self.conn, dict):
            self.conn.close()
            print("[DB] Connection closed")

def init_db():
    """Initialize database for DOAn_SDN"""
    db = DatabaseManager()
    print("[DB] DOAn_SDN Database Manager")
    print("[DB] Attempting to connect to PostgreSQL...")
    
    if db.connect():
        db.init_schema()
        print("[DB] Database ready!")
        
        # Test logging
        db.log_alert(
            alert_type="TEST",
            severity="INFO",
            source_ip="10.0.0.1",
            dest_ip="10.0.1.1",
            score=0.3,
            description="Database initialization test"
        )
        db.close()
    else:
        print("[DB] Using file-based logging fallback")
        print(f"[DB] Logs will be written to: {db.logs_file}")

if __name__ == '__main__':
    init_db()
