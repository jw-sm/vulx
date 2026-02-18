"""
Database migration script for CVE database.
Handles creating and dropping all tables needed for CVE storage.
"""

import psycopg
from psycopg import sql

def create_tables(conn):
    """
    Create all tables neede for CVE storage.
    This builds the schema from scratch.
    """
    
    with conn.cursor() as cur:
        print("Creating cves table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(20) UNIQUE NOT NULL,
                data_type VARCHAR(50) NOT NULL,
                data_version VARCHAR(10) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)

        print("Creating cve_metadata table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_metadata(
                id SERIAL PRIMARY KEY,
                cve_id INTEGER REFERENCES cves(id) ON DELETE CASCADE,
                assigner_org_id VARCHAR(100),
                state VARCHAR(20),
                assigner_short_name VARCHAR(50),
                date_reserved TIMESTAMP,
                date_published TIMESTAMP,
                date_update TIMESTAMP
            )
        """)

        print("Creating cna_containers table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cna_containers(
                id SERIAL PRIMARY KEY,
                cve_id INTEGER REFERENCES cves(id) ON DELETE CASCADE,
                title TEXT
            )
        """)

        print("Creating descriptions table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS descriptions(
                id SERIAL PRIMARY KEY,
                cna_container_id INTEGER REFERENCES cna_container(id) ON DELETE CASCADE,
                lang VARCHAR(10),
                value TEXT
            )
        """)

        print("Creating references table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS references(
                id SERIAL PRIMARY KEY,
                cna_container_id  INTEGER REFERENCES cna_containers(id) ON DELETE CASCADE,
                url TEXT ON NULL,
                name TEXT
            )
        """)

        print("Creating reference_tags table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reference_tags(
                reference_id INTEGER REFERENCES references(id) ON DELETE CASCADE,
                tag VARCHAR(100),
                PRIMARY KEY (reference_id, tag)    
            )
        """)

        print("Creating problem_types table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS problem_types (
                id SERIAL PRIMARY KEY,
                cna_container_id INTEGER REFERENCES cna_container(id) ON DELETE CASCADE,
            )
        """)

        # TODO: cwe descriptions table
        
