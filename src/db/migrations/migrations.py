"""
Database migration script for CVE database.
Handles creating and dropping all tables needed for CVE storage.
"""

import psycopg
from src.ingestion.config import Config
from dotenv import load_dotenv

load_dotenv()


def create_tables(conn):
    """
    Create all tables needed for CVE storage.
    This builds the schema from scratch.
    """

    with conn.cursor() as cur:
        # ==========================================
        # cve
        # ==========================================
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

        # ==========================================
        # cveMetaData
        # ==========================================
        print("Creating cve_metadata table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_metadata (
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

        # ==========================================
        # containers.cna
        # ==========================================
        print("Creating cna_container table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cna_container (
                id SERIAL PRIMARY KEY,
                cve_id INTEGER REFERENCES cves(id) ON DELETE CASCADE,
                title TEXT
            )
        """)

        # ==========================================
        # containers.cna.descriptions
        # ==========================================
        print("Creating descriptions table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS descriptions (
                id SERIAL PRIMARY KEY,
                cna_container_id INTEGER REFERENCES cna_container(id) ON DELETE CASCADE,
                lang VARCHAR(10),
                value TEXT
            )
        """)

        # ==========================================
        # containers.cna.problemTypes
        # ==========================================
        print("Creating problem_types table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS problem_types (
                id SERIAL PRIMARY KEY,
                cna_container_id INTEGER REFERENCES cna_container(id) ON DELETE CASCADE
            )
        """)

        print("Creating cwe_descriptions table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cwe_descriptions (
                id SERIAL PRIMARY KEY,
                problem_type_id INTEGER REFERENCES problem_types(id) ON DELETE CASCADE,
                cwe_id VARCHAR(20),
                lang VARCHAR(10),
                description TEXT,
                type VARCHAR(50)
            )
        """)

        # ==========================================
        # containers.metrics
        # ==========================================
        print("Creating cvss_metrics table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cvss_metrics (
                id SERIAL PRIMARY KEY,
                cna_container_id INTEGER REFERENCES cna_container(id) ON DELETE CASCADE,
                attack_vector VARCHAR(20),
                attack_complexity VARCHAR(20),
                attack_requirements VARCHAR(20),
                privileges_required VARCHAR(20),
                user_interaction VARCHAR(20),
                vuln_confidentiality_impact VARCHAR(20),
                vuln_integrity_impact VARCHAR(20),
                vuln_availability_impact VARCHAR(20),
                sub_confidentiality_impact VARCHAR(20),
                sub_integrity_impact VARCHAR(20),
                sub_availability_impact VARCHAR(20),
                base_score DECIMAL(3,1),
                base_severity VARCHAR(20),
                vector_string TEXT,
                version VARCHAR(10)
            )
        """)

        # ==========================================
        # containers.cna.references
        # ==========================================
        print("Creating cve_references table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_references (
                id SERIAL PRIMARY KEY,
                cna_container_id INTEGER REFERENCES cna_container(id) ON DELETE CASCADE,
                url TEXT,
                name TEXT
            )
        """)

        print("Creating reference_tags table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reference_tags (
                reference_id INTEGER REFERENCES cve_references(id) ON DELETE CASCADE,
                tag VARCHAR(100),
                PRIMARY KEY (reference_id, tag)
            )
        """)

        # ==========================================
        # containers.cna.affected
        # ==========================================
        print("Creating affected_products table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS affected_products (
                id SERIAL PRIMARY KEY,
                cna_container_id INTEGER REFERENCES cna_container(id) ON DELETE CASCADE,
                vendor VARCHAR(255),
                product VARCHAR(255)
            )
        """)

        print("Creating affected_versions table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS affected_versions (
                id SERIAL PRIMARY KEY,
                affected_product_id INTEGER REFERENCES affected_products(id) ON DELETE CASCADE,
                version VARCHAR(100),
                status VARCHAR(50)
            )
        """)

        # ==========================================
        # containers.cna.sources
        # ==========================================
        print("Creating sources table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sources (
                id SERIAL PRIMARY KEY,
                cna_container_id INTEGER REFERENCES cna_container(id) ON DELETE CASCADE,
                advisory TEXT,
                discovery VARCHAR(50)
            )
        """)

        # ==========================================
        # metadata table to track sync state
        # ==========================================
        print("Creating sync_metadata table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sync_metadata (
                key VARCHAR(50) PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)

        print("Creating indexes...")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_metadata_state ON cve_metadata(state)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cvss_base_score ON cvss_metrics(base_score)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cvss_severity ON cvss_metrics(base_severity)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_affected_vendor ON affected_products(vendor)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_affected_product ON affected_products(product)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_date_published ON cve_metadata(date_published)")

        conn.commit()
        print("All tables are created successfully")


def drop_tables(conn):
    """
    Drop all CVE-related tables.
    """

    with conn.cursor() as cur:
        print("Dropping all tables...")

        cur.execute("DROP TABLE IF EXISTS sync_metadata CASCADE")
        cur.execute("DROP TABLE IF EXISTS sources CASCADE")
        cur.execute("DROP TABLE IF EXISTS affected_versions CASCADE")
        cur.execute("DROP TABLE IF EXISTS affected_products CASCADE")
        cur.execute("DROP TABLE IF EXISTS cvss_metrics CASCADE")
        cur.execute("DROP TABLE IF EXISTS cwe_descriptions CASCADE")
        cur.execute("DROP TABLE IF EXISTS problem_types CASCADE")
        cur.execute("DROP TABLE IF EXISTS reference_tags CASCADE")
        cur.execute("DROP TABLE IF EXISTS cve_references CASCADE")
        cur.execute("DROP TABLE IF EXISTS descriptions CASCADE")
        cur.execute("DROP TABLE IF EXISTS cna_container CASCADE")
        cur.execute("DROP TABLE IF EXISTS cve_metadata CASCADE")
        cur.execute("DROP TABLE IF EXISTS cves CASCADE")

        conn.commit()
        print("All tables dropped successfully!")


def reset_database(conn):
    print("Resetting database...")
    drop_tables(conn)
    create_tables(conn)
    print("Database reset completed")


if __name__ == "__main__":
    import sys

    DB_CONNECTION = Config.get_db_connection_string()

    if len(sys.argv) < 2:
        print("Usage: python migration.py [up|down|reset]")
        sys.exit(1)

    command = sys.argv[1]

    try:
        conn = psycopg.connect(DB_CONNECTION)

        if command == "up":
            create_tables(conn)
        elif command == "down":
            confirm = input("This will DELETE ALL DATA. Are you sure? (yes/no): ")
            if confirm.lower() == "yes":
                drop_tables(conn)
        elif command == "reset":
            confirm = input("This will DELETE ALL DATA and recreate tables. Are you sure? (yes/no): ")
            if confirm.lower() == "yes":
                reset_database(conn)

        conn.close()

    except Exception as e:
        print(f"Migration failed: {e}")
        sys.exit(1)

