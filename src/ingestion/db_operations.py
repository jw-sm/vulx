"""
Database operations for CVE Records.
Handles inserting, updating, and querying CVE data in Postgresql.
"""

import psycopg
from datetime import datetime
from parser import CVERecord


def upsert_cve(conn, cve: CVERecord):
    """
    Insert or update a CVE Record.
    If a CVE record already exists, delete it with its all related records, then insert a fresh CVE.
    Uses transaction to ensure atomicity. It's either everyting succeeds or nothing changes.

    Args:
        conn: psql connection object
        cve: CVERecord dataclass instance
    """

    with conn.cursor() as cur:
        try:
            # Check if the CVE exists already in db
            cur.execute(
                "SELECT id FROM cves WHERE cve_id = %s", (cve.cveMetadata.cveId,)
            )
            exists = cur.fetchone()

            if exists:
                # Delete the existing CVE and all related records
                cur.execute(
                    "DELETE FROM cves WHERE cve_id =  %s", (cve.cveMetadata.cveId,)
                )
                print(f"Deleted existing {cve.cveMetadata.cveId}")

            # Insert main cve record
            # Returns the generated primary key
            cur.execute(
                """
                INSERT INTO cves (cve_id, data_type, data_version)
                VALUES (%s, %s, %s)
                RETURNING id
            """,
                (cve.cveMetadata.cveId, cve.dataType, cve.dataVersion),
            )

            cve_id = cur.fetchone()[0]

            # Insert CVE metadata
            cur.execute(
                """
                INSERT INTO cve_metadata (
                    cve_id, assigner_org_id, state, assigner_short_name,
                    date_reserved, date_published, date_update
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    cve_id,
                    cve.cveMetadata.assignerOrgId,
                    cve.cveMetadata.state,
                    cve.cveMetadata.assignerShortName,
                    cve.cveMetadata.dateReserved,
                    cve.cveMetadata.datePublished,
                    cve.cveMetadata.dateUpdated,
                ),
            )

            if cve.containers.cna:
                cna = cve.containers.cna

                cur.execute(
                    """
                    INSERT INTO cna_containers (cve_id, title)
                    VALUES (%s, %s)
                    RETURNING id
                """,
                    (cve_id, cna.title),
                )

                cna_id = cur.fetchone()[0]

                # Insert all descriptions
                for desc in cna.descriptions:
                    cur.execute(
                        """
                        INSERT INTO descriptions (cna_container_id, lang, value)
                        VALUES (%s, %s, %s)
                    """,
                        (cna_id, desc.lang, desc.value),
                    )

                # Insert all reference and their tags
                for ref in cna.references:
                    cur.execute(
                        """
                        INSERT INTO cve_references (cna_container_id, url, name)
                        VALUES (%s, %s, %s)
                        RETURNING id
                    """,
                        (cna_id, ref.url, ref.name),
                    )

                    ref_id = cur.fetchone()[0]

                    # Insert tags for this reference
                    for tag in ref.tags:
                        cur.execute(
                            """
                            INSERT INTO reference_tags (reference_id, tag)
                            VALUES (%s, %s)
                        """,
                            (ref_id, tag),
                        )

                # Insert problem types with their CWE Description
                for pt in cna.problemTypes:
                    cur.execute(
                        """
                        INSERT INTO problem_types (cna_container_id)
                        VALUES (%s)
                        RETURNING id
                    """,
                        (cna_id,),
                    )

                    pt_id = cur.fetchone()[0]

                    # Insert CWE descriptions for this problem type
                    for cwe in pt.descriptions:
                        cur.execute(
                            """
                            INSERT INTO cwe_descriptions (
                                problem_type_id, cwe_id, lang, description, type
                            ) VALUES (%s, %s, %s, %s, %s)
                        """,
                            (pt_id, cwe.cweId, cwe.lang, cwe.description, cwe.type),
                        )

                # Insert CVSS metrics
                for metric in cna.metrics:
                    if metric.cvssV4_0:
                        cvss = metric.cvssV4_0
                        cur.execute(
                            """
                            INSERT INTO cvss_metrics (
                                cna_container_id, attack_vector, attack_complexity,
                                attack_requirements, privileges_required, user_interaction,
                                vuln_confidentiality_impact, vuln_integrity_impact,
                                vuln_availability_impact, sub_confidentiality_impact,
                                sub_integrity_impact, sub_availability_impact,
                                base_score, base_severity, vector_string, version
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                            (
                                cna_id,
                                cvss.attackVector,
                                cvss.attackComplexity,
                                cvss.attackRequirements,
                                cvss.privilegesRequired,
                                cvss.userInteraction,
                                cvss.vulnConfidentialityImpact,
                                cvss.vulnIntegrityImpact,
                                cvss.vulnAvailabilityImpact,
                                cvss.subConfidentialityImpact,
                                cvss.subIntegrityImpact,
                                cvss.subAvailabilityImpact,
                                cvss.baseScore,
                                cvss.baseSeverity,
                                cvss.vectorString,
                                cvss.version,
                            ),
                        )

                # Insert affected products and their versions
                for affected in cna.affected:
                    cur.execute(
                        """
                        INSERT INTO affected_products (cna_container_id, vendor, product)
                        VALUES (%s, %s, %s)
                        RETURNING id
                    """,
                        (cna_id, affected.vendor, affected.product),
                    )

                    product_id = cur.fetchone()[0]

                    # Insert all versions for this product
                    for version in affected.versions:
                        cur.execute(
                            """
                            INSERT INTO affected_versions (affected_product_id, version, status)
                            VALUES (%s, %s, %s)
                        """,
                            (product_id, version.version, version.status),
                        )

                # Insert source information if it exists
                if cna.source:
                    cur.execute(
                        """
                        INSERT INTO sources (cna_container_id, advisory, discovery)
                        VALUES (%s, %s, %s)
                    """,
                        (cna_id, cna.source.advisory, cna.source.discovery),
                    )

            # If we got here, everything succeeded - commit the transaction
            conn.commit()
            return True

        except Exception as e:
            # Something went wrong - rollback all changes
            conn.rollback()
            print(f"Error upserting {cve.cveMetadata.cveId}: {e}")
            raise


def get_last_sync_time(conn):
    """
    Retrieve the last successful sync timestamp from the database.
    Returns None if no sync has been performed yet.
    """
    with conn.cursor() as cur:
        cur.execute("""
            SELECT value FROM sync_metadata WHERE key = 'last_sync_time'
        """)
        result = cur.fetchone()
        return result[0] if result else None


def update_last_sync_time(conn, timestamp=None):
    """
    Update the last sync timestamp in the database.
    If timestamp is None, uses current time.
    """
    if timestamp is None:
        timestamp = datetime.now().isoformat()

    with conn.cursor() as cur:
        # Use ON CONFLICT to handle both insert and update
        cur.execute(
            """
            INSERT INTO sync_metadata (key, value, updated_at)
            VALUES ('last_sync_time', %s, NOW())
            ON CONFLICT (key) DO UPDATE
            SET value = EXCLUDED.value, updated_at = NOW()
        """,
            (timestamp,),
        )
        conn.commit()


def get_cve_count(conn):
    """
    Get the total number of CVEs in the database.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM cves")
        return cur.fetchone()[0]
