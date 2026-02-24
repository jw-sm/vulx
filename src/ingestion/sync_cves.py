"""
CVE synchronization script.
Pulls updates from a Git repository of CVE JSON files and syncs them to PostgreSQL.
"""
from dotenv import load_dotenv
load_dotenv()

from config import Config

import subprocess
import psycopg
from pathlib import Path
from datetime import datetime
import sys

from parser import load_cve_from_file, CVEParseError
from db_operations import upsert_cve, get_last_sync_time, update_last_sync_time, get_cve_count


def run_git_command(repo_path, command):
    """
    Execute a git command in the specified repository.
    Returns the command output as a string.
    """
    result = subprocess.run(
        command,
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=True  # Raises exception if command fails
    )
    return result.stdout.strip()


def git_pull(repo_path):
    """
    Pull latest changes from the remote Git repository.
    Returns True if there were updates, False if already up to date.
    """
    print(f"Pulling latest changes from repository at {repo_path}...")
    
    try:
        output = run_git_command(repo_path, ['git', 'pull'])
        
        if "Already up to date" in output or "Already up-to-date" in output:
            print("Repository is already up to date")
            return False
        else:
            print(f"Pulled updates: {output}")
            return True
    except subprocess.CalledProcessError as e:
        print(f"Error pulling from git: {e}")
        raise


def get_modified_files_since(repo_path, since_timestamp):
    """
    Get list of JSON files modified since the given timestamp.
    Uses git log to find files that changed after the timestamp.
    
    Args:
        repo_path: Path to the git repository
        since_timestamp: ISO format timestamp string
        
    Returns:
        List of file paths relative to repo root
    """
    print(f"Finding files modified since {since_timestamp}...")
    
    try:
        # Use git log to find all JSON files modified since the timestamp
        output = run_git_command(repo_path, [
            'git', 'log',
            f'--since={since_timestamp}',
            '--name-only',
            '--pretty=format:',
            '--', '*.json'
        ])
        
        # Split output into lines and remove empty lines
        files = [f for f in output.split('\n') if f.strip()]
        
        # Remove duplicates (same file might appear in multiple commits)
        files = list(set(files))
        
        print(f"Found {len(files)} modified files")
        return files
        
    except subprocess.CalledProcessError as e:
        print(f"Error getting modified files: {e}")
        raise


def get_all_cve_files(repo_path):
    """
    Get all CVE JSON files in the repository.
    Used for initial sync when there's no last sync time.
    
    Returns list of Path objects for all .json files.
    """
    print(f"Finding all CVE files in {repo_path}...")
    
    repo = Path(repo_path)
    # Find all .json files recursively
    json_files = list(repo.rglob("*.json"))
    
    print(f"Found {len(json_files)} total CVE files")
    return [str(f.relative_to(repo)) for f in json_files]


def sync_cves(repo_path, db_connection_string, force_full_sync=False):
    """
    Main synchronization function.
    
    Args:
        repo_path: Path to the cloned CVE repository
        db_connection_string: PostgreSQL connection string
        force_full_sync: If True, sync all files regardless of last sync time
    """
    print("=" * 60)
    print("CVE Database Synchronization")
    print("=" * 60)
    
    # Connect to the database
    try:
        conn = psycopg.connect(
            dbname=Config.DB_NAME,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            host=Config.DB_HOST,
            port=int(Config.DB_PORT) if Config.DB_PORT else 5432
        )
        print(f"✓ Connected to database")
    except Exception as e:
        print(f"✗ Failed to connect to database: {e}")
        sys.exit(1)
    
    try:
        # Get current CVE count before sync
        initial_count = get_cve_count(conn)
        print(f"Current database contains {initial_count} CVEs")
        
        # Pull latest changes from Git
        had_updates = git_pull(repo_path)
        
        # Determine which files need to be processed
        if force_full_sync:
            print("Force full sync requested - processing all files")
            files_to_process = get_all_cve_files(repo_path)
        else:
            # Get the last sync time from database
            last_sync = get_last_sync_time(conn)
            
            if last_sync is None:
                print("No previous sync found - performing initial full sync")
                files_to_process = get_all_cve_files(repo_path)
            else:
                print(f"Last sync was at: {last_sync}")
                
                if not had_updates:
                    print("No new updates in repository")
                    files_to_process = []
                else:
                    # Get files modified since last sync
                    files_to_process = get_modified_files_since(repo_path, last_sync)
        
        if not files_to_process:
            print("No files to process")
            conn.close()
            return
        
        print(f"\nProcessing {len(files_to_process)} files...")
        print("-" * 60)
        
        # Track statistics
        successful = 0
        failed = 0
        skipped = 0
        
        # Process each file
        for idx, relative_path in enumerate(files_to_process, 1):
            file_path = Path(repo_path) / relative_path
            
            # Progress indicator
            if idx % 100 == 0:
                print(f"Progress: {idx}/{len(files_to_process)} files processed...")
            
            # Skip if file doesn't exist (might have been deleted)
            if not file_path.exists():
                skipped += 1
                continue
            
            try:
                # Parse the CVE JSON file
                cve = load_cve_from_file(str(file_path))
                
                # Insert or update in database
                upsert_cve(conn, cve)
                
                successful += 1
                
                # Print progress for individual files occasionally
                if idx % 50 == 0:
                    print(f"  Processed: {cve.cveMetadata.cveId}")
                
            except CVEParseError as e:
                print(f"  Parse error in {relative_path}: {e}")
                failed += 1
            except Exception as e:
                print(f"  Unexpected error processing {relative_path}: {e}")
                failed += 1
        
        # Update the last sync timestamp
        sync_time = datetime.now().isoformat()
        update_last_sync_time(conn, sync_time)
        
        # Get final count
        final_count = get_cve_count(conn)
        
        # Print summary
        print("-" * 60)
        print("\nSync Summary:")
        print(f"  Successfully processed: {successful}")
        print(f"  Failed: {failed}")
        print(f"  Skipped: {skipped}")
        print(f"  Database size: {initial_count} → {final_count} CVEs")
        print(f"  Last sync time: {sync_time}")
        print("\n✓ Sync completed successfully!")
        
    except Exception as e:
        print(f"\n✗ Sync failed: {e}")
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    import os
    
    REPO_PATH = Config.CVE_REPO_PATH
    
    # Check for command line arguments
    force_full = "--full" in sys.argv
    
    if force_full:
        print("Running full sync (all files)...")

    try:
        sync_cves(REPO_PATH, None, force_full_sync=force_full)
    except KeyboardInterrupt:
        print("\n\nSync interrupted by user")
        sys.exit(1)
