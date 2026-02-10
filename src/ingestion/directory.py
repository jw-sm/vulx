from pathlib import Path
from typing import List, Dict, Optional
import logging
import json
from src.ingestion.parser import load_cve_from_file, CVERecord, parse_cve_record

logger = logging.getLogger(__name__)

class FileCleanupError(Exception):
    pass

def _clean_rejected_files(directory: Path, pattern: str = "*.json", encoding: str = "utf-8") -> Dict[str, List[Path]]:
    if not directory.exists():
        raise FileCleanupError(f"Directory does not exist: {directory}")

    if not directory.is_dir():
        raise FileCleanupError(f"Path is not a directory: {directory}")

    results = {'deleted': [], 'errors': []}

    try:
        file_list = list(directory.glob(pattern))
    except Exception as e:
        raise FileCleanupError(f"Failed to list files: {e}")

    logger.info(f"Processing {len(file_list)} JSON files")

    for file_path in file_list:
        try:
            # Read and parse the JSON
            with open(file_path, 'r', encoding=encoding) as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON in {file_path}: {e}")
                    results['errors'].append(file_path)
                    continue
            
            # This will parse the structure and works whether data is a dict or a list of dicts
            # TODO: Finisih the function
            has_rejected = False
            if isinstance(data, dict) and "rejectedReason" in data:
                has_rejected = True
            elif isinstance(data, list):
                has_rejected = any(isinstance(item, dict) and "rejectedReason" in item for item in data)

            


script_dir = Path.cwd() 
p_src = script_dir.parent / "cvelistv5" / "cves" / "2026" / "25xxx"


if __name__ == "__main__":
    clean_dir()
