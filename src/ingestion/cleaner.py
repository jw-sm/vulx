from pathlib import Path
from typing import List, Dict
import logging
import json

logger = logging.getLogger(__name__)


class FileCleanupError(Exception):
    pass


# ==============================================================================
# Helpers
# ==============================================================================


def _contains_rejected(data: dict) -> bool:
    if not isinstance(data, dict):
        raise TypeError("data must be a dict")
    return bool(data.get("containers", {}).get("cna", {}).get("rejectedReasons"))


def remove_rejected_files(
    directory: Path, pattern: str = "*.json", encoding: str = "utf-8"
) -> Dict[str, List[Path]]:
    """
    Removes *.json files inside a directory that has "rejectedReasons" key

    Traverses through all the sub-directories and removes json files that
    contains "rejectedReasons" key. These files are irrelevant to the dataset
    thus needs deletion.

    Args:
        directory: A Path object that contains the dir
        pattern: pattern of the file to be deleted
        encoding: encoding of the file

    Returns:
        Returns the number of deleted files, and errors encountered

    Raises:
        FileCleanupError if:
            - if dir doesnt exist
            - Path is not dir
            - failed to convert rglob's generator to list
    """
    if not directory.exists():
        raise FileCleanupError(f"Directory does not exist: {directory}")

    if not directory.is_dir():
        raise FileCleanupError(f"Path is not a directory: {directory}")

    results = {"deleted": [], "errors": []}

    try:
        file_list = list(directory.rglob(pattern))
    except Exception as e:
        raise FileCleanupError(f"Failed to list files: {e}")

    logger.info(f"Processing {len(file_list)} JSON files")

    for file_path in file_list:
        try:
            with open(file_path, "r", encoding=encoding) as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON in {file_path}: {e}")
                    results["errors"].append(file_path)
                    continue

            if _contains_rejected(data):
                try:
                    file_path.unlink()
                    logger.info(f"Deleted {file_path}")
                    results["deleted"].append(file_path)
                except (PermissionError, OSError) as e:
                    logger.error(f"Failed to delete {file_path}: {e}")
                    results["errors"].append(file_path)

        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}", exc_info=True)
            results["errors"].append(file_path)
    logger.info(
        f"Deleted {len(results['deleted'])} files with {len(results['errors'])} errors"
    )
    return results


_SCRIPT_DIR = Path.cwd()
_DATA_SRC = script_dir.parent / "cvelistv5" / "cves" / "2022"

if __name__ == "__main__":
    remove_rejected_files(_DATA_SRC)
