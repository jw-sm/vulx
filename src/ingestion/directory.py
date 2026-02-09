from pathlib import Path
from src.ingestion.parser import load_cve_from_file, CVERecord

script_dir = Path.cwd() 
p_src = script_dir.parent / "cvelistv5" / "cves" / "2026" / "0xxx"

if __name__ == "__main__":
    file_list = [k for k in p_src.glob('*.json')]
    file_list.sort()
    print(load_cve_from_file(file_list[3]))