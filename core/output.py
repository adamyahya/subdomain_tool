# core/output.py
import json
import csv
from typing import List, Dict
from pathlib import Path

def write_json(path: Path, items: List[Dict]):
    path.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")

def write_text(path: Path, lines: List[str]):
    path.write_text("\n".join(lines), encoding="utf-8")

def write_csv(path: Path, items: List[Dict]):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "ips"])
        writer.writeheader()
        for item in items:
            writer.writerow({"name": item["name"], "ips": ",".join(item["ips"])})

def write_output(path, items: List[Dict], format: str = "json"):
    """
    Write results to file in specified format (json, txt, csv).
    """
    path = Path(path).resolve()
    if format == "json":
        write_json(path, items)
    elif format == "txt":
        write_text(path, [r["name"] for r in items])
    elif format == "csv":
        write_csv(path, items)
    else:
        raise ValueError(f"Unsupported output format: {format}")
