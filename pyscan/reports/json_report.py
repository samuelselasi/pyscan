import json
from datetime import datetime
from pathlib import Path


class JSONReporter:
    def __init__(self, output_dir="pyscan_results"):
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def write(self, meta, findings):
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = self._dir / ("pyscan_report_" + ts + ".json")
        with path.open("w", encoding="utf-8") as f:
            json.dump({"scan_meta": meta, "findings": findings}, f, indent=2, ensure_ascii=False)
        return str(path)
