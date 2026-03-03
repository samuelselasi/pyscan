import json
import re
from datetime import datetime
from pathlib import Path

_SENSITIVE = re.compile(
    r"(password|passwd|secret|token|api.key|db.pass|app.key|auth|credential|private.key|access.key|client.secret)",
    re.IGNORECASE,
)
_MASK = "[REDACTED]"

def _mask_dict(obj):
    if isinstance(obj, dict):
        return {k: _MASK if _SENSITIVE.search(k) and isinstance(v, str) else _mask_dict(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_dict(item) for item in obj]
    return obj

class EvidenceStore:
    def __init__(self, output_dir="pyscan_results"):
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self._base = Path(output_dir) / "evidence" / timestamp
        self._base.mkdir(parents=True, exist_ok=True)
        self._counter = 0

    @property
    def evidence_dir(self):
        return self._base

    def save(self, finding):
        self._counter += 1
        safe = _mask_dict(finding)
        slug = re.sub(r"[^a-z0-9]+", "_", finding.get("title", "finding").lower())
        path = self._base / f"{self._counter:03d}_{slug}.json"
        with path.open("w", encoding="utf-8") as fh:
            json.dump(safe, fh, indent=2, ensure_ascii=False)
        return path

    def list_evidence(self):
        return sorted(self._base.glob("*.json"))
