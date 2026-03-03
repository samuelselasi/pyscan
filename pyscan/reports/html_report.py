"""HTML report generator for PyScan."""

from datetime import datetime
from pathlib import Path

SEVERITY_COLOURS = {
    "critical": "#7c1c1c",
    "high": "#a84432",
    "medium": "#b5821a",
    "low": "#1a5276",
}

CSS = """
body{font-family:'Segoe UI',sans-serif;max-width:980px;margin:auto;padding:24px;background:#f4f6f8;}
h1{color:#1a1a2e;border-bottom:3px solid #a84432;padding-bottom:8px;}
.meta-box{background:#fff;border:1px solid #ddd;padding:16px 20px;border-radius:6px;margin-bottom:28px;}
.meta-box p{margin:4px 0;font-size:0.95em;}
.finding{background:#fff;border-left:5px solid #a84432;padding:16px 20px;border-radius:6px;
         margin-bottom:18px;box-shadow:0 1px 3px rgba(0,0,0,.08);}
.finding h3{margin:0 0 12px;font-size:1.05em;color:#1a1a2e;}
table{width:100%;border-collapse:collapse;margin:8px 0 12px;}
td{padding:5px 10px;border-bottom:1px solid #eee;font-size:0.88em;vertical-align:top;}
td:first-child{font-weight:600;width:130px;color:#555;white-space:nowrap;}
pre.snippet{background:#1a1a2e;color:#a8d8a8;padding:12px;border-radius:4px;
            font-size:0.78em;overflow-x:auto;white-space:pre-wrap;margin-top:8px;}
.badge{display:inline-block;padding:2px 9px;border-radius:4px;color:#fff;
       font-size:0.8em;font-weight:700;margin-left:8px;vertical-align:middle;}
.learning{background:#e8f4fd;border-left:4px solid #2196f3;padding:10px 14px;
          border-radius:4px;margin-top:12px;font-size:0.87em;line-height:1.5;}
.none-msg{color:#888;font-style:italic;}
"""


def _badge(severity):
    colour = SEVERITY_COLOURS.get(severity, "#555")
    return (
        '<span class="badge" style="background:' + colour + '">'
        + severity.upper()
        + "</span>"
    )


def _escape(text):
    """Minimally escape HTML special characters in text."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class HTMLReporter:
    """Generates a styled HTML penetration test report."""

    def __init__(self, output_dir="pyscan_results"):
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def write(self, meta, findings):
        """Write the HTML report to disk and return the file path."""
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = self._dir / ("pyscan_report_" + ts + ".html")
        html = self._render(meta, findings)
        path.write_text(html, encoding="utf-8")
        return str(path)

    def _render(self, meta, findings):
        finding_html = ""
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "low")
            ln = f.get("learning_note", "")
            ln_html = ""
            if ln:
                ln_html = (
                    '<div class="learning"><strong>Learning Mode:</strong> '
                    + _escape(ln)
                    + "</div>"
                )

            snippet = _escape(f.get("response_snippet", ""))
            finding_html += (
                '<div class="finding">'
                "<h3>" + str(i) + ". " + _escape(f.get("title", "Finding")) + " " + _badge(sev) + "</h3>"
                "<table>"
                "<tr><td>URL</td><td>" + _escape(f.get("url", "-")) + "</td></tr>"
                "<tr><td>Parameter</td><td>" + _escape(f.get("parameter", "-")) + "</td></tr>"
                "<tr><td>Payload</td><td><code>" + _escape(f.get("payload", "-")) + "</code></td></tr>"
                "<tr><td>OWASP</td><td>" + _escape(f.get("owasp", "-")) + "</td></tr>"
                "<tr><td>Confidence</td><td>" + _escape(f.get("confidence", "-")) + "</td></tr>"
                "<tr><td>Timestamp</td><td>" + _escape(f.get("timestamp", "-")) + "</td></tr>"
                "</table>"
                '<pre class="snippet">' + snippet + "</pre>"
                + ln_html
                + "</div>\n"
            )

        if not finding_html:
            finding_html = '<p class="none-msg">No findings at this severity level.</p>'

        lm_status = "Enabled" if meta.get("learning_mode") else "Disabled"

        return (
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
            '<meta charset="utf-8">\n'
            "<title>pyscan Report - " + _escape(meta.get("target", "")) + "</title>\n"
            "<style>\n" + CSS + "\n</style>\n"
            "</head>\n<body>\n"
            "<h1>pyscan Penetration Test Report</h1>\n"
            '<div class="meta-box">\n'
            "<p><strong>Target:</strong> " + _escape(meta.get("target", "-")) + "</p>\n"
            "<p><strong>Scan Date:</strong> " + _escape(meta.get("started_at", "-")) + "</p>\n"
            "<p><strong>pyscan Version:</strong> " + _escape(meta.get("pyscan_version", "-")) + "</p>\n"
            "<p><strong>Total Findings:</strong> "
            + str(meta.get("total_findings", 0))
            + " (showing "
            + str(meta.get("filtered_findings", 0))
            + " after severity filter)</p>\n"
            "<p><strong>Learning Mode:</strong> " + lm_status + "</p>\n"
            "</div>\n"
            + finding_html
            + "\n<hr>\n"
            '<p style="color:#aaa;font-size:0.8em;">Generated by pyscan '
            + _escape(meta.get("pyscan_version", "")) + " | Educational use only | "
            "Always obtain written authorization before testing."
            "</p>\n"
            "</body>\n</html>\n"
        )
