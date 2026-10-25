from datetime import datetime
from html import escape
from pathlib import Path


def save_html(target, kind, results, output_path):
    cards = []
    for item in results:
        details = escape(str(item.get("details", {})))
        source = escape(str(item.get("source", "Source")))
        status = escape(str(item.get("status", "unknown")))
        summary = escape(str(item.get("summary", "")))
        url = item.get("url", "")
        link = f'<p><a href="{escape(url, quote=True)}">{escape(url)}</a></p>' if url else ""
        cards.append(
            f'<section><h2>{source}</h2><p><b>Status:</b> {status}</p>'
            f'<p>{summary}</p>{link}<pre>{details}</pre></section>'
        )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>BLADE OSINT Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#0b0e14;color:#e5edf9;max-width:1100px;margin:32px auto;padding:0 20px}}
h1{{color:#38d6a3}}section{{background:#111722;border:1px solid #293448;border-radius:12px;padding:18px;margin:16px 0}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;color:#bdc9da}}a{{color:#6c91ff}}
small{{color:#91a0b5}}
</style></head><body><h1>BLADE OSINT</h1>
<p><b>Target:</b> {escape(str(target))} &nbsp; <b>Type:</b> {escape(str(kind))}</p>
<small>Generated {datetime.now().astimezone().isoformat(timespec="seconds")}. Findings require independent verification.</small>
{''.join(cards)}</body></html>"""
    Path(output_path).write_text(document, encoding="utf-8")
    return str(output_path)
