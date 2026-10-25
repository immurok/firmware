#!/usr/bin/env python3
"""Render rftest-manual.md to the RFTEST 使用说明 PDF (blue-heading style)."""
import os, sys
import markdown
from weasyprint import HTML

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "rftest-manual.md")
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "..", "RFTEST使用说明.pdf")

CSS = """
@page { size: A4; margin: 18mm 16mm 18mm 16mm;
  @bottom-center { content: counter(page) " / " counter(pages); font-size: 8pt; color:#999; }
  @bottom-right { content: "immurok IK-1 RFTEST"; font-size: 8pt; color:#ccc; } }
* { box-sizing: border-box; }
body { font-family:"Noto Sans CJK SC","Source Han Sans CN",sans-serif; font-size:10.5pt;
  line-height:1.55; color:#222; }
h1 { font-size:21pt; color:#1a1a1a; margin:0 0 18px; }
h2 { font-size:15pt; color:#1565a8; margin:22px 0 8px; border-bottom:1px solid #d6e4f0; padding-bottom:3px; }
h3 { font-size:12pt; color:#1565a8; margin:16px 0 6px; }
p,li { font-size:10.5pt; }
table { border-collapse:collapse; width:100%; font-size:9.5pt; margin:10px 0; }
th,td { border:none; border-bottom:1px solid #ddd; padding:6px 8px; text-align:left;
  vertical-align:top; word-break:break-word; }
thead th { border-bottom:2px solid #aaa; font-weight:bold; }
pre { background:#f5f5f5; border:1px solid #e2e2e2; border-radius:3px; padding:8px 10px;
  font-family:"DejaVu Sans Mono",monospace; font-size:8.6pt; line-height:1.35;
  white-space:pre-wrap; word-break:break-word; }
code { font-family:"DejaVu Sans Mono",monospace; font-size:9pt; background:#f3f3f3; padding:0 2px; }
pre code { background:none; padding:0; font-size:inherit; }
blockquote { margin:8px 0; padding:4px 12px; border-left:3px solid #c9c9c9; color:#555;
  background:#fafafa; }
hr { border:none; border-top:1px solid #ddd; margin:16px 0; }
"""


def main():
    with open(SRC, encoding="utf-8") as f:
        text = f.read()
    # First non-empty line is the title -> promote to H1.
    lines = text.splitlines()
    for idx, ln in enumerate(lines):
        if ln.strip():
            lines[idx] = "# " + ln.strip()
            break
    body = markdown.markdown("\n".join(lines),
                             extensions=["tables", "fenced_code", "sane_lists", "attr_list"])
    html = f"<html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{body}</body></html>"
    HTML(string=html, base_url=ROOT).write_pdf(OUT)
    print(f"OK -> {OUT} ({os.path.getsize(OUT)//1024} KB)")


if __name__ == "__main__":
    main()
