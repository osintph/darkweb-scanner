"""
Daily threat intelligence digest — PDF builder + Mailgun delivery.
"""

import json
import logging
import os
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

MAILGUN_API_KEY = os.getenv("MAILGUN_API_KEY", "")
MAILGUN_DOMAIN = os.getenv("MAILGUN_DOMAIN", "intel.osintph.info")
MAILGUN_FROM = os.getenv("MAILGUN_FROM", "OSINT PH Threat Intel <digest@intel.osintph.info>")
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
SUBSCRIBERS_FILE = DATA_DIR / "digest_subscribers.txt"


# ── Subscriber management ──────────────────────────────────────────────────────

def load_subscribers() -> list[str]:
    if not SUBSCRIBERS_FILE.exists():
        return []
    return [
        line.strip()
        for line in SUBSCRIBERS_FILE.read_text().splitlines()
        if line.strip() and "@" in line and not line.startswith("#")
    ]


def add_subscriber(email: str) -> bool:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    existing = load_subscribers()
    if email in existing:
        return False
    existing.append(email)
    SUBSCRIBERS_FILE.write_text("\n".join(existing) + "\n")
    return True


def remove_subscriber(email: str) -> bool:
    existing = load_subscribers()
    updated = [e for e in existing if e != email]
    if len(updated) == len(existing):
        return False
    SUBSCRIBERS_FILE.write_text("\n".join(updated) + "\n")
    return True


# ── PDF builder ────────────────────────────────────────────────────────────────

def build_digest_pdf(storage, date: Optional[datetime] = None) -> bytes:
    """Build a daily digest PDF for the given date (defaults to today PHT)."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable, Image, Paragraph, SimpleDocTemplate,
        Spacer, Table, TableStyle,
    )

    if date is None:
        # PHT = UTC+8
        date = datetime.utcnow() + timedelta(hours=8)

    date_str = date.strftime("%B %d, %Y")
    date_label = date.strftime("%Y-%m-%d")

    # Fetch data
    stats = storage.get_stats()
    hits = storage.get_hits_for_report(limit=200)
    sessions = storage.get_sessions(limit=10)

    # Group hits by category
    hits_by_cat: dict[str, list] = {}
    for h in hits:
        cat = h.category or "uncategorized"
        hits_by_cat.setdefault(cat, []).append(h)

    buf = BytesIO()
    W, H = A4
    M = 20 * mm
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=M, rightMargin=M,
        topMargin=M, bottomMargin=M,
    )

    styles = getSampleStyleSheet()
    PW = W - 2 * M  # printable width

    # ── Custom styles ──
    s_title = ParagraphStyle("Title", parent=styles["Normal"],
        fontSize=20, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0d1117"), spaceAfter=2)
    s_sub = ParagraphStyle("Sub", parent=styles["Normal"],
        fontSize=9, textColor=colors.HexColor("#8b949e"), spaceAfter=2)
    s_h2 = ParagraphStyle("H2", parent=styles["Normal"],
        fontSize=12, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0d1117"), spaceBefore=14, spaceAfter=5)
    s_h3 = ParagraphStyle("H3", parent=styles["Normal"],
        fontSize=10, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#f85149"), spaceBefore=8, spaceAfter=3)
    s_body = ParagraphStyle("Body", parent=styles["Normal"],
        fontSize=8.5, textColor=colors.HexColor("#24292f"),
        leading=13, spaceAfter=4)
    s_small = ParagraphStyle("Small", parent=styles["Normal"],
        fontSize=7.5, textColor=colors.HexColor("#57606a"), leading=11)
    s_mono = ParagraphStyle("Mono", parent=styles["Normal"],
        fontSize=7, fontName="Courier",
        textColor=colors.HexColor("#0550ae"), leading=10, wordWrap="CJK")
    s_footer = ParagraphStyle("Footer", parent=styles["Normal"],
        fontSize=7, textColor=colors.HexColor("#8b949e"), leading=10)

    story = []

    # ── Header band ──
    story.append(HRFlowable(width=PW, thickness=3, color=colors.HexColor("#f85149"), spaceAfter=10))
    story.append(Paragraph("Daily Threat Intelligence", s_title))
    story.append(Paragraph("powered by OSINT PH", ParagraphStyle("Brand", parent=s_sub,
        fontSize=10, textColor=colors.HexColor("#f85149"), fontName="Helvetica-Bold")))
    story.append(Spacer(1, 2))
    story.append(Paragraph(f"Report Date: {date_str} (PHT)  ·  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", s_sub))
    story.append(HRFlowable(width=PW, thickness=0.5, color=colors.HexColor("#d0d7de"), spaceAfter=12))

    # ── Executive summary ──
    story.append(Paragraph("Executive Summary", s_h2))
    stat_data = [
        ["Metric", "Value"],
        ["Total Crawl Sessions", f"{stats['total_sessions']:,}"],
        ["Total Pages Crawled", f"{stats['total_pages']:,}"],
        ["Total Keyword Hits", f"{stats['total_hits']:,}"],
        ["Unique Keywords Triggered", str(len(stats["top_keywords"]))],
        ["Active Threat Categories", str(len(hits_by_cat))],
    ]
    stat_tbl = Table(stat_data, colWidths=[PW * 0.65, PW * 0.35])
    stat_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1117")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]))
    story.append(stat_tbl)

    # ── Top keywords ──
    if stats["top_keywords"]:
        story.append(Paragraph("Top Keywords by Hit Count", s_h2))
        kw_data = [["Keyword", "Category", "Hits"]]
        for k in stats["top_keywords"][:15]:
            kw_data.append([k["keyword"], k.get("category", "—"), str(k["count"])])
        kw_tbl = Table(kw_data, colWidths=[PW * 0.5, PW * 0.3, PW * 0.2])
        kw_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1117")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ]))
        story.append(kw_tbl)

    # ── Hits grouped by category ──
    if hits_by_cat:
        story.append(Paragraph("Intelligence Findings by Category", s_h2))
        for cat, cat_hits in sorted(hits_by_cat.items()):
            story.append(Paragraph(f"{cat.upper().replace('_', ' ')} ({len(cat_hits)} hits)", s_h3))
            hit_data = [["Keyword", "URL", "Context", "Found At"]]
            for h in cat_hits[:20]:
                found = h.found_at.strftime("%m-%d %H:%M") if h.found_at else "—"
                ctx = (h.context or "")[:100] + ("…" if len(h.context or "") > 100 else "")
                hit_data.append([
                    Paragraph(h.keyword or "", s_small),
                    Paragraph(h.url or "", s_mono),
                    Paragraph(ctx, s_small),
                    Paragraph(found, s_small),
                ])
            hit_tbl = Table(hit_data, colWidths=[PW * 0.13, PW * 0.27, PW * 0.43, PW * 0.17], repeatRows=1)
            hit_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 7.5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(hit_tbl)
            story.append(Spacer(1, 6))

    # ── Recent sessions ──
    if sessions:
        story.append(Paragraph("Recent Scan Sessions", s_h2))
        sess_data = [["Session", "Started", "Status", "Pages", "Hits"]]
        for s in sessions[:8]:
            started = (s["started_at"] or "")[:16].replace("T", " ")
            sess_data.append([
                f"#{s['id']}",
                started,
                s.get("status") or "—",
                str(s.get("pages_crawled") or 0),
                str(s.get("hits_found") or 0),
            ])
        sess_tbl = Table(sess_data, colWidths=[PW*0.1, PW*0.32, PW*0.18, PW*0.2, PW*0.2])
        sess_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1117")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("ALIGN", (2, 0), (-1, -1), "CENTER"),
        ]))
        story.append(sess_tbl)

    # ── Footer ──
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width=PW, thickness=0.5, color=colors.HexColor("#d0d7de")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "CONFIDENTIAL — Daily Threat Intelligence powered by OSINT PH · osintph.info · "
        "This report contains sensitive threat intelligence data. "
        "Do not distribute without authorization. "
        f"Report ID: OSINTPH-{date_label}",
        s_footer,
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()


# ── Mailgun delivery ───────────────────────────────────────────────────────────

def send_digest(storage, recipients: Optional[list[str]] = None, date: Optional[datetime] = None) -> dict:
    """Build PDF digest and send via Mailgun to all subscribers (or supplied list)."""
    if recipients is None:
        recipients = load_subscribers()

    if not recipients:
        return {"ok": False, "error": "No subscribers configured"}

    try:
        pdf_bytes = build_digest_pdf(storage, date=date)
    except Exception as e:
        logger.exception("Failed to build digest PDF")
        return {"ok": False, "error": f"PDF build failed: {e}"}

    if date is None:
        date = datetime.utcnow() + timedelta(hours=8)
    date_str = date.strftime("%B %d, %Y")
    date_label = date.strftime("%Y-%m-%d")
    filename = f"osintph-threat-digest-{date_label}.pdf"

    subject = f"Daily Threat Intelligence — {date_str} | OSINT PH"

    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f6f8fa;padding:24px;border-radius:8px">
      <div style="border-left:4px solid #f85149;padding-left:16px;margin-bottom:20px">
        <h2 style="margin:0;color:#0d1117;font-size:20px">Daily Threat Intelligence</h2>
        <p style="margin:4px 0 0;color:#f85149;font-weight:bold;font-size:13px">powered by OSINT PH</p>
      </div>
      <p style="color:#24292f;font-size:14px">Your daily threat intelligence digest for <strong>{date_str}</strong> is attached.</p>
      <table style="width:100%;border-collapse:collapse;margin:16px 0;background:white;border-radius:6px;overflow:hidden">
        <tr style="background:#0d1117;color:white">
          <td style="padding:8px 12px;font-size:12px;font-weight:bold">Metric</td>
          <td style="padding:8px 12px;font-size:12px;font-weight:bold;text-align:center">Value</td>
        </tr>
        <tr><td style="padding:7px 12px;font-size:12px;border-bottom:1px solid #d0d7de">Total Crawl Sessions</td><td style="padding:7px 12px;font-size:12px;text-align:center;border-bottom:1px solid #d0d7de">{storage.get_stats()['total_sessions']:,}</td></tr>
        <tr style="background:#f6f8fa"><td style="padding:7px 12px;font-size:12px;border-bottom:1px solid #d0d7de">Pages Crawled</td><td style="padding:7px 12px;font-size:12px;text-align:center;border-bottom:1px solid #d0d7de">{storage.get_stats()['total_pages']:,}</td></tr>
        <tr><td style="padding:7px 12px;font-size:12px">Keyword Hits</td><td style="padding:7px 12px;font-size:12px;text-align:center">{storage.get_stats()['total_hits']:,}</td></tr>
      </table>
      <p style="color:#57606a;font-size:12px">Please find the full detailed report attached as a PDF.</p>
      <hr style="border:none;border-top:1px solid #d0d7de;margin:20px 0"/>
      <p style="color:#8b949e;font-size:11px;margin:0">
        CONFIDENTIAL — This digest is sent to verified OSINT PH subscribers only.<br/>
        <a href="https://osintph.info" style="color:#f85149">osintph.info</a> · 
        To unsubscribe, contact <a href="mailto:hello@osintph.info" style="color:#f85149">hello@osintph.info</a>
      </p>
    </div>
    """

    text_body = (
        f"Daily Threat Intelligence powered by OSINT PH\n"
        f"Report Date: {date_str}\n\n"
        f"Your threat intelligence digest is attached as a PDF.\n\n"
        f"CONFIDENTIAL — OSINT PH subscribers only.\n"
        f"osintph.info"
    )

    errors = []
    sent = 0
    for recipient in recipients:
        try:
            resp = requests.post(
                f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
                auth=("api", MAILGUN_API_KEY),
                files=[("attachment", (filename, pdf_bytes, "application/pdf"))],
                data={
                    "from": MAILGUN_FROM,
                    "to": recipient,
                    "subject": subject,
                    "html": html_body,
                    "text": text_body,
                },
                timeout=30,
            )
            if resp.status_code == 200:
                sent += 1
                logger.info(f"Digest sent to {recipient}")
            else:
                errors.append(f"{recipient}: HTTP {resp.status_code} — {resp.text[:200]}")
                logger.error(f"Mailgun error for {recipient}: {resp.status_code} {resp.text}")
        except Exception as e:
            errors.append(f"{recipient}: {e}")
            logger.exception(f"Failed to send digest to {recipient}")

    return {
        "ok": sent > 0,
        "sent": sent,
        "total": len(recipients),
        "errors": errors,
    }
