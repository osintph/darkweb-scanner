"""
Daily Threat Intelligence Digest — curated newsletter with feed data.
Separate from the crawl intelligence report (api/report/pdf).
API keys loaded from environment only — never hardcoded.
"""

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


def load_subscribers() -> list[str]:
    if not SUBSCRIBERS_FILE.exists():
        return []
    return [
        line.strip()
        for line in SUBSCRIBERS_FILE.read_text().splitlines()
        if line.strip() and "@" in line and not line.startswith("#")
    ]


def add_subscriber(email: str, name: str = "", org: str = "") -> bool:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    existing = load_subscribers()
    if email in existing:
        return False
    existing.append(email)
    SUBSCRIBERS_FILE.write_text("\n".join(existing) + "\n")
    meta_file = DATA_DIR / "digest_subscribers_meta.txt"
    with open(meta_file, "a") as f:
        f.write(f"{email}\t{name}\t{org}\t{datetime.utcnow().isoformat()}\n")
    return True


def remove_subscriber(email: str) -> bool:
    existing = load_subscribers()
    updated = [e for e in existing if e != email]
    if len(updated) == len(existing):
        return False
    SUBSCRIBERS_FILE.write_text("\n".join(updated) + "\n")
    return True


def build_digest_pdf(feed_data: dict, scanner_summary: dict = None, date: datetime = None) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    if date is None:
        date = datetime.utcnow() + timedelta(hours=8)

    date_str = date.strftime("%B %d, %Y")
    date_label = date.strftime("%Y-%m-%d")
    buf = BytesIO()
    W, H = A4
    M = 18 * mm
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=M, rightMargin=M, topMargin=M, bottomMargin=M)
    PW = W - 2 * M
    styles = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, parent=styles["Normal"], **kw)

    s_h1 = S("h1", fontSize=22, fontName="Helvetica-Bold", textColor=colors.HexColor("#0d1117"), spaceAfter=0)
    s_tagline = S("tl", fontSize=11, textColor=colors.HexColor("#f85149"), fontName="Helvetica-Bold", spaceAfter=2)
    s_meta = S("meta", fontSize=8.5, textColor=colors.HexColor("#8b949e"), spaceAfter=2)
    s_h2 = S("h2", fontSize=12, fontName="Helvetica-Bold", textColor=colors.HexColor("#0d1117"), spaceBefore=14, spaceAfter=5)
    s_h3 = S("h3", fontSize=9.5, fontName="Helvetica-Bold", textColor=colors.HexColor("#f85149"), spaceBefore=8, spaceAfter=2)
    s_body = S("body", fontSize=8.5, textColor=colors.HexColor("#24292f"), leading=13, spaceAfter=3)
    s_small = S("small", fontSize=7.5, textColor=colors.HexColor("#57606a"), leading=11, spaceAfter=2)
    s_mono = S("mono", fontSize=7, fontName="Courier", textColor=colors.HexColor("#0550ae"), leading=10, wordWrap="CJK")
    s_src = S("src", fontSize=7, textColor=colors.HexColor("#8b949e"), fontName="Helvetica-Bold")
    s_footer = S("footer", fontSize=7, textColor=colors.HexColor("#8b949e"), leading=10)

    story = []
    story.append(HRFlowable(width=PW, thickness=4, color=colors.HexColor("#f85149"), spaceAfter=8))
    story.append(Paragraph("Daily Threat Intelligence", s_h1))
    story.append(Paragraph("powered by OSINT PH", s_tagline))
    story.append(Paragraph(f"Edition: {date_str} (PHT)  ·  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ·  osintph.info", s_meta))
    story.append(HRFlowable(width=PW, thickness=0.5, color=colors.HexColor("#d0d7de"), spaceAfter=10))

    def sec(emoji, title, color="#0d1117"):
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"{emoji}  {title}", S(f"sec{title[:10]}", fontSize=12, fontName="Helvetica-Bold",
            textColor=colors.HexColor(color), spaceBefore=10, spaceAfter=4)))
        story.append(HRFlowable(width=PW, thickness=0.5, color=colors.HexColor("#d0d7de"), spaceAfter=4))

    def item_block(source, title, desc, url="", tags=None, highlight=False):
        bg = colors.HexColor("#fff8f8") if highlight else colors.HexColor("#f6f8fa")
        border = colors.HexColor("#f85149") if highlight else colors.HexColor("#d0d7de")
        tag_str = "  ".join([f"[{t}]" for t in (tags or [])[:5]])
        inner = [[Paragraph(f"<b>{title[:120]}</b>", s_body)],
                 [Paragraph((desc or "")[:350] + ("..." if len(desc or "") > 350 else ""), s_small)]]
        if tag_str:
            inner.append([Paragraph(tag_str, s_src)])
        if url:
            inner.append([Paragraph(f"Link: {url[:90]}", s_mono)])
        inner.append([Paragraph(f"Source: {source}", s_src)])
        tbl = Table(inner, colWidths=[PW - 10])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("BOX", (0, 0), (-1, -1), 0.8, border),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (0, 0), 6),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 6),
            ("TOPPADDING", (0, 1), (-1, -1), 2),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 5))

    kev = feed_data.get("cisa_kev", [])
    if kev:
        sec("CRITICAL", "CISA Known Exploited Vulnerabilities", "#f85149")
        story.append(Paragraph("Patch immediately if affected products are in use.", s_small))
        story.append(Spacer(1, 4))
        kd = [["CVE", "Vulnerability", "Vendor / Product", "Due"]]
        for v in kev[:10]:
            kd.append([Paragraph(v["cve"], s_mono), Paragraph(v["title"][:60], s_small),
                       Paragraph(f"{v['vendor']} - {v['product']}"[:50], s_small), Paragraph(v["due_date"], s_small)])
        kt = Table(kd, colWidths=[PW*0.16, PW*0.36, PW*0.30, PW*0.18], repeatRows=1)
        kt.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#f85149")),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0),(-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#fff8f8"), colors.white]),
            ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#d0d7de")),
            ("PADDING", (0,0),(-1,-1), 5),
            ("VALIGN", (0,0),(-1,-1), "TOP"),
        ]))
        story.append(kt)

    otx = feed_data.get("otx_pulses", [])
    sea_otx = [p for p in otx if p.get("sea_relevant")]
    other_otx = [p for p in otx if not p.get("sea_relevant")]
    if sea_otx:
        sec("PHILIPPINES & SEA", "Threat Intelligence — Regional Focus")
        for p in sea_otx[:6]:
            item_block(f"OTX · {p.get('author','')}", p.get("title",""), p.get("description",""),
                      p.get("url",""), p.get("tags",[])[:5], highlight=True)
    if other_otx:
        sec("GLOBAL", "Threat Intelligence (OTX)")
        for p in other_otx[:4]:
            item_block(f"OTX · {p.get('author','')}", p.get("title",""), p.get("description",""),
                      p.get("url",""), p.get("tags",[])[:4])

    rss = feed_data.get("rss", [])
    sea_rss = [r for r in rss if r.get("sea_relevant")]
    other_rss = [r for r in rss if not r.get("sea_relevant")]
    if sea_rss:
        sec("SEA NEWS", "Cybersecurity News — Philippines & Region")
        for r in sea_rss[:5]:
            item_block(r["source"], r["title"], r["description"], r.get("url",""), highlight=True)
    if other_rss:
        sec("GLOBAL NEWS", "Cybersecurity News")
        for r in other_rss[:5]:
            item_block(r["source"], r["title"], r["description"], r.get("url",""))

    urlhaus = feed_data.get("urlhaus", [])
    feodo = [f for f in feed_data.get("feodo", []) if f.get("sea_relevant")]
    if urlhaus or feodo:
        sec("MALWARE IOCs", "Active Malware Infrastructure")
        if urlhaus:
            story.append(Paragraph("Recent Malicious URLs (URLhaus)", s_h3))
            ud = [["Host", "Threat", "Tags", "Status"]]
            for u in urlhaus[:8]:
                ud.append([Paragraph(u["host"][:40], s_mono), Paragraph(u["threat"][:25], s_small),
                           Paragraph(", ".join(u["tags"][:3]), s_small), Paragraph(u["status"], s_small)])
            ut = Table(ud, colWidths=[PW*0.35, PW*0.22, PW*0.28, PW*0.15], repeatRows=1)
            ut.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#161b22")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f6f8fa"),colors.white]),
                ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#d0d7de")),("PADDING",(0,0),(-1,-1),4),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
            ]))
            story.append(ut)
        if feodo:
            story.append(Spacer(1, 6))
            story.append(Paragraph("SEA C2 Botnet IPs (Feodo Tracker)", s_h3))
            fd = [["IP", "Port", "Malware", "Country"]]
            for f in feodo[:6]:
                fd.append([f["ip"], str(f["port"]), f["malware"], f["country"]])
            ft = Table(fd, colWidths=[PW*0.3, PW*0.12, PW*0.28, PW*0.3])
            ft.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#161b22")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#fff8f8"),colors.white]),
                ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#d0d7de")),("PADDING",(0,0),(-1,-1),4),
            ]))
            story.append(ft)

    if scanner_summary and scanner_summary.get("total_hits", 0) > 0:
        sec("SCANNER", "Dark Web Scanner Summary")
        story.append(Paragraph("Brief summary only. Full Scanner Intelligence Report available separately.", s_small))
        sd = [["Metric","Value"],
              ["Keyword Hits", f"{scanner_summary.get('total_hits',0):,}"],
              ["Pages Crawled", f"{scanner_summary.get('total_pages',0):,}"],
              ["Top Keyword", scanner_summary.get("top_keyword","—")]]
        st = Table(sd, colWidths=[PW*0.6, PW*0.4])
        st.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0d1117")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8.5),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f6f8fa"),colors.white]),
            ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#d0d7de")),("PADDING",(0,0),(-1,-1),6),
            ("ALIGN",(1,0),(1,-1),"CENTER"),
        ]))
        story.append(st)

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width=PW, thickness=0.5, color=colors.HexColor("#d0d7de")))
    story.append(Spacer(1, 5))
    story.append(Paragraph(
        f"CONFIDENTIAL — Daily Threat Intelligence powered by OSINT PH · osintph.info · "
        f"To unsubscribe reply UNSUBSCRIBE · Report ID: OSINTPH-DIGEST-{date_label}", s_footer))
    doc.build(story)
    buf.seek(0)
    return buf.read()


def build_email_html(feed_data: dict, date_str: str, stats: dict) -> str:
    kev = feed_data.get("cisa_kev", [])
    sea_items = ([p for p in feed_data.get("otx_pulses",[]) if p.get("sea_relevant")] +
                 [r for r in feed_data.get("rss",[]) if r.get("sea_relevant")])[:6]
    global_items = [r for r in feed_data.get("rss",[]) if not r.get("sea_relevant")][:5]

    kev_rows = "".join([
        f'<tr style="background:{"#fff8f8" if i%2==0 else "#ffffff"}"><td style="padding:6px 10px;font-size:11px;font-family:monospace;color:#f85149;border-bottom:1px solid #d0d7de">{v["cve"]}</td><td style="padding:6px 10px;font-size:11px;border-bottom:1px solid #d0d7de">{v["title"][:60]}</td><td style="padding:6px 10px;font-size:11px;color:#57606a;border-bottom:1px solid #d0d7de">{v["vendor"]}</td></tr>'
        for i,v in enumerate(kev[:8])
    ])

    def news_rows(items, highlight=False):
        rows = ""
        for item in items:
            bg = "#fff8f8" if highlight else "#ffffff"
            rows += f'<tr style="background:{bg}"><td style="padding:10px 12px;border-bottom:1px solid #d0d7de"><div style="font-size:13px;font-weight:600;color:#0d1117;margin-bottom:3px">{item.get("title","")[:100]}</div><div style="font-size:11px;color:#57606a;margin-bottom:4px">{(item.get("description","") or "")[:200]}</div><div style="font-size:10px;color:#8b949e"><b style="color:#f85149">{item.get("source","")}</b>{f' · <a href="{item.get("url","")}" style="color:#58a6ff">Read more</a>' if item.get("url") else ""}</div></td></tr>'
        return rows

    kev_section = "" if not kev else f'''
  <div style="background:#fff8f8;border-left:4px solid #f85149;padding:16px 20px">
    <div style="font-size:13px;font-weight:700;color:#f85149;margin-bottom:8px">CISA: {len(kev)} Exploited Vulnerabilities This Week</div>
    <table style="width:100%;border-collapse:collapse;background:white">
      <tr style="background:#f85149"><th style="padding:6px 10px;font-size:11px;color:white;text-align:left">CVE</th><th style="padding:6px 10px;font-size:11px;color:white;text-align:left">Vulnerability</th><th style="padding:6px 10px;font-size:11px;color:white;text-align:left">Vendor</th></tr>
      {kev_rows}
    </table>
  </div>'''

    sea_section = "" if not sea_items else f'''
  <div style="padding:16px 20px 0">
    <div style="font-size:14px;font-weight:700;color:#0d1117;margin-bottom:8px">Philippines & SEA Focus</div>
    <table style="width:100%;border-collapse:collapse;border:1px solid #d0d7de">{news_rows(sea_items, True)}</table>
  </div>'''

    global_section = "" if not global_items else f'''
  <div style="padding:16px 20px 0">
    <div style="font-size:14px;font-weight:700;color:#0d1117;margin-bottom:8px">Global Cybersecurity News</div>
    <table style="width:100%;border-collapse:collapse;border:1px solid #d0d7de">{news_rows(global_items)}</table>
  </div>'''

    return f'''<div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;background:#f6f8fa">
  <div style="background:#0d1117;padding:24px 28px;border-bottom:4px solid #f85149">
    <div style="font-size:22px;font-weight:800;color:white;margin-bottom:2px">Daily Threat Intelligence</div>
    <div style="font-size:12px;color:#f85149;font-weight:700;margin-bottom:6px">powered by OSINT PH</div>
    <div style="font-size:11px;color:#8b949e">{date_str} · Full report attached as PDF</div>
  </div>
  {kev_section}{sea_section}{global_section}
  <div style="padding:16px 20px">
    <div style="font-size:12px;color:#57606a;background:white;border:1px solid #d0d7de;padding:12px;border-radius:4px">
      Scanner: {stats.get("total_hits",0):,} hits · {stats.get("total_pages",0):,} pages · Full report available on request.
    </div>
  </div>
  <div style="padding:14px 20px;background:#0d1117">
    <p style="color:#8b949e;font-size:11px;margin:0">CONFIDENTIAL · <a href="https://osintph.info" style="color:#f85149">osintph.info</a> · Reply UNSUBSCRIBE to opt out</p>
  </div>
</div>'''


def send_digest(storage, recipients: list = None, date: datetime = None) -> dict:
    if not MAILGUN_API_KEY:
        return {"ok": False, "error": "MAILGUN_API_KEY not set in environment"}
    if recipients is None:
        recipients = load_subscribers()
    if not recipients:
        return {"ok": False, "error": "No subscribers configured"}
    if date is None:
        date = datetime.utcnow() + timedelta(hours=8)

    date_str = date.strftime("%B %d, %Y")
    date_label = date.strftime("%Y-%m-%d")

    from .feeds import fetch_all_feeds
    try:
        feed_data = fetch_all_feeds()
    except Exception as e:
        logger.exception("Feed fetch failed")
        feed_data = {"otx_pulses":[],"cisa_kev":[],"urlhaus":[],"feodo":[],"rss":[]}

    stats = storage.get_stats()
    top_kw = stats.get("top_keywords", [{}])
    scanner_summary = {
        "total_hits": stats.get("total_hits", 0),
        "total_pages": stats.get("total_pages", 0),
        "total_sessions": stats.get("total_sessions", 0),
        "top_keyword": top_kw[0].get("keyword","—") if top_kw else "—",
    }

    try:
        pdf_bytes = build_digest_pdf(feed_data, scanner_summary=scanner_summary, date=date)
    except Exception as e:
        logger.exception("PDF build failed")
        return {"ok": False, "error": f"PDF build failed: {e}"}

    filename = f"osintph-threat-digest-{date_label}.pdf"
    subject = f"Daily Threat Intelligence - {date_str} | OSINT PH"
    html_body = build_email_html(feed_data, date_str, stats)
    text_body = f"Daily Threat Intelligence powered by OSINT PH\n{date_str}\nFull report attached.\nosintph.info"

    errors, sent = [], 0
    for recipient in recipients:
        try:
            resp = requests.post(
                f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
                auth=("api", MAILGUN_API_KEY),
                files=[("attachment", (filename, pdf_bytes, "application/pdf"))],
                data={"from": MAILGUN_FROM, "to": recipient, "subject": subject,
                      "html": html_body, "text": text_body},
                timeout=30,
            )
            if resp.status_code == 200:
                sent += 1
                logger.info(f"Digest sent to {recipient}")
            else:
                errors.append(f"{recipient}: HTTP {resp.status_code}")
        except Exception as e:
            errors.append(f"{recipient}: {e}")

    return {"ok": sent > 0, "sent": sent, "total": len(recipients), "errors": errors}
