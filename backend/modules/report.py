"""
CERNIS PRO PDF Report Generator
Creates a professional scan report using reportlab.
"""
import io
import os
from datetime import datetime
from dataclasses import dataclass
from typing import Optional

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether,
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    # ── Color palette ───────────────────────────────────────
    C_BG       = colors.HexColor("#0a0c0f")
    C_ACCENT   = colors.HexColor("#00d4ff")
    C_GREEN    = colors.HexColor("#00e676")
    C_RED      = colors.HexColor("#ff3d3d")
    C_ORANGE   = colors.HexColor("#ff9900")
    REPORTLAB_AVAILABLE = True
except Exception as _reportlab_err:
    REPORTLAB_AVAILABLE = False
    import sys
    print(f"reportlab import failed: {type(_reportlab_err).__name__}: {_reportlab_err}", file=sys.stderr, flush=True)
    # Dummy colors for when reportlab not available
    class _DummyColor:
        def HexColor(self, x): return None
    colors = _DummyColor()
    C_BG = C_ACCENT = C_GREEN = C_RED = C_ORANGE = None
C_YELLOW   = colors.HexColor("#ffe033")
C_TEXT     = colors.HexColor("#d0d8e8")
C_MUTED    = colors.HexColor("#a0b0c8")
C_ROW_ALT  = colors.HexColor("#12161e")
C_ROW_BASE = colors.HexColor("#181e28")
C_HEADER   = colors.HexColor("#1e2636")
C_BORDER   = colors.HexColor("#3a4a60")


def _sev_color(sev: str) -> object:
    return {"CRITICAL": C_RED, "HIGH": C_ORANGE,
            "MEDIUM": C_YELLOW, "LOW": C_GREEN}.get(sev.upper(), C_MUTED)


def _port_count_color(n: int) -> object:
    if n == 0: return C_GREEN
    if n < 5:  return C_YELLOW
    return C_ORANGE


def generate_report(
    scan: dict,
    fritz_status: dict = None,
    output_path: str = None,
) -> bytes:
    """
    Generate a PDF report from a scan result.
    Returns PDF bytes. If output_path given, also saves to disk.
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab not installed. Run: pip install reportlab")

    from reportlab.lib.pagesizes import landscape

    buf = io.BytesIO()
    page = landscape(A4)
    doc = SimpleDocTemplate(
        buf,
        pagesize=page,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=15*mm, bottomMargin=15*mm,
        title="CERNIS PRO — Network Scan Report",
        author="CERNIS PRO v1.0.0",
    )

    W = page[0] - 30*mm
    styles = getSampleStyleSheet()

    # ── Custom styles ──────────────────────────────────────────
    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    sTitle    = S("T", fontName="Helvetica-Bold", fontSize=22, textColor=C_ACCENT, spaceAfter=4)
    sSubtitle = S("ST", fontName="Helvetica", fontSize=11, textColor=C_MUTED, spaceAfter=16)
    sSection  = S("SEC", fontName="Helvetica-Bold", fontSize=11, textColor=C_ACCENT,
                  spaceBefore=14, spaceAfter=6, borderPadding=(0,0,4,0))
    sBody     = S("B", fontName="Helvetica", fontSize=9, textColor=C_TEXT, spaceAfter=4)
    sMono     = S("M", fontName="Courier", fontSize=8.5, textColor=C_TEXT)
    sSmall    = S("SM", fontName="Helvetica", fontSize=8, textColor=C_MUTED)
    sHostIP   = S("HIP", fontName="Courier-Bold", fontSize=9, textColor=C_ACCENT)
    sSev      = S("SEV", fontName="Helvetica-Bold", fontSize=7.5, textColor=C_TEXT)

    story = []

    # ── Header ────────────────────────────────────────────────
    now = datetime.now().strftime("%d.%m.%Y %H:%M")
    scanned_at = scan.get("scanned_at", "")
    cidr = scan.get("cidr", "—")
    hosts = scan.get("hosts", [])
    host_count = len(hosts)

    story.append(Spacer(1, 8*mm))
    story.append(Paragraph("CERNIS PRO", sTitle))
    story.append(Paragraph(f"Network Scan Report  ·  {cidr}  ·  {scanned_at or now}", sSubtitle))
    story.append(HRFlowable(width=W, thickness=1, color=C_ACCENT, spaceAfter=12))

    # ── Summary table ─────────────────────────────────────────
    unknown = sum(1 for h in hosts if not h.get("is_known") and h.get("mac"))
    total_ports = sum(len(h.get("ports") or []) for h in hosts)
    ndi_count = sum(1 for h in hosts if h.get("is_ndi"))

    summary_data = [
        ["Hosts Found", "Unknown Devices", "Open Ports", "NDI Devices", "Scan CIDR"],
        [str(host_count), str(unknown), str(total_ports), str(ndi_count), cidr],
    ]
    summary_table = Table(summary_data, colWidths=[W/5]*5)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), C_HEADER),
        ("BACKGROUND",  (0,1), (-1,1), C_ROW_BASE),
        ("TEXTCOLOR",   (0,0), (-1,0), C_MUTED),
        ("TEXTCOLOR",   (0,1), (-1,1), C_TEXT),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTNAME",    (0,1), (-1,1), "Courier-Bold"),
        ("FONTSIZE",    (0,0), (-1,0), 7),
        ("FONTSIZE",    (0,1), (-1,1), 11),
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_HEADER, C_ROW_BASE]),
        ("BOX",         (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID",   (0,0), (-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",  (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8*mm))

    # ── FritzBox section ──────────────────────────────────────
    if fritz_status and fritz_status.get("reachable"):
        story.append(Paragraph("FritzBox Status", sSection))
        fz = fritz_status
        fritz_data = [
            ["Model", "Firmware", "WAN IP", "WAN Status", "DSL Downstream", "DSL Upstream"],
            [
                fz.get("model", "—"),
                fz.get("firmware", "—"),
                fz.get("wan_ip_external", "—"),
                "Connected" if fz.get("wan_connected") else "Offline",
                f"{fz.get('dsl_downstream_kbps',0):,} kbps",
                f"{fz.get('dsl_upstream_kbps',0):,} kbps",
            ]
        ]
        ft = Table(fritz_data, colWidths=[W/6]*6)
        ft.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), C_HEADER),
            ("BACKGROUND",  (0,1), (-1,1), C_ROW_BASE),
            ("TEXTCOLOR",   (0,0), (-1,0), C_MUTED),
            ("TEXTCOLOR",   (0,1), (-1,1), C_TEXT),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTNAME",    (0,1), (-1,1), "Courier"),
            ("FONTSIZE",    (0,0), (-1,-1), 7.5),
            ("ALIGN",       (0,0), (-1,-1), "CENTER"),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
            ("BOX",         (0,0), (-1,-1), 0.5, C_BORDER),
            ("INNERGRID",   (0,0), (-1,-1), 0.5, C_BORDER),
            ("TOPPADDING",  (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ]))
        story.append(ft)
        story.append(Spacer(1, 6*mm))

    # ── Host table ────────────────────────────────────────────
    story.append(Paragraph(f"Discovered Hosts ({host_count})", sSection))

    # Landscape A4 = 277mm usable width (297 - 2×15 margins ≈ 267)
    col_w = [28*mm, 44*mm, 55*mm, 42*mm, 35*mm, W - 204*mm]
    header = ["IPv4", "MAC / Vendor", "Hostname", "OS Guess", "Open Ports", "RTT"]
    rows = [header]

    for h in sorted(hosts, key=lambda x: [int(o) for o in (x.get("ip","0.0.0.0")).split(".")]):
        ip       = h.get("ip", "")
        mac      = h.get("mac", "")
        vendor   = h.get("vendor", "")
        hostname = h.get("hostname", "") or h.get("smb_name", "") or "—"
        os_guess = (h.get("os_guess") or "—")[:30]
        ports    = h.get("ports") or []
        label    = h.get("label", "")

        mac_vendor = f"{mac}\n{vendor[:25]}" if vendor else mac or "—"
        ports_str  = ", ".join(str(p["port"]) for p in ports[:10])
        if len(ports) > 10: ports_str += f" +{len(ports)-10}"
        if label: hostname = f"{label} ({hostname})"
        rtt = h.get("rtt_ms")
        rtt_str = f"{rtt:.1f}ms" if rtt and rtt > 0 else "—"

        rows.append([
            Paragraph(ip, sHostIP),
            Paragraph(mac_vendor, sSmall),
            Paragraph(hostname[:40], sBody),
            Paragraph(os_guess, sBody),
            Paragraph(ports_str or "—", sMono),
            Paragraph(rtt_str, sMono),
        ])

    host_table = Table(rows, colWidths=col_w, repeatRows=1)
    row_colors = [C_HEADER] + [C_ROW_BASE if i%2==0 else C_ROW_ALT for i in range(len(rows)-1)]
    host_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), C_HEADER),
        ("TEXTCOLOR",   (0,0), (-1,0), C_MUTED),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,0), 7.5),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_ROW_BASE, C_ROW_ALT]),
        ("ALIGN",       (0,0), (-1,-1), "LEFT"),
        ("VALIGN",      (0,0), (-1,-1), "TOP"),
        ("BOX",         (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID",   (0,0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",  (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(host_table)

    # ── Security highlights ───────────────────────────────────
    risky = [h for h in hosts if h.get("ports") and
             any(p["port"] in [23, 445, 3389, 5900, 21] for p in h["ports"])]
    unknown_devs = [h for h in hosts if not h.get("is_known") and h.get("mac")]

    if risky or unknown_devs:
        story.append(PageBreak())
        story.append(Paragraph("Security Highlights", sSection))

        if unknown_devs:
            story.append(Paragraph(
                f"<b>{len(unknown_devs)} unknown device(s)</b> detected — not in known device database:",
                sBody))
            for h in unknown_devs[:10]:
                story.append(Paragraph(
                    f"&nbsp;&nbsp;&nbsp;• {h.get('ip')}  {h.get('mac','')}  {h.get('vendor','')}",
                    sMono))
            story.append(Spacer(1, 4*mm))

        if risky:
            story.append(Paragraph(
                f"<b>{len(risky)} host(s)</b> with potentially risky open ports:", sBody))
            for h in risky[:10]:
                risky_ports = [p["port"] for p in h["ports"] if p["port"] in [23,445,3389,5900,21]]
                story.append(Paragraph(
                    f"&nbsp;&nbsp;&nbsp;• {h.get('ip')}  [{', '.join(str(p) for p in risky_ports)}]  {h.get('hostname','') or h.get('vendor','')}",
                    sMono))

    # ── Footer ────────────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width=W, thickness=0.5, color=C_BORDER))
    story.append(Paragraph(
        f"Generated by CERNIS PRO v1.0.0  ·  {now}  ·  Scan ID: {scan.get('id', '—')}",
        S("F", fontName="Helvetica", fontSize=8, textColor=C_TEXT,
          alignment=TA_CENTER, spaceBefore=4)
    ))

    doc.build(story)
    pdf_bytes = buf.getvalue()

    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes
