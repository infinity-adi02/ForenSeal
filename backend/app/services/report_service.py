from datetime import datetime, timezone
from io import BytesIO
import uuid
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, KeepTogether, PageBreak
from sqlalchemy.orm import Session

from ..config import settings
from ..models import AuditLog, Batch, Case, CustodyEvent, Evidence
from .hashing_service import hash_file
from .merkle_service import inclusion_proofs


INK = colors.black
ACCENT = colors.black
PALE = colors.white
RULE = colors.HexColor("#B8B8B8")
MUTED = colors.HexColor("#333333")


def _cell(text: str, style: ParagraphStyle, *, hash_value: bool = False) -> Paragraph:
    value = escape(str(text))
    if hash_value:
        value = "<br/>".join(value[i:i + 32] for i in range(0, len(value), 32))
    return Paragraph(value or "&nbsp;", style)


def _table(rows, widths, *, header=True, font_size=7.5, paddings=6):
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), paddings),
        ("RIGHTPADDING", (0, 0), (-1, -1), paddings),
        ("TOPPADDING", (0, 0), (-1, -1), paddings),
        ("BOTTOMPADDING", (0, 0), (-1, -1), paddings),
        ("GRID", (0, 0), (-1, -1), 0.35, RULE),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, PALE]),
    ]
    if header:
        commands.extend([
            ("BACKGROUND", (0, 0), (-1, 0), INK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ])
    table.setStyle(TableStyle(commands))
    return table


def generate_report(db: Session, case: Case, include_fingerprints: bool = False) -> tuple[bytes, str]:
    report_id = str(uuid.uuid4())
    generated = datetime.now(timezone.utc)
    evidence = db.query(Evidence).filter(Evidence.case_id == case.id).order_by(Evidence.id).all()
    batches = db.query(Batch).filter(Batch.case_id == case.id).order_by(Batch.created_at).all()
    audit = db.query(AuditLog).filter(AuditLog.case_id == case.id).order_by(AuditLog.sequence).all()
    custody = (db.query(CustodyEvent).join(Evidence, Evidence.id == CustodyEvent.evidence_id)
               .filter(Evidence.case_id == case.id).order_by(CustodyEvent.created_at).all())

    output = BytesIO()
    doc = SimpleDocTemplate(output, pagesize=letter, rightMargin=42, leftMargin=42,
                            topMargin=58, bottomMargin=48, title=f"ForenSeal report - {case.reference}",
                            author="ForenSeal")
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("ReportTitle", parent=base["Title"], fontName="Helvetica-Bold",
                                 fontSize=22, leading=26, textColor=INK, alignment=TA_LEFT,
                                 spaceAfter=7),
        "subtitle": ParagraphStyle("ReportSubtitle", parent=base["BodyText"], fontName="Helvetica",
                                    fontSize=9, leading=13, textColor=MUTED, spaceAfter=3),
        "section": ParagraphStyle("ReportSection", parent=base["Heading2"], fontName="Helvetica-Bold",
                                   fontSize=12, leading=15, textColor=INK, spaceBefore=14, spaceAfter=7,
                                   keepWithNext=True),
        "body": ParagraphStyle("ReportBody", parent=base["BodyText"], fontName="Helvetica",
                                fontSize=8.2, leading=11.3, textColor=INK, splitLongWords=1,
                                wordWrap="CJK", spaceAfter=3),
        "small": ParagraphStyle("ReportSmall", parent=base["BodyText"], fontName="Helvetica",
                                 fontSize=7.2, leading=9.4, textColor=MUTED, splitLongWords=1,
                                 wordWrap="CJK"),
        "hash": ParagraphStyle("ReportHash", parent=base["Code"], fontName="Courier",
                                fontSize=6.8, leading=9, textColor=INK, splitLongWords=1,
                                wordWrap="CJK"),
        "header": ParagraphStyle("TableHeader", parent=base["BodyText"], fontName="Helvetica-Bold",
                                  fontSize=7.2, leading=9, textColor=colors.white),
        "center": ParagraphStyle("ReportCenter", parent=base["BodyText"], fontName="Helvetica-Bold",
                                  fontSize=7.4, leading=9, textColor=INK, alignment=TA_CENTER),
    }

    def page_chrome(canvas, document):
        canvas.saveState()
        page_width, page_height = letter
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.6)
        canvas.line(42, page_height - 38, page_width - 42, page_height - 38)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.setFillColor(ACCENT)
        canvas.drawString(42, page_height - 29, "FORENSEAL  /  CASE INTEGRITY REPORT")
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(page_width - 42, page_height - 29, case.reference)
        canvas.line(42, 35, page_width - 42, 35)
        canvas.drawString(42, 23, f"Report {report_id}  ·  Generated {generated.strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawRightString(page_width - 42, 23, f"Page {document.page}")
        canvas.restoreState()

    story = [Paragraph("Case integrity report", styles["title"]),
             Paragraph(f"<b>{escape(case.name)}</b> &nbsp; · &nbsp; Case reference {escape(case.reference)}", styles["subtitle"]),
             Paragraph(f"Generated {generated.strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp; · &nbsp; Report ID {report_id}", styles["small"]),
             Spacer(1, 8), Paragraph("Evidence manifest", styles["section"])]

    manifest_rows = [[_cell("Evidence ID", styles["header"]), _cell("File and provenance", styles["header"]),
                      _cell("Original SHA-256", styles["header"]), _cell("Current check", styles["header"])]]
    for item in evidence:
        path = settings.storage_dir / item.storage_key
        current = hash_file(path) if path.is_file() else None
        result = "MISSING" if current is None else "VERIFIED" if current == item.original_sha256 else "TAMPERED"
        shown_hash = item.original_sha256 if include_fingerprints else "Hidden - admin code required"
        file_lines = [f"<b>{escape(item.original_filename)}</b>", f"Source: {escape(item.source_name)}"]
        if item.source_url:
            file_lines.append(f"URL: {escape(item.source_url)}")
        if item.source_scenario:
            file_lines.append(f"Scenario: {escape(item.source_scenario)}")
        manifest_rows.append([
            _cell(item.id, styles["small"]),
            Paragraph("<br/>".join(file_lines), styles["small"]),
            _cell(shown_hash, styles["hash"], hash_value=include_fingerprints),
            _cell(result, styles["center"]),
        ])
    if len(manifest_rows) == 1:
        story.append(Paragraph("No evidence has been added to this case.", styles["body"]))
    else:
        story.append(_table(manifest_rows, [100, 190, 164, 74], font_size=7.2))

    story.append(Paragraph("Merkle commitments and blockchain references", styles["section"]))
    if not batches:
        story.append(Paragraph("No batch commitment is recorded for this case.", styles["body"]))
    for batch in batches:
        details = [
            ("Batch", batch.id),
            ("Status / evidence count", f"{batch.status} / {batch.evidence_count}"),
            ("Merkle root", batch.merkle_root),
            ("Manifest commitment", batch.manifest_commitment),
            ("Chain / contract", f"{batch.chain_id or 'Not recorded'} / {batch.contract_address or 'Not recorded'}"),
            ("Transaction hash", batch.transaction_hash or "Not recorded"),
        ]
        batch_rows = [[_cell("Field", styles["header"]), _cell("Recorded value", styles["header"])]]
        for label, value in details:
            batch_rows.append([_cell(label, styles["body"]),
                               _cell(value, styles["hash"] if label in {"Merkle root", "Manifest commitment", "Transaction hash"} else styles["body"],
                                     hash_value=label in {"Merkle root", "Manifest commitment", "Transaction hash"})])
        story.append(KeepTogether([Paragraph(f"Batch {escape(batch.id[:8])}", styles["body"]),
                                   _table(batch_rows, [130, 398], header=True, paddings=5), Spacer(1, 9)]))

    if batches:
        story.append(PageBreak())
    story.append(Paragraph("Merkle inclusion proof references", styles["section"]))
    for batch in batches:
        members = sorted((item for item in evidence if item.batch_id == batch.id), key=lambda item: item.id)
        leaves = [(item.id, item.original_sha256) for item in members]
        proofs = inclusion_proofs(leaves)
        for item in members:
            proof_rows = [[_cell("Level", styles["header"]), _cell("Sibling side", styles["header"]),
                           _cell("Sibling SHA-256", styles["header"])]]
            for level, node in enumerate(proofs[item.id], start=1):
                proof_rows.append([_cell(str(level), styles["small"]), _cell(node.sibling_side, styles["small"]),
                                   _cell(node.sibling_hash, styles["hash"], hash_value=True)])
            block = [Paragraph(f"Evidence {escape(item.id)}", styles["body"]),
                     Paragraph(f"Proof verifies the original evidence fingerprint against root {escape(batch.merkle_root)}.", styles["small"])]
            if len(proof_rows) == 1:
                block.append(Paragraph("Single-file batch: the inclusion proof has no sibling nodes.", styles["small"]))
            else:
                block.append(_table(proof_rows, [55, 95, 378], paddings=4))
            block.append(Spacer(1, 7))
            story.append(KeepTogether(block))
    if not batches:
        story.append(Paragraph("No inclusion proofs are available because this case has no batches.", styles["body"]))

    story.append(Paragraph("Custody history", styles["section"]))
    custody_rows = [[_cell("Time (UTC)", styles["header"]), _cell("Custody event", styles["header"])]]
    for event in custody:
        details = (f"<b>{escape(event.event_type)} - {escape(event.outcome)}</b><br/>"
                   f"Actor: {escape(event.actor_id)} &nbsp; · &nbsp; Evidence: {escape(event.evidence_id)}<br/>"
                   f"Recipient: {escape(event.recipient or 'None')} &nbsp; · &nbsp; Transaction: {escape(event.blockchain_reference or 'Off-chain only')}<br/>"
                   f"Reason: {escape(event.reason or 'None supplied')}")
        custody_rows.append([_cell(event.created_at.strftime("%Y-%m-%d %H:%M:%S"), styles["small"]),
                             Paragraph(details, styles["small"])])
    if len(custody_rows) == 1:
        story.append(Paragraph("No custody events are recorded for this case.", styles["body"]))
    else:
        story.append(_table(custody_rows, [115, 413], paddings=5))

    story.append(Paragraph("Audit history", styles["section"]))
    audit_rows = [[_cell("Sequence / time (UTC)", styles["header"]), _cell("Recorded action", styles["header"])]]
    for row in audit:
        details = (f"<b>{escape(row.action)} - {escape(row.outcome)}</b><br/>"
                   f"Actor: {escape(row.actor_id)} &nbsp; · &nbsp; Reference: {escape(row.reference or 'None')}")
        audit_rows.append([Paragraph(f"#{row.sequence}<br/>{row.occurred_at.strftime('%Y-%m-%d %H:%M:%S')}", styles["small"]),
                           Paragraph(details, styles["small"])])
    if len(audit_rows) == 1:
        story.append(Paragraph("No audit events are recorded for this case.", styles["body"]))
    else:
        story.append(_table(audit_rows, [125, 403], paddings=5))

    story.extend([Paragraph("Methodology and limitations", styles["section"]),
                  Paragraph("SHA-256 fingerprints are recomputed from files available in protected storage at report generation time and compared with the ingestion reference. Merkle roots use domain-separated SHA-256 leaves and internal nodes. Blockchain status reflects the locally recorded deployment metadata and transaction references; independently re-check those references against the named chain and contract. A blockchain commitment does not establish who created a file, whether collection was proper, or legal admissibility. The database audit hash chain is not independent protection against an administrator able to rewrite the database.", styles["body"])])

    doc.build(story, onFirstPage=page_chrome, onLaterPages=page_chrome)
    return output.getvalue(), report_id
