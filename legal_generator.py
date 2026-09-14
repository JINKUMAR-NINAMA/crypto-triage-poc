"""
legal_generator.py
===================
Generates a formal certificate under Section 63 of the BSA, 2023 
and Section 94 of the BNSS, 2023 for crypto forensics.
"""

from __future__ import annotations

import os
import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Union

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

HASH_ALGORITHM = "SHA-256"

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class DeviceParticulars:
    device_type: str
    manufacturer_model: str = "N/A"
    serial_number: str = "N/A"
    operating_system: str = "N/A"
    software_used: str = "N/A"
    location: str = "N/A"
    network_details: str = "N/A"

@dataclass
class CertifyingParty:
    name: str
    designation: str
    organization: str = ""
    address: str = ""
    contact: str = ""

@dataclass
class ExpertDetails:
    name: str
    designation: str
    qualifications: str = ""
    organization: str = ""
    contact: str = ""

@dataclass
class CertificateMetadata:
    case_reference: str
    description_of_electronic_record: str
    manner_of_production: str
    court_name: str = ""
    place_of_certification: str = ""
    date_of_certification: date = field(default_factory=date.today)
    additional_statements: List[str] = field(default_factory=list)

@dataclass
class CertificateResult:
    output_path: str
    payload_hash: str
    hash_algorithm: str
    certificate_id: str
    generated_at: datetime

# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #

def canonicalize_payload(payload: Union[str, bytes, Dict, List]) -> bytes:
    if isinstance(payload, (dict, list)):
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
        ).encode("utf-8")
    if isinstance(payload, str):
        return payload.encode("utf-8")
    if isinstance(payload, bytes):
        return payload
    raise TypeError("Unsupported payload type for hashing")

def compute_payload_hash(payload: Union[str, bytes, Dict, List]) -> str:
    data = canonicalize_payload(payload)
    return hashlib.sha256(data).hexdigest()

# --------------------------------------------------------------------------- #
# PDF styling helpers
# --------------------------------------------------------------------------- #

def _build_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles: Dict[str, ParagraphStyle] = {}
    styles["Title"] = ParagraphStyle("CertTitle", parent=base["Title"], fontSize=13, leading=17, alignment=TA_CENTER, spaceAfter=4)
    styles["Subtitle"] = ParagraphStyle("CertSubtitle", parent=base["Normal"], fontSize=9.5, leading=13, alignment=TA_CENTER, textColor=colors.HexColor("#444444"), spaceAfter=14)
    styles["SectionHeading"] = ParagraphStyle("SectionHeading", parent=base["Heading2"], fontSize=11.5, leading=15, spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#1a1a1a"))
    styles["SubHeading"] = ParagraphStyle("SubHeading", parent=base["Heading3"], fontSize=10, leading=13, spaceBefore=8, spaceAfter=4)
    styles["Body"] = ParagraphStyle("Body", parent=base["Normal"], fontSize=9.7, leading=14, alignment=TA_JUSTIFY, spaceAfter=6)
    styles["Clause"] = ParagraphStyle("Clause", parent=styles["Body"], leftIndent=14)
    styles["Mono"] = ParagraphStyle("Mono", parent=base["Normal"], fontName="Courier", fontSize=8.7, leading=12, textColor=colors.HexColor("#0a0a0a"))
    styles["Small"] = ParagraphStyle("Small", parent=base["Normal"], fontSize=7.8, leading=10.5, textColor=colors.HexColor("#666666"))
    styles["Label"] = ParagraphStyle("Label", parent=base["Normal"], fontSize=9.2, leading=13, fontName="Helvetica-Bold")
    return styles

def _field_table(rows: List[List[str]], styles: Dict[str, ParagraphStyle]) -> Table:
    data = [[Paragraph(f"{label}", styles["Label"]), Paragraph(str(value), styles["Body"])] for label, value in rows]
    table = Table(data, colWidths=[5.2 * cm, 10.8 * cm])
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 2), ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#dddddd"))]))
    return table

def _signature_block(role_label: str, name: str, designation: str, styles: Dict) -> Table:
    data = [
        [Paragraph("Signature:", styles["Body"]), Paragraph("_" * 34, styles["Body"])],
        [Paragraph("Name:", styles["Body"]), Paragraph(name or "_" * 34, styles["Body"])],
        [Paragraph("Designation:", styles["Body"]), Paragraph(designation or "_" * 34, styles["Body"])],
        [Paragraph("Date:", styles["Body"]), Paragraph("_" * 34, styles["Body"])],
    ]
    table = Table(data, colWidths=[3.2 * cm, 8 * cm])
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3)]))
    return KeepTogether([Paragraph(role_label, styles["SubHeading"]), table])

# --------------------------------------------------------------------------- #
# Certificate generation (Section 63 BSA)
# --------------------------------------------------------------------------- #

def generate_section_63_certificate(
    payload: Union[str, bytes, Dict, List],
    metadata: CertificateMetadata,
    device: DeviceParticulars,
    party: CertifyingParty,
    expert: Optional[ExpertDetails] = None,
    output_path: str = "section_63_certificate.pdf",
) -> CertificateResult:
    
    payload_hash = compute_payload_hash(payload)
    generated_at = datetime.now()
    certificate_id = _make_certificate_id(metadata.case_reference, payload_hash, generated_at)

    styles = _build_styles()
    story: List = []

    _add_header(story, styles, metadata, certificate_id)
    _add_recital(story, styles)
    _add_part_a(story, styles, metadata, device, party, payload_hash)
    if expert is not None:
        _add_part_b(story, styles, expert, payload_hash)
    else:
        story.append(Spacer(1, 10))
        story.append(Paragraph("Part B (Expert Certificate) has not been completed.", styles["Small"]))
    _add_footer_note(story, styles, generated_at, certificate_id)

    doc = SimpleDocTemplate(
        output_path, pagesize=A4, topMargin=1.8 * cm, bottomMargin=1.8 * cm, leftMargin=2.0 * cm, rightMargin=2.0 * cm,
        title=f"Section 63 BSA Certificate - {metadata.case_reference}", author=party.name,
    )
    doc.build(story)

    return CertificateResult(output_path=output_path, payload_hash=payload_hash, hash_algorithm=HASH_ALGORITHM, certificate_id=certificate_id, generated_at=generated_at)

def _make_certificate_id(case_reference: str, payload_hash: str, generated_at: datetime) -> str:
    basis = f"{case_reference}|{payload_hash}|{generated_at.isoformat()}"
    short = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12].upper()
    return f"BSA63-{short}"

def _add_header(story: List, styles: Dict, metadata: CertificateMetadata, certificate_id: str) -> None:
    if metadata.court_name:
        story.append(Paragraph(metadata.court_name, styles["Subtitle"]))
    story.append(Paragraph("CERTIFICATE UNDER SECTION 63 OF THE<br/>BHARATIYA SAKSHYA ADHINIYAM, 2023", styles["Title"]))
    story.append(Paragraph("(Certificate as to electronic record, read with the Schedule to the Act)", styles["Subtitle"]))
    story.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#999999")))
    story.append(Spacer(1, 8))
    header_rows = [["Case / Reference No.", metadata.case_reference], ["Certificate ID", certificate_id], ["Date of Certification", metadata.date_of_certification.strftime("%d %B %Y")], ["Place of Certification", metadata.place_of_certification or "N/A"]]
    story.append(_field_table(header_rows, styles))
    story.append(Spacer(1, 6))

def _add_recital(story: List, styles: Dict) -> None:
    story.append(Paragraph("I/We, the undersigned, do hereby certify as follows...", styles["Body"]))

def _add_part_a(story: List, styles: Dict, metadata: CertificateMetadata, device: DeviceParticulars, party: CertifyingParty, payload_hash: str) -> None:
    story.append(Paragraph("PART A &ndash; CERTIFICATE BY PERSON IN CHARGE", styles["SectionHeading"]))
    story.append(Paragraph("(a) Identification of the electronic record and manner of production", styles["SubHeading"]))
    story.append(Paragraph(metadata.description_of_electronic_record, styles["Clause"]))
    story.append(Paragraph(metadata.manner_of_production, styles["Clause"]))
    story.append(Paragraph("(b) Particulars of the device / computer / communication device", styles["SubHeading"]))
    device_rows = [["Device type", device.device_type], ["Manufacturer / model", device.manufacturer_model], ["Serial / asset number", device.serial_number], ["Operating system", device.operating_system], ["Software used for production", device.software_used], ["Location of device", device.location], ["Network details", device.network_details]]
    story.append(_field_table(device_rows, styles))
    story.append(Paragraph("(c) Cryptographic hash of the certified electronic record", styles["SubHeading"]))
    story.append(Spacer(1, 4))
    story.append(_hash_box(payload_hash, styles))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Particulars of the certifying party", styles["SubHeading"]))
    party_rows = [["Name", party.name], ["Designation", party.designation], ["Organization", party.organization or "N/A"], ["Address", party.address or "N/A"], ["Contact", party.contact or "N/A"]]
    story.append(_field_table(party_rows, styles))
    story.append(Spacer(1, 10))
    story.append(_signature_block("Signature of person in charge of the device / activities", party.name, party.designation, styles))

def _add_part_b(story: List, styles: Dict, expert: ExpertDetails, payload_hash: str) -> None:
    story.append(Spacer(1, 14))
    story.append(Paragraph("PART B &ndash; CERTIFICATE BY EXPERT", styles["SectionHeading"]))
    story.append(_hash_box(payload_hash, styles, label="Hash independently verified by expert"))
    story.append(Spacer(1, 10))
    story.append(_signature_block("Signature of expert", expert.name, expert.designation, styles))

def _hash_box(payload_hash: str, styles: Dict, label: str = "SHA-256 hash of electronic record") -> Table:
    data = [[Paragraph(f"<b>{label}:</b>", styles["Body"])], [Paragraph(payload_hash, styles["Mono"])]]
    table = Table(data, colWidths=[16 * cm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f4f4")), ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#bbbbbb")), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8)]))
    return table

def _add_footer_note(story: List, styles: Dict, generated_at: datetime, certificate_id: str) -> None:
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Document generated: {generated_at.strftime('%d %B %Y, %H:%M:%S')} &middot; Certificate ID: {certificate_id} &middot; Hash algorithm: {HASH_ALGORITHM}", styles["Small"]))

# --------------------------------------------------------------------------- #
# Notice generation (Section 94 BNSS)
# --------------------------------------------------------------------------- #

def get_next_pdf_path(folder: str = "notices") -> str:
    """Finds the next sequential integer filename (1.pdf, 2.pdf, etc.)."""
    os.makedirs(folder, exist_ok=True)
    existing = [
        int(f.split(".")[0]) for f in os.listdir(folder) 
        if f.endswith(".pdf") and f.split(".")[0].isdigit()
    ]
    next_num = max(existing, default=0) + 1
    return os.path.join(folder, f"{next_num}.pdf")

def generate_section_94_notice(
    exchange_name: str,
    exchange_address: str,
    output_path: Optional[str] = None,
    folder: str = "notices",
) -> str:
    """
    Generates a Section 94 BNSS production notice.

    If `output_path` is supplied, the PDF is written there directly (used
    when the caller wants the document placed inside a specific,
    e.g. victim-specific, case folder). Otherwise falls back to the legacy
    sequential-numbering behaviour inside `folder`.
    """
    if output_path is None:
        output_path = get_next_pdf_path(folder)
    else:
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4
    
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * cm, height - 2 * cm, "ORDER FOR PRODUCTION OF DOCUMENTS / DIGITAL EVIDENCE")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(1 * cm, height - 2.8 * cm, "Under Section 94, Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023")
    
    c.setFont("Helvetica", 11)
    text = c.beginText(1 * cm, height - 4 * cm)
    text.setLeading(14)
    
    body_content = [
        f"To: Compliance Officer / Nodal Officer, {exchange_name}",
        f"Subject Wallet Address: {exchange_address}",
        "",
        "Whereas it has been made to appear to this authority that the production of",
        "KYC documents, transaction logs, and digital evidence pertaining to the",
        "above-mentioned wallet address is necessary for the purposes of an",
        "ongoing investigation into illicit fund routing.",
        "",
        "Under Section 94 of the BNSS, 2023, law enforcement and courts are empowered",
        "to require the production of documents and electronic communications likely",
        "to contain digital evidence.",
        "",
        "You are hereby directed to produce the following within 48 hours:",
        "1. Complete KYC (Know Your Customer) details of the account holder.",
        "2. IP access logs and device IDs associated with this wallet.",
        "3. A complete ledger of internal transfers post-deposit.",
        "",
        "Failure to comply may result in further legal proceedings.",
        "",
        "Date: ___________________",
        "Signature: _______________",
        "Designation: Investigating Officer"
    ]
    
    for line in body_content:
        text.textLine(line)
        
    c.drawText(text)
    c.save()
    print(f"[+] SUCCESS: Legal notice saved -> {output_path}")
    return output_path


# --------------------------------------------------------------------------- #
# Interpol / FIU-IND Referral generation (offshore VASP terminal endpoints)
# --------------------------------------------------------------------------- #

def generate_interpol_referral(
    exchange_name: str,
    exchange_address: str,
    output_path: Optional[str] = None,
    folder: str = "referrals",
) -> str:
    """
    Generates a FIU-IND / Interpol referral document for terminal traces
    that resolve to an offshore or non-compliant VASP where a domestic
    SAHYOG / Section 94 BNSS production order cannot be enforced directly.

    This corresponds to Stage 2 "VASP Classification & Confidence Gating" of
    the workflow: offshore / unregulated VASPs are auto-routed to this
    referral template instead of a domestic freeze notice.

    If `output_path` is supplied, the PDF is written there directly (used
    when the caller wants the document placed inside a specific,
    e.g. victim-specific, case folder). Otherwise falls back to the legacy
    sequential-numbering behaviour inside `folder`.
    """
    if output_path is None:
        output_path = get_next_pdf_path(folder)
    else:
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * cm, height - 2 * cm, "INTERNATIONAL REFERRAL FOR MUTUAL LEGAL ASSISTANCE")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(1 * cm, height - 2.8 * cm, "FIU-IND / INTERPOL Referral - Offshore Virtual Asset Service Provider")

    c.setFont("Helvetica", 11)
    text = c.beginText(1 * cm, height - 4 * cm)
    text.setLeading(14)

    body_content = [
        f"To: Financial Intelligence Unit - India (FIU-IND) / INTERPOL National Central Bureau",
        f"Subject Exchange / VASP: {exchange_name}",
        f"Subject Wallet Address: {exchange_address}",
        "",
        "Whereas the blockchain trace conducted pursuant to an ongoing investigation",
        "into illicit fund routing has identified the above wallet address as being",
        "held by, or associated with, a Virtual Asset Service Provider that is",
        "offshore, unregulated, or otherwise outside the direct jurisdiction of",
        "Indian domestic production-order mechanisms (SAHYOG / Section 94 BNSS).",
        "",
        "This matter is accordingly referred for action through international",
        "cooperation channels, including but not limited to:",
        "1. Request for KYC and account-opening records via FIU-IND's foreign",
        "   counterpart Financial Intelligence Unit (Egmont Group channel).",
        "2. Request for preservation and disclosure of transaction/IP logs via",
        "   INTERPOL Purple Notice / diffusion, or a Mutual Legal Assistance",
        "   Treaty (MLAT) request as applicable.",
        "3. Coordination with the exchange's compliance desk directly, where a",
        "   voluntary law-enforcement request channel exists.",
        "",
        "Investigators are advised that, absent domestic jurisdiction, this",
        "wallet CANNOT be frozen directly by a Section 94 BNSS order and",
        "requires the above referral route for further action.",
        "",
        "Date: ___________________",
        "Signature: _______________",
        "Designation: Investigating Officer / Nodal Officer, FIU-IND Liaison",
    ]

    for line in body_content:
        text.textLine(line)

    c.drawText(text)
    c.save()
    print(f"[+] SUCCESS: Interpol/FIU-IND referral saved -> {output_path}")
    return output_path


# --------------------------------------------------------------------------- #
# Case Intake Record (Stage 1 chain-of-custody evidentiary summary)
# --------------------------------------------------------------------------- #

def generate_intake_report(
    case_reference: str,
    victim_name: str,
    victim_wallet: str,
    intake_timestamp: datetime,
    case_hash: str,
    output_path: str,
) -> str:
    """
    Generates the Case Intake Record: a one-page evidentiary summary fixing
    the Complainant/Victim Name, Victim Wallet, Intake UTC Timestamp, and
    the Stage 1 chain-of-custody SHA-256 hash, so that every case's
    evidentiary dossier documents exactly what was reported at intake,
    independent of trace outcome.
    """
    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * cm, height - 2 * cm, "CASE INTAKE RECORD")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(1 * cm, height - 2.8 * cm, "Stage 1 Chain-of-Custody Intake Certification")

    c.setFont("Helvetica", 11)
    text = c.beginText(1 * cm, height - 4 * cm)
    text.setLeading(16)

    body_content = [
        f"Case Reference: {case_reference}",
        "",
        f"Complainant / Victim Name: {victim_name}",
        f"Victim Wallet Address: {victim_wallet}",
        f"Intake Timestamp (UTC): {intake_timestamp.isoformat()}",
        "",
        "Chain-of-Custody Cryptographic Hash (SHA-256):",
        case_hash,
        "",
        "This record certifies that the above intake particulars were captured",
        "at the commencement of the investigation, prior to any blockchain",
        "trace, risk scoring, or downstream legal document generation, and are",
        "fixed immutably by the accompanying SHA-256 hash entered into the",
        "audit ledger (audit_ledger.txt) at the moment of intake.",
        "",
        "Date: ___________________",
        "Signature: _______________",
        "Designation: Investigating Officer / SIH Nodal Officer",
    ]

    for line in body_content:
        text.textLine(line)

    c.drawText(text)
    c.save()
    print(f"[+] SUCCESS: Case intake record saved -> {output_path}")
    return output_path


# --------------------------------------------------------------------------- #
# Fallback BNSS Section 94 Preservation Order (no exchange/VASP identified)
# --------------------------------------------------------------------------- #

def generate_preservation_order(
    terminal_wallets: List[str],
    case_hash: str,
    output_path: str,
) -> str:
    """
    Generates a fallback BNSS Section 94 preservation & monitoring order for
    cases where the trace never resolved to a known exchange/VASP node.
    Addressed generically to "Relevant Virtual Asset Custodians /
    Intermediaries" rather than a named exchange, and lists every terminal
    (leaf) wallet discovered during the BFS trace, so that any custodian
    later identified as holding one of these addresses is already on notice
    to preserve and monitor it.
    """
    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * cm, height - 2 * cm, "ORDER FOR PRESERVATION & MONITORING OF DIGITAL EVIDENCE")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(1 * cm, height - 2.8 * cm, "Under Section 94, Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023")

    c.setFont("Helvetica", 11)
    text = c.beginText(1 * cm, height - 4 * cm)
    text.setLeading(14)

    body_content = [
        "To: Relevant Virtual Asset Custodians / Intermediaries",
        f"Reference Chain-of-Custody Hash: {case_hash}",
        "",
        "Whereas the blockchain trace conducted pursuant to an ongoing",
        "investigation into illicit fund routing has not, at this stage,",
        "resolved to any identified regulated Virtual Asset Service Provider,",
        "and whereas the following wallet address(es) represent the terminal",
        "suspect endpoints discovered during the trace:",
        "",
    ]

    if terminal_wallets:
        for addr in terminal_wallets:
            body_content.append(f"   - {addr}")
    else:
        body_content.append("   - (no terminal wallets identified)")

    body_content += [
        "",
        "Under Section 94 of the BNSS, 2023, any Virtual Asset Custodian or",
        "Intermediary subsequently identified as holding, controlling, or",
        "processing transactions for the above wallet address(es) is hereby",
        "directed to:",
        "1. Preserve all KYC records, transaction logs, and account data",
        "   associated with the above address(es) pending further orders.",
        "2. Place the above address(es) under active monitoring and report",
        "   any further inbound/outbound activity to the investigating",
        "   authority without delay.",
        "3. Refrain from disclosing the existence of this preservation order",
        "   to the account holder(s), where legally permissible.",
        "",
        "This is a preservation and monitoring directive issued in the",
        "absence of a confirmed custodian; it is superseded by a",
        "custodian-specific Section 94 production notice or Interpol/FIU-IND",
        "referral upon subsequent identification of the relevant VASP.",
        "",
        "Date: ___________________",
        "Signature: _______________",
        "Designation: Investigating Officer",
    ]

    for line in body_content:
        text.textLine(line)

    c.drawText(text)
    c.save()
    print(f"[+] SUCCESS: BNSS Sec 94 preservation order saved -> {output_path}")
    return output_path