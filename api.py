"""
api.py
======
FastAPI wrapper around the existing crypto-forensics backend
(tracer.py + rules_engine.py + legal_generator.py).

Serves:
  GET  /            -> the single-page frontend (index.html)
  POST /api/trace    -> runs trace_wallet() + RiskScoringEngine() for a
                        submitted wallet address, triggers Stage 1 chain-of-
                        custody logging and automated legal document
                        generation (BNSS Sec 94 / Interpol referral / BSA
                        Sec 63 certificate), and returns a JSON graph
                        (nodes + edges) ready for Cytoscape.js.

Run locally with:
    uvicorn api:app --reload
"""

from __future__ import annotations

import os
import sys

# Prevent Uvicorn logging crash in PyInstaller windowed mode
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from legal_generator import (
    CertificateMetadata,
    CertifyingParty,
    DeviceParticulars,
    generate_interpol_referral,
    generate_section_63_certificate,
    generate_section_94_notice,
)
from rules_engine import RiskScoringEngine
from tracer import KNOWN_VASPS, is_domestic_vasp, is_valid_eth_address, trace_wallet

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api")

# When frozen, internal files (index.html, .env) unpack to sys._MEIPASS
# External files (reports, logs) write to the .exe's actual location
if getattr(sys, 'frozen', False):
    INTERNAL_DIR = Path(sys._MEIPASS)
    EXTERNAL_DIR = Path(sys.executable).resolve().parent
else:
    INTERNAL_DIR = Path(__file__).resolve().parent
    EXTERNAL_DIR = INTERNAL_DIR

INDEX_HTML = INTERNAL_DIR / "index.html"
AUDIT_LEDGER_PATH = EXTERNAL_DIR / "audit_ledger.txt"
CASE_REPORTS_ROOT = EXTERNAL_DIR / "case_reports"

MAX_TRACE_DEPTH = 3  # kept in sync with tracer.trace_wallet's default

app = FastAPI(
    title="Crypto Forensics Tracer API",
    description="Local API for tracing on-chain fund flows, scoring laundering risk, and generating statutory legal documents.",
    version="1.0.0",
)


# --------------------------------------------------------------------------- #
# Request / response models
# --------------------------------------------------------------------------- #

class TraceRequest(BaseModel):
    victim_name: str = Field(..., description="Name of the victim/complainant reporting the incident.")
    address: str = Field(
        ..., description="Victim's wallet address - this is the trace origin, e.g. '0x...'"
    )
    max_depth: int = Field(
        default=MAX_TRACE_DEPTH, ge=1, le=8, description="Max BFS hop depth (1-8)."
    )


# --------------------------------------------------------------------------- #
# Stage 1: Intake & Chain-of-Custody
# --------------------------------------------------------------------------- #

def _record_chain_of_custody(
    victim_name: str,
    victim_wallet_address: str,
    timestamp: datetime,
) -> str:
    """
    Builds a canonical, order-fixed string from the intake data, SHA-256
    hashes it, and appends a human-readable audit entry to
    `audit_ledger.txt` alongside this file. Returns the resulting hash so
    callers can log/reference it.

    The canonical string and hash are computed at request intake, before the
    BFS trace runs, so the ledger records exactly what was requested,
    independent of trace duration or outcome.

    Canonical string: "VictimName|VictimWalletAddress|Timestamp"
    """
    timestamp_iso = timestamp.isoformat()

    canonical_string = f"{victim_name}|{victim_wallet_address}|{timestamp_iso}"
    case_hash = hashlib.sha256(canonical_string.encode("utf-8")).hexdigest()

    log_entry = (
        f"[{timestamp_iso}] "
        f"Victim: {victim_name} | "
        f"Wallet: {victim_wallet_address} | "
        f"Chain-of-Custody Hash: {case_hash}\n"
    )

    try:
        with open(AUDIT_LEDGER_PATH, "a", encoding="utf-8") as ledger:
            ledger.write(log_entry)
    except OSError:
        # Chain-of-custody logging should never silently block an
        # investigation, but a failure here is a real problem - surface it
        # loudly in the server log even though we let the trace proceed.
        logger.exception("Failed to write audit_ledger.txt entry for case hash %s", case_hash)

    logger.info("Chain-of-custody entry recorded: %s", case_hash)
    return case_hash


# --------------------------------------------------------------------------- #
# Stage 1b: Case Report Directory Management
# --------------------------------------------------------------------------- #

def _sanitize_victim_name(victim_name: str) -> str:
    """
    Sanitizes a victim's name for safe use as a directory component:
    spaces become underscores, and any character that isn't alphanumeric,
    an underscore, or a hyphen is stripped out. Falls back to "victim" if
    sanitization leaves nothing usable.
    """
    normalized = victim_name.strip().replace(" ", "_")
    sanitized = re.sub(r"[^A-Za-z0-9_-]", "", normalized)
    return sanitized or "victim"


def _get_case_report_dir(victim_name: str, case_hash: str) -> Path:
    """
    Builds (and ensures the existence of) the victim-specific case report
    directory used to hold all legal documents generated for a given trace:

        case_reports/{sanitized_victim_name}_{case_hash[:8]}/

    Returns the resulting Path so callers can write PDFs directly into it.
    """
    sanitized_name = _sanitize_victim_name(victim_name)
    case_dir = CASE_REPORTS_ROOT / f"{sanitized_name}_{case_hash[:8]}"
    case_dir.mkdir(parents=True, exist_ok=True)
    return case_dir


# --------------------------------------------------------------------------- #
# Stage 2: Automated Legal Document Generation
# --------------------------------------------------------------------------- #

def _trigger_vasp_notices(nodes: List[Dict[str, Any]], case_dir: Path) -> None:
    """
    For every traced node typed as "Exchange", routes to the appropriate
    statutory production request: a domestic VASP gets a BNSS Section 94
    notice, an offshore/unregulated VASP gets an Interpol/FIU-IND referral.
    All generated PDFs are written into the victim-specific `case_dir`.

    Document generation is best-effort: a PDF failure is logged but never
    allowed to break the trace response, since the Cytoscape graph is the
    primary deliverable of this endpoint.
    """
    exchange_nodes = [n for n in nodes if n.get("type") == "Exchange"]

    for node in exchange_nodes:
        address = node["id"]
        exchange_name = KNOWN_VASPS.get(address.lower(), "Unknown Exchange")
        safe_exchange_name = re.sub(r"[^A-Za-z0-9_-]", "_", exchange_name)

        try:
            if is_domestic_vasp(exchange_name):
                logger.info("Domestic VASP detected (%s). Generating BNSS Section 94 notice.", exchange_name)
                output_path = case_dir / f"Section_94_Notice_{safe_exchange_name}.pdf"
                generate_section_94_notice(
                    exchange_name=exchange_name,
                    exchange_address=address,
                    output_path=str(output_path),
                )
            else:
                logger.info("Offshore/unregulated VASP detected (%s). Generating Interpol/FIU-IND referral.", exchange_name)
                output_path = case_dir / f"Interpol_Referral_{safe_exchange_name}.pdf"
                generate_interpol_referral(
                    exchange_name=exchange_name,
                    exchange_address=address,
                    output_path=str(output_path),
                )
        except Exception:
            logger.exception("Failed to generate legal notice for VASP %s (%s)", exchange_name, address)


def _generate_bsa_certificate(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    assessments: Dict[str, Any],
    victim_name: str,
    case_hash: str,
    case_dir: Path,
) -> None:
    """
    Generates the Section 63 BSA digital-evidence certificate for the full
    trace, embedding the Stage 1 chain-of-custody hash into the case
    reference so the certificate is traceable back to its audit ledger
    entry. The PDF is written into the victim-specific `case_dir`.
    Best-effort: failures are logged, not raised.
    """
    payload_data = {
        "nodes": nodes,
        "edges": edges,
        "risk_assessments": [a.to_dict() for a in assessments.values()],
    }

    short_hash = case_hash[:12].upper()

    metadata = CertificateMetadata(
        case_reference=f"SIH-26183-Crypto-Trace-{short_hash}",
        description_of_electronic_record=(
            f"Automated blockchain BFS trace and heuristic risk scoring "
            f"(victim: {victim_name}). Chain-of-custody hash: {case_hash}."
        ),
        manner_of_production="Extracted via Etherscan API and processed by RiskScoringEngine.",
        place_of_certification="SIH Headquarters",
    )

    device = DeviceParticulars(
        device_type="Forensic Workstation",
        software_used="Crypto-Triage PoC v1.0",
    )

    party = CertifyingParty(
        name="Investigating Officer",
        designation="SIH Nodal Officer",
        organization="Law Enforcement Agency",
    )

    output_path = case_dir / f"Section_63_BSA_Certificate_{short_hash}.pdf"

    try:
        cert_result = generate_section_63_certificate(
            payload=payload_data,
            metadata=metadata,
            device=device,
            party=party,
            output_path=str(output_path),
        )
        logger.info("BSA Section 63 certificate generated -> %s", cert_result.output_path)
    except Exception:
        logger.exception("Failed to generate Section 63 BSA certificate for case %s", case_hash)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@app.get("/")
def serve_frontend() -> FileResponse:
    """Serves the single-page frontend."""
    if not INDEX_HTML.exists():
        raise HTTPException(status_code=500, detail="index.html not found next to api.py")
    return FileResponse(INDEX_HTML)


@app.post("/api/trace")
def api_trace(payload: TraceRequest) -> JSONResponse:
    """
    Records a Stage 1 chain-of-custody entry, runs a BFS trace from the
    victim's wallet address (tracer.trace_wallet), scores every discovered
    wallet with RiskScoringEngine, triggers the appropriate statutory legal
    documents (BNSS Section 94 notice / Interpol referral per VASP, plus a
    BSA Section 63 certificate for the whole trace) into a victim-specific
    case_reports subfolder, and returns a graph payload of the shape:

        {
          "start_address": "0x...",
          "nodes": [
            {
              "id": "0x...",
              "type": "Wallet" | "Exchange" | "Mixer" | "High-Degree Hub",
              "depth": 0,
              "is_start": true,
              "risk_score": 7.42,
              "risk_level": "HIGH",
              "flags": ["peel_chain", "high_velocity"]
            },
            ...
          ],
          "edges": [
            {
              "source": "0x...",
              "target": "0x...",
              "tx_hash": "0x...",
              "value": 1.5,
              "timestamp": 1700000000
            },
            ...
          ]
        }
    """
    # Captured immediately on entry so the chain-of-custody timestamp reflects
    # the moment the request was received, not when validation/tracing finished.
    intake_timestamp = datetime.now(timezone.utc)

    address = (payload.address or "").strip()
    victim_name = (payload.victim_name or "").strip()

    # STAGE 1 SAFEGUARD: reuse tracer's own EIP-55 format validation so the
    # API rejects malformed input before touching the network/BFS engine.
    if not is_valid_eth_address(address):
        raise HTTPException(
            status_code=400,
            detail=f"'{address}' is not a valid wallet address (expected 0x + 40 hex chars).",
        )

    if not victim_name:
        raise HTTPException(status_code=400, detail="Victim name is required.")

    # STAGE 1: INTAKE & CHAIN-OF-CUSTODY
    # Fingerprint the case inputs before the trace runs, so the ledger
    # entry reflects exactly what was requested at intake time, independent
    # of how long the BFS trace/risk scoring subsequently takes.
    case_hash = _record_chain_of_custody(
        victim_name=victim_name,
        victim_wallet_address=address,
        timestamp=intake_timestamp,
    )
    logger.info("Starting trace for case %s (victim wallet=%s)", case_hash, address)

    # STAGE 1b: Prepare the victim-specific case_reports subfolder up front
    # so both legal-document generation stages can write directly into it.
    case_dir = _get_case_report_dir(victim_name=victim_name, case_hash=case_hash)

    try:
        graph = trace_wallet(address, max_depth=payload.max_depth)
    except RuntimeError as exc:
        # e.g. missing ETHERSCAN_API_KEY in .env
        logger.exception("Trace failed due to configuration error")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - surface unexpected errors to the caller
        logger.exception("Unexpected error while tracing %s", address)
        raise HTTPException(status_code=500, detail=f"Trace failed: {exc}") from exc

    if graph.number_of_nodes() == 0:
        raise HTTPException(
            status_code=404,
            detail="No on-chain activity found for this address on the configured chain.",
        )

    # Run the laundering heuristics / risk scoring engine over the traced graph.
    engine = RiskScoringEngine(graph)
    assessments = engine.analyze()

    start_address = address.lower()

    nodes: List[Dict[str, Any]] = []
    for node_id, attrs in graph.nodes(data=True):
        assessment = assessments.get(node_id)
        if assessment is not None:
            risk_score = round(assessment.risk_score, 2)
            risk_level = assessment.risk_level.value
            flags = assessment.flags()
        else:
            # Node had no outgoing edges to analyze (e.g. terminal exchange /
            # mixer leaf) - treat as baseline low risk rather than omitting it.
            risk_score = 1.0
            risk_level = "LOW"
            flags = []

        nodes.append(
            {
                "id": node_id,
                "type": attrs.get("type", "Wallet"),
                "depth": attrs.get("depth", 0),
                "is_start": node_id == start_address,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "flags": flags,
            }
        )

    edges: List[Dict[str, Any]] = [
        {
            "source": u,
            "target": v,
            "tx_hash": data.get("tx_hash"),
            "value": data.get("value"),
            "timestamp": data.get("timestamp"),
        }
        for u, v, data in graph.edges(data=True)
    ]

    # STAGE 2: AUTOMATED LEGAL DOCUMENT GENERATION
    # Best-effort side effects - failures here are logged but never allowed
    # to break the JSON response the Cytoscape frontend depends on. All PDFs
    # land in the victim-specific case_dir created in Stage 1b.
    try:
        _trigger_vasp_notices(nodes, case_dir=case_dir)
    except Exception:
        logger.exception("Unexpected error while triggering VASP notices for case %s", case_hash)

    try:
        _generate_bsa_certificate(
            nodes=nodes,
            edges=edges,
            assessments=assessments,
            victim_name=victim_name,
            case_hash=case_hash,
            case_dir=case_dir,
        )
    except Exception:
        logger.exception("Unexpected error while generating BSA certificate for case %s", case_hash)

    # RESPONSE INTEGRITY: the exact same shape the frontend has always
    # consumed, regardless of what happened with the legal document side effects.
    return JSONResponse(
        {
            "start_address": start_address,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
        }
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)