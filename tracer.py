"""
tracer.py
----------
Core analytics engine for tracking illicit fund flows on Ethereum/EVM networks.
Uses Breadth-First Search (BFS) to map transactions and automatically generates
legal notices when funds hit a known centralized exchange (VASP).
"""

import os
import re
import time
import json
from collections import deque

import requests
import networkx as nx

# Import our custom PDF generators and Risk Engine
from legal_generator import (
    generate_section_94_notice,
    generate_interpol_referral,
    generate_section_63_certificate,
    CertificateMetadata,
    DeviceParticulars,
    CertifyingParty
)
from rules_engine import RiskScoringEngine

from pathlib import Path

# Explicitly find and load .env from the directory containing tracer.py
BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=ENV_PATH, override=True)
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Config & Database Loading
# ---------------------------------------------------------------------------

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"
CHAIN_ID = 11155111  # 11155111 is the Sepolia Testnet. Change to 1 for Ethereum Mainnet.

def load_known_vasps(filepath: str = "known_vasps.json") -> dict:
    """
    Loads exchange addresses from the JSON database.
    CRITICAL: Converts all mixed-case addresses (Checksums) to strict lowercase
    so Python can mathematically match them against the Etherscan API data.
    """
    if not os.path.exists(filepath):
        return {}
    
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    # Dictionary comprehension: loops through JSON and applies .lower() to keys
    return {address.strip().lower(): name for address, name in data.items()}

# Store the clean, lowercase dictionary in memory
KNOWN_VASPS = load_known_vasps()

# ---------------------------------------------------------------------------
# Mixer / Tumbler Database (mock)
# ---------------------------------------------------------------------------
# Mock addresses standing in for privacy-mixing smart contracts (e.g. Tornado
# Cash). Any branch that routes funds into one of these addresses is treated
# as a terminal dead-end: the pre-mixer trace is preserved and exported, but
# the branch is not expanded further since post-mixer withdrawal addresses
# have no deterministic on-chain link back to the deposit.
KNOWN_MIXERS_RAW = {
    "0x8589427373D6D84E98730D7795D8f6f8731FDA0": "Tornado Cash Router (Mock)",
    "0x722122dF12D4e14e13Ac3b6895a86e84145b6f0": "Tornado Cash: Proxy (Mock)",
}
KNOWN_MIXERS = {addr.strip().lower(): name for addr, name in KNOWN_MIXERS_RAW.items()}

# ---------------------------------------------------------------------------
# VASP Jurisdiction Classification (Stage 2: Confidence Gating)
# ---------------------------------------------------------------------------
# Exchange names whose lowercase form contains one of these keywords are
# treated as domestic (Indian) VASPs eligible for a direct SAHYOG / Section
# 94 BNSS production order. Anything else is treated as offshore/unregulated
# and routed to an FIU-IND / Interpol referral instead.
DOMESTIC_VASP_KEYWORDS = ("coindcx", "wazirx", "zebpay", "coinswitch", "bitbns")

def is_domestic_vasp(exchange_name: str) -> bool:
    """Returns True if the exchange name matches a known domestic (Indian) VASP."""
    name = (exchange_name or "").lower()
    return any(keyword in name for keyword in DOMESTIC_VASP_KEYWORDS)

# ---------------------------------------------------------------------------
# Graph Safeguards
# ---------------------------------------------------------------------------
# Nodes with more outgoing transactions than this are almost certainly not a
# simple laundering wallet (they are typically an exchange deposit hub or
# high-frequency contract). Expanding their full neighbor set would blow up
# memory usage, so the branch is tagged and hard-stopped instead.
HIGH_DEGREE_TX_THRESHOLD = 500

# Wait time between API calls to prevent Etherscan from blocking our IP
REQUEST_DELAY_SECONDS = 0.25  


# ---------------------------------------------------------------------------
# Stage 1: Address Format & Checksum Validation
# ---------------------------------------------------------------------------

_ETH_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

def is_valid_eth_address(address: str) -> bool:
    """
    Basic EIP-55 format validation for an Ethereum/EVM address.

    Confirms the address is a '0x'-prefixed, 40-hex-character string. If the
    address uses mixed-case letters (i.e. it claims to carry an EIP-55
    checksum), this additionally verifies the checksum via eth_utils when
    that library is available; otherwise it falls back to format-only
    validation (all-lowercase / all-uppercase addresses carry no checksum
    information to verify).
    """
    if not isinstance(address, str) or not _ETH_ADDRESS_RE.match(address):
        return False

    body = address[2:]
    if body == body.lower() or body == body.upper():
        # No mixed-case checksum to verify - format check is sufficient.
        return True

    try:
        from eth_utils import to_checksum_address
        return to_checksum_address(address) == address
    except ImportError:
        # eth_utils not installed in this environment; accept on format alone.
        return True


# ---------------------------------------------------------------------------
# Core Tracing Logic (The Math Engine)
# ---------------------------------------------------------------------------

def _fetch_outgoing_txs(address: str) -> list:
    """
    Pings the Etherscan server to get the transaction history of a specific wallet.
    """
    if not ETHERSCAN_API_KEY:
        raise RuntimeError("ETHERSCAN_API_KEY not found in .env file.")

    # The payload we send to Etherscan asking for 'normal' outgoing transactions
    params = {
        "chainid": CHAIN_ID,
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "sort": "asc",
        "apikey": ETHERSCAN_API_KEY,
    }

    try:
        resp = requests.get(ETHERSCAN_V2_URL, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"  [!] Request failed for {address}: {e}")
        return []

    if data.get("status") != "1":
        message = data.get("message", "Unknown")
        if message != "No transactions found":
            print(f"  [!] API returned no data for {address}: {message}")
        return []

    # Returns the list of transactions
    result = data.get("result", [])
    if not isinstance(result, list):
        return []
    return result


def trace_wallet(start_address: str, max_depth: int = 3) -> nx.DiGraph:
    """
    Executes a Breadth-First Search (BFS) algorithm to track stolen funds.
    It builds a Directed Graph (DiGraph) where wallets are 'Nodes' and 
    transactions are 'Edges'.
    """
    graph = nx.DiGraph()

    # Ensure starting address is lowercase
    start_address = start_address.lower()
    graph.add_node(start_address, type="Wallet", depth=0)

    # The queue tracks which wallets to investigate next
    queue = deque([(start_address, 0)])
    visited = {start_address}

    # Keep investigating until the queue is empty
    while queue:
        current_address, depth = queue.popleft()

        # Stop investigating this branch if we hit the hop limit
        if depth >= max_depth:
            continue

        print(f"[depth {depth}] Tracing {current_address} ...")
        txs = _fetch_outgoing_txs(current_address)
        time.sleep(REQUEST_DELAY_SECONDS) 

        # SAFEGUARD: High-Degree Fan-Out Cutoff.
        # If this node has an unmanageable number of outgoing transactions,
        # tag it as a hub and stop expanding this branch entirely — do not
        # even parse its transaction list, to avoid a memory blow-up from
        # adding hundreds of neighbors to the graph/queue.
        if len(txs) > HIGH_DEGREE_TX_THRESHOLD:
            print(
                f"    -> {current_address} has {len(txs)} outgoing txs "
                f"(> {HIGH_DEGREE_TX_THRESHOLD}). Tagging as High-Degree Hub; branch terminated."
            )
            graph.nodes[current_address]["type"] = "High-Degree Hub"
            continue

        # Analyze every transaction sent by the current wallet
        for tx in txs:
            from_addr = tx.get("from", "").lower()
            to_addr = tx.get("to", "").lower()
            tx_hash = tx.get("hash")

            # Ignore incoming money; we only care where the money went
            if from_addr != current_address or not to_addr:
                continue

            # Check if the destination is a known mixer/tumbler or exchange
            is_mixer = to_addr in KNOWN_MIXERS
            is_exchange = to_addr in KNOWN_VASPS

            # Add the destination wallet to our visual graph
            if to_addr not in graph:
                if is_mixer:
                    node_type = "Mixer"
                elif is_exchange:
                    node_type = "Exchange"
                else:
                    node_type = "Wallet"
                graph.add_node(to_addr, type=node_type, depth=depth + 1)
            elif is_mixer:
                graph.nodes[to_addr]["type"] = "Mixer"
            elif is_exchange:
                graph.nodes[to_addr]["type"] = "Exchange"

            # Convert Wei string to float ETH (1 ETH = 10^18 Wei)
            raw_val = tx.get("value", "0")
            eth_value = float(raw_val) / 1e18 if raw_val else 0.0
            
            # Catch the Etherscan camelCase key and convert to int
            raw_time = tx.get("timeStamp")
            epoch_time = int(raw_time) if raw_time else None

            # Draw a line (edge) connecting the sender to the receiver
            graph.add_edge(
                from_addr,
                to_addr,
                tx_hash=tx_hash,
                value=eth_value,
                timestamp=epoch_time,
            )

            # TERMINATION RULE: If it hits a mixer/tumbler, the tracing link
            # is cryptographically broken. Flag as a terminal dead-end and
            # preserve the pre-mixer trace, but do not enqueue anything past it.
            if is_mixer:
                print(f"    -> {to_addr} is a known Mixer/Tumbler ({KNOWN_MIXERS[to_addr]}). Branch terminated (pre-mixer trace preserved).")
                continue

            # TERMINATION RULE: If it hits an exchange, stop tracing this branch.
            if is_exchange:
                print(f"    -> {to_addr} is a known exchange ({KNOWN_VASPS[to_addr]}). Branch terminated.")
                continue

            # If it's a normal wallet we haven't seen yet, add it to the queue to investigate next
            if to_addr not in visited:
                visited.add(to_addr)
                queue.append((to_addr, depth + 1))

    return graph


# ---------------------------------------------------------------------------
# Main Execution / Output
# ---------------------------------------------------------------------------

def main():
    # The starting 'Victim' wallet
    test_address = "0x8C1a9Ab9E8ae8C5f6cdDfAD0422FaF50cEB1eE50"

    # STAGE 1: Format & Checksum Validation — reject immediately if malformed.
    if not is_valid_eth_address(test_address):
        print(f"[!] REJECTED: '{test_address}' failed EIP-55 address format validation. Aborting trace.")
        return

    # Start the trace engine (3 hops max)
    graph = trace_wallet(test_address, max_depth=3)

    print("\n--- Trace Summary ---")
    print(f"Start address : {test_address}")
    print(f"Nodes (wallets/exchanges): {graph.number_of_nodes()}")
    print(f"Edges (transactions)     : {graph.number_of_edges()}")

    # Find all nodes tagged as an Exchange
    exchange_nodes = [
        n for n, attrs in graph.nodes(data=True) if attrs.get("type") == "Exchange"
    ]

    # Find nodes tagged as terminal safeguards (mixers / high-degree hubs)
    mixer_nodes = [n for n, attrs in graph.nodes(data=True) if attrs.get("type") == "Mixer"]
    hub_nodes = [n for n, attrs in graph.nodes(data=True) if attrs.get("type") == "High-Degree Hub"]

    print(f"All addresses found      : {list(graph.nodes())}")

    if mixer_nodes:
        print(f"Mixer/Tumbler dead-ends found ({len(mixer_nodes)}):")
        for n in mixer_nodes:
            print(f"  - {n} ({KNOWN_MIXERS.get(n.lower(), 'Unknown Mixer')})")

    if hub_nodes:
        print(f"High-Degree Hubs found ({len(hub_nodes)}):")
        for n in hub_nodes:
            print(f"  - {n}")

    # If an exchange was found, generate the PDF
    if exchange_nodes:
        print(f"Exchange endpoints found ({len(exchange_nodes)}):")
        for n in exchange_nodes:
            exchange_name = KNOWN_VASPS.get(n.lower(), 'Unknown Exchange')
            print(f"  - {n} ({exchange_name})")

            # VASP CONFIDENCE GATING: route domestic vs. offshore VASPs to
            # the appropriate legal instrument. Domestic VASPs can be served
            # a direct SAHYOG / Section 94 BNSS production order; offshore or
            # unregulated VASPs cannot be compelled domestically and are
            # instead routed to an FIU-IND / Interpol referral.
            if is_domestic_vasp(exchange_name):
                print(f"\nDomestic VASP detected. Generating BNSS Section 94 notice for {exchange_name}...")
                generate_section_94_notice(exchange_name=exchange_name, exchange_address=n)
            else:
                print(f"\nOffshore/unregulated VASP detected. Generating FIU-IND / Interpol referral for {exchange_name}...")
                generate_interpol_referral(exchange_name=exchange_name, exchange_address=n)
    else:
        print("No known exchange endpoints found in this trace.")
        
        # Find 'dead end' wallets where the trail went cold (no outgoing transactions)
        dead_ends = [
            n for n in graph.nodes() 
            if graph.out_degree(n) == 0 and graph.nodes[n].get("type") == "Wallet"
        ]
        
        if dead_ends:
            print(f"\nTerminal Wallets to Monitor ({len(dead_ends)}):")
            for n in dead_ends:
                print(f"  - {n}")

    # Run the automated fraud risk scoring engine
    print("\n--- Fraud & Risk Assessment ---")
    engine = RiskScoringEngine(graph)
    risk_results = engine.analyze()

    for addr, report in sorted(risk_results.items(), key=lambda x: x[1].risk_score, reverse=True):
        flags_str = ", ".join(report.flags()) if report.flags() else "None"
        node_type = graph.nodes[addr].get("type", "Wallet")
        print(f"[{report.risk_level.value:8s}] ({report.risk_score:4.1f}/10) {addr} | Type: {node_type} | Flags: {flags_str}")        

    # ---------------------------------------------------------
    # Generate Section 63 BSA Digital Evidence Certificate
    # ---------------------------------------------------------
    print("\nGenerating Section 63 BSA Digital Evidence Certificate...")
    
    # Structure the payload exactly as it appears in the graph
    payload_data = {
        "nodes": list(graph.nodes(data=True)),
        "edges": list(graph.edges(data=True)),
        "risk_assessments": [r.to_dict() for r in risk_results.values()]
    }

    metadata = CertificateMetadata(
        case_reference="SIH-26183-Crypto-Trace",
        description_of_electronic_record="Automated blockchain BFS trace and heuristic risk scoring.",
        manner_of_production="Extracted via Etherscan API and processed by RiskScoringEngine.",
        place_of_certification="SIH Headquarters"
    )

    device = DeviceParticulars(
        device_type="Forensic Workstation",
        software_used="Crypto-Triage PoC v1.0"
    )

    party = CertifyingParty(
        name="Investigating Officer",
        designation="SIH Nodal Officer",
        organization="Law Enforcement Agency"
    )

    cert_result = generate_section_63_certificate(
        payload=payload_data,
        metadata=metadata,
        device=device,
        party=party,
        output_path="Section_63_BSA_Certificate.pdf"
    )
    print(f"[+] BSA Certificate generated -> {cert_result.output_path}")

if __name__ == "__main__":
    main()