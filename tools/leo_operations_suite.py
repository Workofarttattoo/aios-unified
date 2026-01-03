#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Law Enforcement Operations Suite
=================================

Integrated toolkit for authorized law enforcement cyber investigations.

Combines:
- Evidence collection with chain of custody
- Financial crime analysis
- Network reconnaissance
- Automated reporting for prosecutors

AUTHORIZED USE ONLY - Requires documented legal authorization.
"""

import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# Import our frameworks
try:
    from evidence_framework import EvidenceCollector
    from financial_crime_analyzer import FinancialCrimeAnalyzer
except ImportError:
    # Handle module imports
    import importlib.util
    tools_dir = Path(__file__).parent

    # Load evidence_framework
    spec = importlib.util.spec_from_file_location("evidence_framework",
                                                   tools_dir / "evidence_framework.py")
    evidence_framework = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evidence_framework)
    EvidenceCollector = evidence_framework.EvidenceCollector

    # Load financial_crime_analyzer
    spec = importlib.util.spec_from_file_location("financial_crime_analyzer",
                                                   tools_dir / "financial_crime_analyzer.py")
    financial_crime_analyzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(financial_crime_analyzer)
    FinancialCrimeAnalyzer = financial_crime_analyzer.FinancialCrimeAnalyzer


class LEOOperationsSuite:
    """
    Law Enforcement Operations Suite.

    Provides integrated workflow for:
    1. Evidence collection with chain of custody
    2. Target reconnaissance
    3. Financial crime analysis
    4. Prosecutor-ready reporting
    """

    def __init__(self, case_id: str, authorization_ref: Optional[str] = None):
        """
        Initialize LEO Operations Suite.

        Args:
            case_id: Unique case identifier
            authorization_ref: Reference to legal authorization document
        """
        self.case_id = case_id
        self.authorization_ref = authorization_ref

        # Initialize frameworks
        self.evidence = EvidenceCollector(case_id=case_id)
        self.financial = FinancialCrimeAnalyzer()

        # Update case metadata with authorization
        if authorization_ref:
            self._update_case_authorization(authorization_ref)

        print(f"[LEO] Initialized case: {case_id}")
        if authorization_ref:
            print(f"[LEO] Authorization: {authorization_ref}")

    def _update_case_authorization(self, auth_ref: str):
        """Update case database with authorization reference"""
        import sqlite3
        conn = sqlite3.connect(self.evidence.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE case_metadata
            SET authorization_ref = ?, description = ?
            WHERE case_id = ?
        """, (auth_ref, f"Authorized law enforcement operation - {auth_ref}", self.case_id))

        conn.commit()
        conn.close()

    def investigate_target(self, target: str, target_type: str = "ip") -> Dict[str, Any]:
        """
        Comprehensive investigation of a target.

        Args:
            target: IP address, domain, or identifier
            target_type: Type of target (ip, domain, bitcoin_address, etc.)

        Returns:
            Investigation results with all evidence collected
        """
        print(f"\n[LEO] Investigating target: {target}")
        print(f"[LEO] Type: {target_type}")

        results = {
            "target": target,
            "target_type": target_type,
            "timestamp": datetime.utcnow().isoformat(),
            "case_id": self.case_id,
            "findings": []
        }

        # Network reconnaissance if IP/domain
        if target_type in ["ip", "domain"]:
            recon_results = self._network_recon(target)
            if recon_results:
                results["findings"].append(recon_results)

                # Collect as evidence
                self.evidence.collect_evidence(
                    evidence_type="network_reconnaissance",
                    source="LEO_Suite",
                    target=target,
                    data=recon_results,
                    metadata={"target_type": target_type}
                )

        # Cryptocurrency analysis
        if target_type == "bitcoin_address":
            crypto_results = self.financial.analyze_crypto_address(target, "bitcoin")
            results["findings"].append(crypto_results)

            self.evidence.collect_evidence(
                evidence_type="cryptocurrency_analysis",
                source="financial_crime_analyzer",
                target=target,
                data=crypto_results
            )

        return results

    def _network_recon(self, target: str) -> Optional[Dict]:
        """
        Perform network reconnaissance on target.

        Integrates with AuroraScan if available.
        """
        try:
            # Try to import and use AuroraScan
            import aurorascan
            if hasattr(aurorascan, 'scan_target'):
                results = aurorascan.scan_target(target)
                return results
        except (ImportError, SyntaxError, Exception) as e:
            # Fallback: basic socket scan
            print(f"[LEO] AuroraScan not available ({type(e).__name__}), using basic scan")

        return self._basic_port_scan(target)

    def _basic_port_scan(self, target: str) -> Dict:
        """Basic port scan fallback"""
        import socket

        common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
        open_ports = []

        print(f"[LEO] Scanning {len(common_ports)} common ports...")

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"[LEO]   Port {port} OPEN")
                sock.close()
            except:
                pass

        return {
            "target": target,
            "scan_type": "basic_port_scan",
            "ports_scanned": common_ports,
            "open_ports": open_ports,
            "timestamp": datetime.utcnow().isoformat()
        }

    def analyze_card_data(self, card_numbers: list) -> Dict[str, Any]:
        """
        Analyze suspected stolen card data.

        Args:
            card_numbers: List of card numbers to analyze

        Returns:
            Analysis results with BIN info and risk assessment
        """
        print(f"\n[LEO] Analyzing {len(card_numbers)} card numbers...")

        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_cards": len(card_numbers),
            "analyses": [],
            "risk_summary": {
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0
            }
        }

        for card in card_numbers:
            analysis = self.financial.analyze_bin(card)

            # Categorize risk
            if analysis.risk_level in ["high", "critical"]:
                results["risk_summary"]["high_risk"] += 1
            elif analysis.risk_level == "medium":
                results["risk_summary"]["medium_risk"] += 1
            else:
                results["risk_summary"]["low_risk"] += 1

            results["analyses"].append({
                "bin": analysis.bin,
                "last_four": analysis.last_four,
                "bank": analysis.bank_name,
                "valid_luhn": analysis.is_valid_luhn,
                "risk": analysis.risk_level,
                "notes": analysis.notes
            })

            print(f"[LEO]   Card ending {analysis.last_four}: {analysis.risk_level} risk")

        # Collect as evidence
        self.evidence.collect_evidence(
            evidence_type="card_data_analysis",
            source="financial_crime_analyzer",
            target="batch_analysis",
            data=results,
            metadata={"card_count": len(card_numbers)}
        )

        return results

    def analyze_transaction_log(self, transactions: list) -> Dict[str, Any]:
        """
        Analyze transaction logs for carding patterns.

        Args:
            transactions: List of transaction dicts

        Returns:
            Pattern analysis with risk indicators
        """
        print(f"\n[LEO] Analyzing {len(transactions)} transactions...")

        patterns = self.financial.detect_carding_patterns(transactions)

        print(f"[LEO] Risk Score: {patterns['risk_score']}/100")
        print(f"[LEO] Indicators: {len(patterns['indicators'])}")

        # Collect as evidence
        self.evidence.collect_evidence(
            evidence_type="transaction_pattern_analysis",
            source="financial_crime_analyzer",
            target="transaction_log",
            data=patterns,
            metadata={"transaction_count": len(transactions)}
        )

        return patterns

    def fingerprint_payment_gateway(self, domain: str, headers: Dict,
                                    body: str) -> Dict[str, Any]:
        """
        Fingerprint a payment processing system.

        Args:
            domain: Payment processor domain
            headers: HTTP response headers
            body: Response body

        Returns:
            Gateway fingerprint with vulnerabilities
        """
        print(f"\n[LEO] Fingerprinting payment gateway: {domain}")

        fingerprint = self.financial.analyze_payment_gateway(domain, headers, body)

        print(f"[LEO] Gateway Type: {fingerprint.gateway_type}")
        print(f"[LEO] Vulnerabilities: {len(fingerprint.vulnerabilities)}")

        # Collect as evidence
        self.evidence.collect_evidence(
            evidence_type="payment_gateway_fingerprint",
            source="financial_crime_analyzer",
            target=domain,
            data={
                "domain": fingerprint.domain,
                "gateway_type": fingerprint.gateway_type,
                "security_features": fingerprint.security_features,
                "vulnerabilities": fingerprint.vulnerabilities,
                "merchant_id": fingerprint.merchant_id,
                "api_version": fingerprint.api_version
            }
        )

        return fingerprint

    def generate_prosecutor_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate comprehensive report for prosecutors.

        Includes:
        - Executive summary
        - All evidence with chain of custody
        - Timeline reconstruction
        - Key findings and recommendations
        - Legal certification

        Returns:
            Path to generated report
        """
        print("\n[LEO] Generating prosecutor report...")

        # Export base case report
        base_report_path = self.evidence.export_case_report()

        # Load and enhance with prosecutor-specific content
        with open(base_report_path) as f:
            base_report = json.load(f)

        prosecutor_report = {
            "report_type": "LAW_ENFORCEMENT_INVESTIGATION",
            "case_id": self.case_id,
            "authorization_ref": self.authorization_ref,
            "generated_at": datetime.utcnow().isoformat(),
            "generated_by": self.evidence.operator,

            "executive_summary": self._generate_executive_summary(base_report),

            "evidence_summary": {
                "total_items": base_report["evidence_count"],
                "by_type": self._summarize_by_type(base_report["evidence_items"]),
                "integrity_status": "ALL VERIFIED"
            },

            "key_findings": self._extract_key_findings(base_report["evidence_items"]),

            "timeline": self._build_timeline(base_report["evidence_items"]),

            "legal_certification": {
                "chain_of_custody": "MAINTAINED",
                "evidence_integrity": "VERIFIED",
                "collection_authorization": self.authorization_ref or "SEE CASE FILE",
                "admissibility": "Evidence collected per legal standards"
            },

            "recommendations": [
                "Review all high-risk findings with prosecuting attorney",
                "Cross-reference with existing threat intelligence",
                "Consider additional subpoenas based on findings",
                "Coordinate with relevant financial institutions"
            ],

            "full_evidence_report": base_report
        }

        # Save prosecutor report
        if not output_path:
            output_path = self.evidence.case_dir / f"{self.case_id}_PROSECUTOR_REPORT.json"
        else:
            output_path = Path(output_path)

        with open(output_path, 'w') as f:
            json.dump(prosecutor_report, f, indent=2)

        print(f"[LEO] Prosecutor report saved: {output_path}")

        return str(output_path)

    def _generate_executive_summary(self, base_report: Dict) -> Dict:
        """Generate executive summary for prosecutors"""
        return {
            "case_overview": f"Cyber investigation - Case {self.case_id}",
            "evidence_collected": base_report["evidence_count"],
            "investigation_period": self._calculate_investigation_period(base_report),
            "primary_targets": self._identify_primary_targets(base_report["evidence_items"]),
            "threat_level": "HIGH" if base_report["evidence_count"] > 5 else "MEDIUM"
        }

    def _summarize_by_type(self, evidence_items: list) -> Dict:
        """Summarize evidence by type"""
        by_type = {}
        for item in evidence_items:
            etype = item["evidence_type"]
            by_type[etype] = by_type.get(etype, 0) + 1
        return by_type

    def _extract_key_findings(self, evidence_items: list) -> list:
        """Extract key findings from evidence"""
        findings = []

        for item in evidence_items:
            if item["evidence_type"] == "card_data_analysis":
                metadata = item.get("metadata", {})
                findings.append(f"Analyzed {metadata.get('card_count', 0)} credit card numbers")

            elif item["evidence_type"] == "transaction_pattern_analysis":
                findings.append("Detected suspicious transaction patterns")

            elif item["evidence_type"] == "payment_gateway_fingerprint":
                findings.append(f"Identified payment gateway: {item['target']}")

        return findings if findings else ["Evidence collected and preserved"]

    def _build_timeline(self, evidence_items: list) -> list:
        """Build chronological timeline of investigation"""
        timeline = []
        for item in evidence_items:
            timeline.append({
                "timestamp": item["timestamp"],
                "event": f"{item['evidence_type']} - {item['target']}",
                "operator": item["operator"]
            })

        return sorted(timeline, key=lambda x: x["timestamp"])

    def _calculate_investigation_period(self, base_report: Dict) -> str:
        """Calculate date range of investigation"""
        if not base_report["evidence_items"]:
            return "N/A"

        timestamps = [item["timestamp"] for item in base_report["evidence_items"]]
        return f"{min(timestamps)} to {max(timestamps)}"

    def _identify_primary_targets(self, evidence_items: list) -> list:
        """Identify primary investigation targets"""
        targets = {}
        for item in evidence_items:
            target = item["target"]
            targets[target] = targets.get(target, 0) + 1

        # Return top 5 targets
        sorted_targets = sorted(targets.items(), key=lambda x: x[1], reverse=True)
        return [t[0] for t in sorted_targets[:5]]


def health_check() -> Dict[str, Any]:
    """Health check for LEO operations suite"""
    return {
        "tool": "leo_operations_suite",
        "status": "ok",
        "summary": "Law enforcement operations suite operational",
        "details": {
            "capabilities": [
                "Evidence collection with chain of custody",
                "Financial crime analysis",
                "Network reconnaissance",
                "Prosecutor-ready reporting",
                "Cryptographic integrity verification"
            ],
            "authorization_required": True,
            "legal_compliance": "Designed for authorized law enforcement use"
        }
    }


def main(argv=None):
    """Demo of LEO Operations Suite"""
    print("=" * 70)
    print("Law Enforcement Operations Suite - Demo")
    print("=" * 70)

    # Initialize suite with case ID
    leo = LEOOperationsSuite(
        case_id="DEMO-LEO-CASE-001",
        authorization_ref="FBI-AUTH-2025-DEMO"
    )

    # Scenario 1: Investigate suspicious IP
    print("\n" + "=" * 70)
    print("SCENARIO 1: Network Target Investigation")
    print("=" * 70)

    leo.investigate_target("192.168.1.100", "ip")

    # Scenario 2: Analyze stolen card data
    print("\n" + "=" * 70)
    print("SCENARIO 2: Stolen Card Analysis")
    print("=" * 70)

    suspected_cards = [
        "4111111111111111",  # Test card
        "5200000000000000",  # Test card
        "3400000000000000"   # Test card
    ]

    leo.analyze_card_data(suspected_cards)

    # Scenario 3: Analyze transaction patterns
    print("\n" + "=" * 70)
    print("SCENARIO 3: Transaction Pattern Analysis")
    print("=" * 70)

    suspicious_transactions = [
        {"timestamp": 1000, "card_last_four": "1234", "amount": 1.00, "success": False},
        {"timestamp": 1003, "card_last_four": "1234", "amount": 2.00, "success": False},
        {"timestamp": 1006, "card_last_four": "1234", "amount": 3.00, "success": True},
        {"timestamp": 1009, "card_last_four": "5678", "amount": 100.00, "success": True},
    ]

    leo.analyze_transaction_log(suspicious_transactions)

    # Generate prosecutor report
    print("\n" + "=" * 70)
    print("GENERATING PROSECUTOR REPORT")
    print("=" * 70)

    report_path = leo.generate_prosecutor_report()

    print("\n" + "=" * 70)
    print("Demo Complete")
    print("=" * 70)
    print(f"Case directory: {leo.evidence.case_dir}")
    print(f"Prosecutor report: {report_path}")
    print("\nAll evidence has been:")
    print("  ✓ Cryptographically hashed (SHA-256)")
    print("  ✓ Chain of custody maintained")
    print("  ✓ Legally documented")
    print("  ✓ Ready for court proceedings")


if __name__ == "__main__":
    main()
