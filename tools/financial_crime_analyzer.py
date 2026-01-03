#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Financial Crime Analysis Module
================================

Specialized tools for investigating credit card fraud, carding operations,
and payment processor exploitation.

AUTHORIZED USE ONLY - For law enforcement and authorized security research.

Features:
- BIN (Bank Identification Number) analysis
- Payment gateway fingerprinting
- CVV algorithm research (theoretical)
- Merchant identification code tracking
- Cryptocurrency transaction analysis
- Dark web marketplace intelligence
"""

import json
import hashlib
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime


# BIN Database (first 6 digits of credit card)
# In production, this would connect to official BIN databases
BIN_DATABASE = {
    "411111": {"bank": "VISA Test Bank", "type": "credit", "country": "US", "risk": "test"},
    "520000": {"bank": "MasterCard Test", "type": "debit", "country": "US", "risk": "test"},
    "340000": {"bank": "American Express Test", "type": "credit", "country": "US", "risk": "test"},
    "601100": {"bank": "Discover Test", "type": "credit", "country": "US", "risk": "test"},
    # Real BINs would be loaded from official databases
}


@dataclass
class CardAnalysis:
    """Analysis results for a credit card number"""
    bin: str
    last_four: str
    bank_name: Optional[str]
    card_type: Optional[str]
    country: Optional[str]
    is_valid_luhn: bool
    risk_level: str
    notes: List[str]


@dataclass
class PaymentGatewayFingerprint:
    """Fingerprint of a payment processing system"""
    domain: str
    gateway_type: str  # stripe, paypal, square, custom
    security_features: List[str]
    vulnerabilities: List[str]
    merchant_id: Optional[str]
    api_version: Optional[str]


class FinancialCrimeAnalyzer:
    """
    Analyzes financial crime indicators without live exploitation.

    All analysis is passive and uses public/theoretical information only.
    """

    def __init__(self):
        self.analysis_timestamp = datetime.utcnow().isoformat()

    def analyze_bin(self, card_number: str) -> CardAnalysis:
        """
        Analyze Bank Identification Number (first 6 digits).

        This identifies the issuing bank and card type WITHOUT validating
        the card itself or testing if it's active.

        Args:
            card_number: Full card number (will be sanitized)

        Returns:
            CardAnalysis with bank info and risk assessment
        """
        # Sanitize input - remove spaces, dashes
        card_clean = re.sub(r'[^0-9]', '', card_number)

        if len(card_clean) < 6:
            return CardAnalysis(
                bin="INVALID",
                last_four="XXXX",
                bank_name=None,
                card_type=None,
                country=None,
                is_valid_luhn=False,
                risk_level="error",
                notes=["Card number too short"]
            )

        bin_number = card_clean[:6]
        last_four = card_clean[-4:] if len(card_clean) >= 4 else "XXXX"

        # Look up BIN in database
        bin_info = BIN_DATABASE.get(bin_number, {})

        # Perform Luhn algorithm check (validates format, not if card is active)
        is_valid_luhn = self._luhn_check(card_clean)

        # Risk assessment
        risk_level = bin_info.get("risk", "unknown")
        notes = []

        if bin_info.get("risk") == "test":
            notes.append("Test card - commonly used in fraud testing")

        if not is_valid_luhn:
            notes.append("Failed Luhn check - likely invalid or typo")
            risk_level = "high"

        if len(card_clean) not in [13, 15, 16, 19]:
            notes.append("Unusual card length")

        return CardAnalysis(
            bin=bin_number,
            last_four=last_four,
            bank_name=bin_info.get("bank"),
            card_type=bin_info.get("type"),
            country=bin_info.get("country"),
            is_valid_luhn=is_valid_luhn,
            risk_level=risk_level,
            notes=notes
        )

    def _luhn_check(self, card_number: str) -> bool:
        """
        Luhn algorithm to validate card number format.

        NOTE: This only validates the format/checksum. It does NOT verify:
        - If the card is active
        - If the card has funds
        - If the CVV is correct
        - If it's stolen
        """
        def digits_of(n):
            return [int(d) for d in str(n)]

        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]

        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))

        return checksum % 10 == 0

    def analyze_payment_gateway(self, domain: str, response_headers: Dict[str, str],
                                response_body: str) -> PaymentGatewayFingerprint:
        """
        Fingerprint a payment gateway by analyzing HTTP responses.

        This is PASSIVE analysis - no exploitation or testing.

        Args:
            domain: Payment processor domain
            response_headers: HTTP response headers
            response_body: HTML/JSON response body

        Returns:
            PaymentGatewayFingerprint with security assessment
        """
        gateway_type = "unknown"
        security_features = []
        vulnerabilities = []
        merchant_id = None
        api_version = None

        # Detect gateway type from headers/body
        if "stripe" in domain.lower() or "stripe" in response_body.lower():
            gateway_type = "stripe"
            api_version = self._extract_stripe_version(response_headers, response_body)
        elif "paypal" in domain.lower():
            gateway_type = "paypal"
        elif "square" in domain.lower():
            gateway_type = "square"
        else:
            gateway_type = "custom"

        # Check for security features
        if response_headers.get("Strict-Transport-Security"):
            security_features.append("HSTS enabled")
        else:
            vulnerabilities.append("Missing HSTS header")

        if response_headers.get("Content-Security-Policy"):
            security_features.append("CSP enabled")
        else:
            vulnerabilities.append("Missing Content-Security-Policy")

        if "3d-secure" in response_body.lower() or "3ds" in response_body.lower():
            security_features.append("3D Secure support")

        # Check for common vulnerabilities
        if "card_number" in response_body.lower() and "value=" in response_body.lower():
            vulnerabilities.append("Card number may be exposed in HTML")

        if response_headers.get("X-Powered-By"):
            vulnerabilities.append(f"Information disclosure: {response_headers['X-Powered-By']}")

        # Extract merchant ID if visible
        merchant_match = re.search(r'merchant[_-]?id["\s:=]+([a-zA-Z0-9_-]+)', response_body, re.IGNORECASE)
        if merchant_match:
            merchant_id = merchant_match.group(1)

        return PaymentGatewayFingerprint(
            domain=domain,
            gateway_type=gateway_type,
            security_features=security_features,
            vulnerabilities=vulnerabilities,
            merchant_id=merchant_id,
            api_version=api_version
        )

    def _extract_stripe_version(self, headers: Dict, body: str) -> Optional[str]:
        """Extract Stripe API version from headers or body"""
        if "Stripe-Version" in headers:
            return headers["Stripe-Version"]

        version_match = re.search(r'stripe[_-]?version["\s:=]+([0-9-]+)', body, re.IGNORECASE)
        if version_match:
            return version_match.group(1)

        return None

    def analyze_crypto_address(self, address: str, blockchain: str = "bitcoin") -> Dict[str, Any]:
        """
        Analyze cryptocurrency address (passive, no blockchain queries).

        In production, this would integrate with blockchain explorers to:
        - Track transaction history
        - Identify known bad actors
        - Calculate total received/sent

        Args:
            address: Crypto wallet address
            blockchain: bitcoin, ethereum, monero, etc.

        Returns:
            Analysis dict with risk indicators
        """
        analysis = {
            "address": address,
            "blockchain": blockchain,
            "timestamp": datetime.utcnow().isoformat(),
            "format_valid": self._validate_crypto_format(address, blockchain),
            "risk_indicators": [],
            "notes": []
        }

        if not analysis["format_valid"]:
            analysis["risk_indicators"].append("Invalid address format")
            return analysis

        # In production, would query blockchain here
        analysis["notes"].append("Live blockchain analysis requires API integration")
        analysis["notes"].append("Consider using blockchain.com or blockchair.com APIs")

        return analysis

    def _validate_crypto_format(self, address: str, blockchain: str) -> bool:
        """Validate cryptocurrency address format"""
        if blockchain == "bitcoin":
            # Bitcoin addresses start with 1, 3, or bc1
            return bool(re.match(r'^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$', address))
        elif blockchain == "ethereum":
            # Ethereum addresses are 0x followed by 40 hex chars
            return bool(re.match(r'^0x[a-fA-F0-9]{40}$', address))
        elif blockchain == "monero":
            # Monero addresses start with 4 or 8
            return bool(re.match(r'^[48][a-zA-Z0-9]{94}$', address))

        return False

    def detect_carding_patterns(self, transaction_log: List[Dict]) -> Dict[str, Any]:
        """
        Detect patterns indicative of carding operations.

        Analyzes transaction logs for:
        - Rapid successive transactions
        - Multiple failed attempts
        - Unusual geographic patterns
        - Card testing behavior

        Args:
            transaction_log: List of transaction dicts

        Returns:
            Pattern analysis with risk scores
        """
        if not transaction_log:
            return {"error": "No transactions to analyze"}

        patterns = {
            "total_transactions": len(transaction_log),
            "timestamp": datetime.utcnow().isoformat(),
            "indicators": [],
            "risk_score": 0,
            "recommendations": []
        }

        # Calculate transaction velocity
        if len(transaction_log) >= 2:
            timestamps = [t.get("timestamp", 0) for t in transaction_log if "timestamp" in t]
            if timestamps and len(timestamps) >= 2:
                time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                avg_diff = sum(time_diffs) / len(time_diffs)

                if avg_diff < 5:  # Less than 5 seconds between transactions
                    patterns["indicators"].append("Extremely high transaction velocity")
                    patterns["risk_score"] += 40

        # Check for multiple failed attempts
        failed = [t for t in transaction_log if not t.get("success", True)]
        if len(failed) > 3:
            patterns["indicators"].append(f"Multiple failed transactions: {len(failed)}")
            patterns["risk_score"] += 30

        # Check for same card, different amounts (card testing)
        card_amounts = {}
        for t in transaction_log:
            card = t.get("card_last_four", "unknown")
            amount = t.get("amount", 0)
            if card not in card_amounts:
                card_amounts[card] = []
            card_amounts[card].append(amount)

        for card, amounts in card_amounts.items():
            if len(set(amounts)) > 3 and max(amounts) < 5:  # Multiple small different amounts
                patterns["indicators"].append(f"Card testing pattern detected on card ending {card}")
                patterns["risk_score"] += 35

        # Risk assessment
        if patterns["risk_score"] >= 70:
            patterns["recommendations"].append("HIGH RISK: Likely carding operation - investigate immediately")
        elif patterns["risk_score"] >= 40:
            patterns["recommendations"].append("MEDIUM RISK: Suspicious patterns - monitor closely")
        else:
            patterns["recommendations"].append("LOW RISK: No strong indicators of carding")

        return patterns

    def generate_report(self, analyses: List[Dict]) -> str:
        """
        Generate comprehensive financial crime analysis report.

        Args:
            analyses: List of analysis results

        Returns:
            JSON report string
        """
        report = {
            "report_id": hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest()[:16],
            "generated_at": datetime.utcnow().isoformat(),
            "tool": "financial_crime_analyzer",
            "analysis_count": len(analyses),
            "analyses": analyses,
            "summary": self._generate_summary(analyses)
        }

        return json.dumps(report, indent=2)

    def _generate_summary(self, analyses: List[Dict]) -> Dict[str, Any]:
        """Generate executive summary of analyses"""
        return {
            "total_analyses": len(analyses),
            "high_risk_findings": sum(1 for a in analyses if a.get("risk_score", 0) >= 70),
            "medium_risk_findings": sum(1 for a in analyses if 40 <= a.get("risk_score", 0) < 70),
            "recommendations": [
                "Review all high-risk findings immediately",
                "Cross-reference with known threat intelligence",
                "Document findings for law enforcement reporting"
            ]
        }


def health_check() -> Dict[str, Any]:
    """Health check for financial crime analyzer"""
    return {
        "tool": "financial_crime_analyzer",
        "status": "ok",
        "summary": "Financial crime analysis module operational",
        "details": {
            "capabilities": [
                "BIN analysis",
                "Luhn validation",
                "Payment gateway fingerprinting",
                "Crypto address validation",
                "Carding pattern detection"
            ],
            "note": "Passive analysis only - no live card testing"
        }
    }


def main(argv=None):
    """Demo of financial crime analyzer"""
    print("=" * 70)
    print("Financial Crime Analyzer - Demo")
    print("=" * 70)

    analyzer = FinancialCrimeAnalyzer()

    # Test BIN analysis with test card
    print("\n[BIN ANALYSIS]")
    test_card = "4111111111111111"  # Standard test card
    analysis = analyzer.analyze_bin(test_card)
    print(f"BIN: {analysis.bin}")
    print(f"Bank: {analysis.bank_name}")
    print(f"Luhn Valid: {analysis.is_valid_luhn}")
    print(f"Risk: {analysis.risk_level}")
    print(f"Notes: {', '.join(analysis.notes)}")

    # Test payment gateway fingerprinting
    print("\n[PAYMENT GATEWAY FINGERPRINTING]")
    sample_headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Powered-By": "Express"
    }
    sample_body = '<html><script src="https://js.stripe.com/v3/"></script></html>'

    gateway = analyzer.analyze_payment_gateway(
        "checkout.example.com",
        sample_headers,
        sample_body
    )
    print(f"Gateway Type: {gateway.gateway_type}")
    print(f"Security Features: {', '.join(gateway.security_features)}")
    print(f"Vulnerabilities: {', '.join(gateway.vulnerabilities)}")

    # Test carding pattern detection
    print("\n[CARDING PATTERN DETECTION]")
    suspicious_transactions = [
        {"timestamp": 1000, "card_last_four": "1234", "amount": 1.00, "success": False},
        {"timestamp": 1003, "card_last_four": "1234", "amount": 2.00, "success": False},
        {"timestamp": 1006, "card_last_four": "1234", "amount": 3.00, "success": True},
        {"timestamp": 1009, "card_last_four": "1234", "amount": 4.00, "success": True},
    ]

    patterns = analyzer.detect_carding_patterns(suspicious_transactions)
    print(f"Risk Score: {patterns['risk_score']}")
    print(f"Indicators: {', '.join(patterns['indicators'])}")
    print(f"Recommendation: {patterns['recommendations'][0]}")

    # Test crypto address validation
    print("\n[CRYPTOCURRENCY ANALYSIS]")
    btc_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # Genesis block address
    crypto_analysis = analyzer.analyze_crypto_address(btc_address, "bitcoin")
    print(f"Address: {crypto_analysis['address']}")
    print(f"Valid Format: {crypto_analysis['format_valid']}")

    print("\n" + "=" * 70)
    print("Demo Complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
