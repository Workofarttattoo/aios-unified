# Law Enforcement Operations - Quick Reference

**Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.**

## ⚠️ AUTHORIZATION REQUIRED FOR ALL OPERATIONS

---

## Quick Start

```python
from tools.leo_operations_suite import LEOOperationsSuite

# Initialize case
leo = LEOOperationsSuite(
    case_id="YOUR-CASE-ID",
    authorization_ref="YOUR-WARRANT-NUMBER"
)

# Investigate target
leo.investigate_target("target-ip-or-domain", "ip")

# Analyze cards
leo.analyze_card_data(["card1", "card2"])

# Analyze transactions
leo.analyze_transaction_log(transaction_list)

# Generate report
leo.generate_prosecutor_report()
```

---

## Evidence Collection

```python
from tools.evidence_framework import EvidenceCollector

collector = EvidenceCollector(case_id="CASE-001")

# Collect evidence
evidence = collector.collect_evidence(
    evidence_type="port_scan",
    source="AuroraScan",
    target="192.168.1.100",
    data=results
)

# Verify integrity
collector.verify_integrity(evidence.evidence_id)

# Export report
collector.export_case_report()
```

---

## Financial Crime Analysis

```python
from tools.financial_crime_analyzer import FinancialCrimeAnalyzer

analyzer = FinancialCrimeAnalyzer()

# BIN analysis
analysis = analyzer.analyze_bin("4111111111111111")

# Carding patterns
patterns = analyzer.detect_carding_patterns(transactions)

# Gateway fingerprinting
gateway = analyzer.analyze_payment_gateway(domain, headers, body)

# Crypto analysis
crypto = analyzer.analyze_crypto_address(address, "bitcoin")
```

---

## Evidence Types

- `port_scan` - Network reconnaissance
- `packet_capture` - Traffic analysis
- `card_data_analysis` - Card fraud
- `transaction_pattern_analysis` - Carding detection
- `payment_gateway_fingerprint` - Gateway vulns
- `cryptocurrency_analysis` - Blockchain tracing
- `screenshot` - Visual evidence
- `log_file` - System logs

---

## Risk Levels

| Score | Level | Action |
|-------|-------|--------|
| 0-30  | LOW | Monitor |
| 31-60 | MEDIUM | Investigate |
| 61-80 | HIGH | Priority |
| 81-100 | CRITICAL | Immediate |

---

## File Locations

```
/Users/noone/aios/tools/
├── evidence_framework.py
├── financial_crime_analyzer.py
└── leo_operations_suite.py

/Users/noone/aios/evidence/
└── {CASE_ID}/
    ├── evidence.db
    ├── {evidence_id}.json
    └── {case_id}_PROSECUTOR_REPORT.json
```

---

## Health Checks

```bash
# Test evidence framework
python tools/evidence_framework.py

# Test financial analyzer
python tools/financial_crime_analyzer.py

# Test LEO suite
python tools/leo_operations_suite.py
```

---

## Chain of Custody Actions

- `collected` - Initial collection
- `transferred` - Moved between operators
- `analyzed` - Processed/analyzed
- `verified` - Integrity check
- `exported` - Report generation
- `integrity_failure` - TAMPERING DETECTED

---

## Legal Checklist

### Before Investigation
- [ ] Obtain warrant/authorization
- [ ] Document authorization reference
- [ ] Verify operator credentials
- [ ] Set up evidence storage

### During Investigation
- [ ] Record all actions
- [ ] Verify evidence integrity
- [ ] Maintain chain of custody
- [ ] Document findings

### After Investigation
- [ ] Generate prosecutor report
- [ ] Final integrity verification
- [ ] Package evidence
- [ ] Brief legal team

---

## Emergency Procedures

### Evidence Integrity Failure
1. Stop all operations
2. Document failure in notes
3. Restore from backup
4. Notify legal team
5. Review chain of custody

### Database Corruption
```bash
sqlite3 evidence.db "PRAGMA integrity_check;"
sqlite3 evidence.db ".dump" > backup.sql
```

### Tool Failure
1. Check logs for errors
2. Verify Python dependencies
3. Test with demo cases
4. Contact technical support

---

## Common Commands

```bash
# Run evidence demo
python tools/evidence_framework.py

# Run financial analyzer demo
python tools/financial_crime_analyzer.py

# Run full LEO suite demo
python tools/leo_operations_suite.py

# Check evidence integrity
python -c "from tools.evidence_framework import EvidenceCollector; \
c = EvidenceCollector('CASE-ID'); \
c.verify_integrity('EVIDENCE-ID')"

# Export case report
python -c "from tools.evidence_framework import EvidenceCollector; \
c = EvidenceCollector('CASE-ID'); \
print(c.export_case_report())"
```

---

## Support Contacts

- **Technical Issues:** Joshua Hendricks Cole
- **Legal Questions:** FBI Legal Counsel
- **Tool Enhancement:** Official channels

---

## Key Abbreviations

- LEO - Law Enforcement Operations
- BIN - Bank Identification Number
- CVV - Card Verification Value
- OPSEC - Operational Security
- PII - Personally Identifiable Information
- CJIS - Criminal Justice Information Services

---

**For full documentation, see: `/Users/noone/aios/LEO_OPERATIONS_GUIDE.md`**
