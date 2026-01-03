#!/usr/bin/env python3

"""
Bug Bounty Reporter
-------------------
Generates professional vulnerability reports.

ECH0-POWERED: Uses ECH0 for natural language generation of reports.
This is where LLM capability shines - professional documentation.

Report quality directly affects bounty amounts.
Higher quality = higher payouts.
"""

import logging
from typing import Dict
from datetime import datetime
import json

logger = logging.getLogger("BugBountyReporter")


class VulnerabilityReporter:
    """
    Generates professional vulnerability reports.
    
    Optionally uses ECH0 for enhanced report generation.
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.ech0_endpoint = config.get("ech0_endpoint", "")
        self.ech0_api_key = config.get("ech0_api_key", "")
        self.use_ech0 = bool(self.ech0_endpoint and self.ech0_api_key)
        
        if self.use_ech0:
            logger.info("ECH0 integration enabled for report generation")
        else:
            logger.info("Using template-based report generation")
    
    async def generate_report(self, finding: Dict) -> Dict:
        """
        Generate a professional vulnerability report.
        
        If ECH0 is available, uses it for enhanced natural language.
        Otherwise, uses high-quality templates.
        """
        if self.use_ech0:
            return await self._generate_with_ech0(finding)
        else:
            return self._generate_with_template(finding)
    
    async def _generate_with_ech0(self, finding: Dict) -> Dict:
        """
        Generate report using ECH0 for natural language generation.
        
        ECH0 provides Level 7 intelligence for professional documentation.
        """
        # TODO: Implement actual ECH0 API call
        # For now, fall back to template
        logger.info("ECH0 report generation (TODO: implement API call)")
        return self._generate_with_template(finding)
    
    def _generate_with_template(self, finding: Dict) -> Dict:
        """
        Generate report using professional templates.
        
        High-quality structured reports following industry standards.
        """
        vuln_type = finding.get("type")
        
        # Generate report based on vulnerability type
        if vuln_type == "XSS":
            return self._generate_xss_report(finding)
        elif vuln_type == "SQLi":
            return self._generate_sqli_report(finding)
        elif vuln_type == "SSRF":
            return self._generate_ssrf_report(finding)
        elif vuln_type == "IDOR":
            return self._generate_idor_report(finding)
        elif vuln_type == "Auth Bypass":
            return self._generate_auth_bypass_report(finding)
        else:
            return self._generate_generic_report(finding)
    
    def _generate_xss_report(self, finding: Dict) -> Dict:
        """Generate XSS vulnerability report."""
        report = {
            "title": f"Cross-Site Scripting (XSS) in {finding.get('parameter', 'parameter')}",
            "vulnerability_type": "XSS",
            "cwe": "CWE-79",
            "owasp": "OWASP Top 10 2021 - A03:2021 Injection",
            "severity": finding.get("severity", "Medium"),
            
            "description": f"""
A Cross-Site Scripting (XSS) vulnerability was discovered in the application. The vulnerability allows an attacker to inject malicious JavaScript code that will be executed in the context of other users' browsers.

**Affected Parameter:** {finding.get('parameter', 'N/A')}
**Affected URL:** {finding.get('url', 'N/A')}

The application fails to properly sanitize user input before including it in the HTML response, allowing arbitrary JavaScript execution.
""".strip(),
            
            "impact": """
This vulnerability can be exploited to:
- Steal user session tokens and cookies
- Perform actions on behalf of the victim user
- Redirect users to malicious websites
- Deface the web page content
- Capture sensitive user information (credentials, personal data)
- Deploy browser-based malware

**Business Impact:**
- User account compromise
- Data theft and privacy violations
- GDPR/CCPA compliance violations
- Reputational damage
- Loss of user trust
""".strip(),
            
            "steps_to_reproduce": f"""
1. Navigate to: {finding.get('url', 'N/A')}
2. Inject the following payload in the '{finding.get('parameter', 'parameter')}' parameter:
   ```
   {finding.get('payload', 'N/A')}
   ```
3. Submit the request
4. Observe that the JavaScript payload is executed in the browser
5. Check the browser console or observe alert/popup execution

**Proof of Concept:**
The injected payload appears unescaped in the HTML response and executes in the user's browser context.

**Validation Results:**
- Confidence: {finding.get('validation_confidence', 0.0) * 100:.0f}%
- Validated: {finding.get('validated', False)}
- Evidence: {json.dumps(finding.get('validation_evidence', []), indent=2)}
""".strip(),
            
            "remediation": """
**Immediate Fix:**
1. Implement proper output encoding for all user-controlled data
2. Use context-aware encoding (HTML entity encoding, JavaScript encoding, URL encoding)
3. Apply Content Security Policy (CSP) headers to prevent inline script execution

**Recommended Solution:**
```python
# Example: Proper output encoding
from html import escape

user_input = request.GET.get('parameter')
safe_output = escape(user_input)  # Encodes <, >, &, etc.
```

**Additional Recommendations:**
- Implement a strict Content Security Policy
- Use modern frameworks with auto-escaping (React, Vue, Angular)
- Validate input on the server side
- Use HTTPOnly and Secure flags on cookies
- Consider implementing a Web Application Firewall (WAF)

**CSP Header Example:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
```
""".strip(),
            
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/79.html"
            ],
            
            "discovered_by": "APEX Bug Bounty Hunter (Autonomous Agent)",
            "discovered_at": datetime.now().isoformat(),
            "report_version": "1.0"
        }
        
        return report
    
    def _generate_sqli_report(self, finding: Dict) -> Dict:
        """Generate SQL Injection vulnerability report."""
        report = {
            "title": f"SQL Injection in {finding.get('parameter', 'parameter')}",
            "vulnerability_type": "SQLi",
            "cwe": "CWE-89",
            "owasp": "OWASP Top 10 2021 - A03:2021 Injection",
            "severity": finding.get("severity", "High"),
            
            "description": f"""
A SQL Injection vulnerability was discovered that allows an attacker to manipulate database queries. The application fails to properly sanitize user input before incorporating it into SQL queries.

**Affected Parameter:** {finding.get('parameter', 'N/A')}
**Affected URL:** {finding.get('url', 'N/A')}

This vulnerability allows arbitrary SQL code execution against the application's database.
""".strip(),
            
            "impact": """
This vulnerability can be exploited to:
- Extract sensitive data from the database
- Modify or delete database records
- Bypass authentication mechanisms
- Execute administrative operations on the database
- In some cases, execute operating system commands

**Business Impact:**
- Complete database compromise
- Data breach and privacy violations
- Compliance violations (PCI DSS, GDPR, HIPAA)
- Financial fraud
- Reputational damage and legal liability
""".strip(),
            
            "steps_to_reproduce": f"""
1. Navigate to: {finding.get('url', 'N/A')}
2. Inject the following SQL payload in the '{finding.get('parameter', 'parameter')}' parameter:
   ```
   {finding.get('payload', 'N/A')}
   ```
3. Submit the request
4. Observe SQL error messages or unexpected behavior
5. Confirm data extraction or query manipulation

**Validation Results:**
- Confidence: {finding.get('validation_confidence', 0.0) * 100:.0f}%
- Validated: {finding.get('validated', False)}
- Evidence: {json.dumps(finding.get('validation_evidence', []), indent=2)}
""".strip(),
            
            "remediation": """
**Immediate Fix:**
1. Use parameterized queries (prepared statements) for all database operations
2. Never concatenate user input directly into SQL queries
3. Implement input validation and sanitization

**Recommended Solution:**
```python
# VULNERABLE CODE:
query = f"SELECT * FROM users WHERE id = {user_id}"  # BAD!

# SECURE CODE:
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # GOOD!
```

**Additional Recommendations:**
- Use ORM frameworks that handle parameterization
- Implement least privilege database access
- Disable detailed error messages in production
- Use Web Application Firewall (WAF)
- Regular security audits and code reviews
- Input validation with whitelist approach
""".strip(),
            
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/89.html"
            ],
            
            "discovered_by": "APEX Bug Bounty Hunter (Autonomous Agent)",
            "discovered_at": datetime.now().isoformat(),
            "report_version": "1.0"
        }
        
        return report
    
    def _generate_ssrf_report(self, finding: Dict) -> Dict:
        """Generate SSRF vulnerability report."""
        report = {
            "title": f"Server-Side Request Forgery (SSRF) in {finding.get('parameter', 'parameter')}",
            "vulnerability_type": "SSRF",
            "cwe": "CWE-918",
            "owasp": "OWASP Top 10 2021 - A10:2021 Server-Side Request Forgery",
            "severity": finding.get("severity", "Critical"),
            
            "description": f"""
A Server-Side Request Forgery (SSRF) vulnerability allows an attacker to make the server perform HTTP requests to arbitrary destinations, including internal network resources.

**Affected Parameter:** {finding.get('parameter', 'N/A')}
**Affected URL:** {finding.get('url', 'N/A')}
""".strip(),
            
            "impact": """
This vulnerability can be exploited to:
- Access cloud metadata services (AWS, GCP, Azure)
- Scan internal network infrastructure
- Access internal services and APIs
- Bypass firewall restrictions
- Steal sensitive credentials from metadata
- Potential RCE through internal services

**Business Impact:**
- Cloud infrastructure compromise
- Internal network reconnaissance
- Credential theft
- Compliance violations
- Critical security breach
""".strip(),
            
            "steps_to_reproduce": f"""
1. Navigate to: {finding.get('url', 'N/A')}
2. Inject the following URL in the '{finding.get('parameter', 'parameter')}' parameter:
   ```
   {finding.get('payload', 'N/A')}
   ```
3. Submit the request
4. Observe that the server fetches the internal resource
5. Check response for sensitive metadata or internal data

**Validation Results:**
- Confidence: {finding.get('validation_confidence', 0.0) * 100:.0f}%
- Evidence: {json.dumps(finding.get('validation_evidence', []), indent=2)}
""".strip(),
            
            "remediation": """
**Immediate Fix:**
1. Implement strict whitelist of allowed destination hosts
2. Disable HTTP redirects for user-supplied URLs
3. Block access to private IP ranges (RFC 1918)

**Recommended Solution:**
```python
# Validate and restrict URL destinations
from ipaddress import ip_address, ip_network

def is_safe_url(url):
    parsed = urlparse(url)
    
    # Block private networks
    try:
        ip = ip_address(parsed.hostname)
        private_networks = [
            ip_network('10.0.0.0/8'),
            ip_network('172.16.0.0/12'),
            ip_network('192.168.0.0/16'),
            ip_network('169.254.0.0/16'),  # AWS metadata
        ]
        for network in private_networks:
            if ip in network:
                return False
    except:
        pass
    
    # Whitelist allowed domains
    allowed_domains = ['example.com', 'api.example.com']
    return parsed.hostname in allowed_domains
```

**Additional Recommendations:**
- Network segmentation
- Disable unnecessary URL schemes (file://, gopher://, etc.)
- Use DNS rebinding protection
- Implement timeout limits
""".strip(),
            
            "references": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/918.html"
            ],
            
            "discovered_by": "APEX Bug Bounty Hunter (Autonomous Agent)",
            "discovered_at": datetime.now().isoformat(),
            "report_version": "1.0"
        }
        
        return report
    
    def _generate_idor_report(self, finding: Dict) -> Dict:
        """Generate IDOR vulnerability report."""
        report = {
            "title": f"Insecure Direct Object Reference (IDOR) in {finding.get('parameter', 'parameter')}",
            "vulnerability_type": "IDOR",
            "cwe": "CWE-639",
            "owasp": "OWASP Top 10 2021 - A01:2021 Broken Access Control",
            "severity": finding.get("severity", "High"),
            
            "description": f"""
An Insecure Direct Object Reference (IDOR) vulnerability allows unauthorized access to resources by manipulating object identifiers.

**Affected Parameter:** {finding.get('parameter', 'N/A')}
**Affected URL:** {finding.get('url', 'N/A')}

The application fails to verify that the requesting user has permission to access the referenced object.
""".strip(),
            
            "impact": """
This vulnerability allows:
- Unauthorized access to other users' data
- Privacy violations
- Data manipulation or deletion
- Privilege escalation
- Account takeover

**Business Impact:**
- GDPR/privacy law violations
- Data breach
- Loss of user trust
- Legal liability
""".strip(),
            
            "steps_to_reproduce": f"""
1. Authenticate as a regular user
2. Access: {finding.get('url', 'N/A')}
3. Modify the '{finding.get('parameter', 'parameter')}' parameter to reference another user's resource
4. Observe unauthorized access to the resource

**Validation Results:**
- Confidence: {finding.get('validation_confidence', 0.0) * 100:.0f}%
- Evidence: {json.dumps(finding.get('validation_evidence', []), indent=2)}
""".strip(),
            
            "remediation": """
**Immediate Fix:**
1. Implement proper authorization checks
2. Verify user ownership before returning resources
3. Use indirect references (UUIDs instead of sequential IDs)

**Recommended Solution:**
```python
def get_user_resource(resource_id, current_user):
    resource = Resource.query.get(resource_id)
    
    # CRITICAL: Verify ownership
    if resource.owner_id != current_user.id:
        raise Unauthorized("Access denied")
    
    return resource
```

**Additional Recommendations:**
- Implement access control lists (ACLs)
- Use role-based access control (RBAC)
- Log all access attempts
- Regular access control audits
""".strip(),
            
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
                "https://cwe.mitre.org/data/definitions/639.html"
            ],
            
            "discovered_by": "APEX Bug Bounty Hunter (Autonomous Agent)",
            "discovered_at": datetime.now().isoformat(),
            "report_version": "1.0"
        }
        
        return report
    
    def _generate_auth_bypass_report(self, finding: Dict) -> Dict:
        """Generate authentication bypass report."""
        report = {
            "title": "Authentication Bypass Vulnerability",
            "vulnerability_type": "Auth Bypass",
            "cwe": "CWE-287",
            "owasp": "OWASP Top 10 2021 - A07:2021 Identification and Authentication Failures",
            "severity": finding.get("severity", "Critical"),
            
            "description": f"""
An authentication bypass vulnerability allows unauthorized access to protected resources.

**Affected URL:** {finding.get('url', 'N/A')}
**Bypass Method:** {finding.get('method', 'N/A')}
""".strip(),
            
            "impact": """
Complete authentication bypass allows:
- Unauthorized access to admin functions
- Account takeover
- Data theft
- System compromise
- Privilege escalation

**Business Impact:**
- Complete security breach
- Compliance violations
- Legal liability
- Reputational damage
""".strip(),
            
            "steps_to_reproduce": f"""
1. Access: {finding.get('url', 'N/A')}
2. Use bypass method: {finding.get('method', 'N/A')}
3. Observe unauthorized access to protected resource

**Validation Results:**
- Confidence: {finding.get('validation_confidence', 0.0) * 100:.0f}%
- Evidence: {json.dumps(finding.get('validation_evidence', []), indent=2)}
""".strip(),
            
            "remediation": """
**Immediate Fix:**
1. Implement proper authentication on all protected endpoints
2. Don't rely solely on client-side checks
3. Validate authentication on the server side

**Recommended Solution:**
- Use established authentication frameworks
- Implement session management correctly
- Use secure, HTTPOnly cookies
- Implement rate limiting
- Multi-factor authentication (MFA)
""".strip(),
            
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                "https://cwe.mitre.org/data/definitions/287.html"
            ],
            
            "discovered_by": "APEX Bug Bounty Hunter (Autonomous Agent)",
            "discovered_at": datetime.now().isoformat(),
            "report_version": "1.0"
        }
        
        return report
    
    def _generate_generic_report(self, finding: Dict) -> Dict:
        """Generate generic vulnerability report."""
        return {
            "title": f"{finding.get('type', 'Security')} Vulnerability",
            "vulnerability_type": finding.get('type', 'Unknown'),
            "severity": finding.get("severity", "Medium"),
            "description": finding.get("description", "Security vulnerability discovered"),
            "impact": "Security impact to be determined",
            "steps_to_reproduce": "See finding details",
            "remediation": "Implement appropriate security controls",
            "discovered_by": "APEX Bug Bounty Hunter (Autonomous Agent)",
            "discovered_at": datetime.now().isoformat()
        }


if __name__ == "__main__":
    # Test reporter
    logging.basicConfig(level=logging.INFO)
    
    config = {}
    reporter = VulnerabilityReporter(config)
    
    test_finding = {
        "type": "XSS",
        "severity": "Medium",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "validated": True,
        "validation_confidence": 0.9,
        "validation_evidence": ["Payload executed in browser context"]
    }
    
    import asyncio
    report = asyncio.run(reporter.generate_report(test_finding))
    print(json.dumps(report, indent=2))

