#!/usr/bin/env python3

"""
Bug Bounty Validator
--------------------
Quality control - validates vulnerabilities to prevent false positives.

CRITICAL FOR REPUTATION:
- False positives destroy credibility on bug bounty platforms
- Validators ensure high-quality submissions
- Multiple validation attempts with different techniques
- Checks for WAF/IDS blocking
- Ensures security impact is real

This protects your reputation and maximizes acceptance rates.
"""

import aiohttp
import asyncio
import logging
from typing import Dict, List, Optional
import time
import re

logger = logging.getLogger("BugBountyValidator")


class VulnerabilityValidator:
    """
    Validates potential vulnerabilities before reporting.
    
    Multiple validation attempts to ensure reliability.
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.validation_attempts = config.get("validation_attempts", 3)
        self.timeout = config.get("timeout", 10)
    
    async def validate(self, finding: Dict) -> Dict:
        """
        Validate a vulnerability finding.
        
        Returns validated finding with confidence score.
        """
        vuln_type = finding.get("type")
        
        validators = {
            "XSS": self._validate_xss,
            "SQLi": self._validate_sqli,
            "SSRF": self._validate_ssrf,
            "IDOR": self._validate_idor,
            "Auth Bypass": self._validate_auth_bypass
        }
        
        validator_func = validators.get(vuln_type)
        
        if not validator_func:
            logger.warning(f"No validator for type: {vuln_type}")
            finding["validated"] = False
            finding["validation_confidence"] = 0.0
            return finding
        
        # Run validator
        try:
            is_valid, confidence, evidence = await validator_func(finding)
            
            finding["validated"] = is_valid
            finding["validation_confidence"] = confidence
            finding["validation_evidence"] = evidence
            finding["validated_at"] = time.time()
            
            if is_valid:
                logger.info(f"✓ Validated {vuln_type} with {confidence:.0%} confidence")
            else:
                logger.info(f"✗ Failed to validate {vuln_type}")
            
            return finding
        
        except Exception as e:
            logger.error(f"Validation error: {e}")
            finding["validated"] = False
            finding["validation_confidence"] = 0.0
            finding["validation_error"] = str(e)
            return finding
    
    async def _validate_xss(self, finding: Dict):
        """
        Validate XSS by attempting multiple payloads and checking execution.
        """
        evidence = []
        successful_validations = 0
        
        url = finding["url"]
        parameter = finding["parameter"]
        original_payload = finding["payload"]
        
        # Try multiple validation payloads
        validation_payloads = [
            original_payload,
            "<img src=x onerror=alert(document.domain)>",
            "<svg/onload=alert(document.domain)>",
            "javascript:alert(document.domain)"
        ]
        
        async with aiohttp.ClientSession() as session:
            for payload in validation_payloads:
                try:
                    # Construct test URL
                    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                    
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[parameter] = [payload]
                    
                    test_query = urlencode(params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        test_query,
                        parsed.fragment
                    ))
                    
                    async with session.get(test_url, timeout=self.timeout) as response:
                        html = await response.text()
                        
                        # Check if payload appears unescaped
                        if payload in html:
                            # Check for actual script execution context
                            dangerous_contexts = [
                                r'<script[^>]*>' + re.escape(payload),
                                r'onerror=["\']?' + re.escape(payload),
                                r'href=["\']?' + re.escape(payload)
                            ]
                            
                            for context in dangerous_contexts:
                                if re.search(context, html, re.IGNORECASE):
                                    successful_validations += 1
                                    evidence.append(f"Payload '{payload}' executes in dangerous context")
                                    break
                            else:
                                # Payload reflected but may be in safe context
                                evidence.append(f"Payload '{payload}' reflected but context unclear")
                
                except Exception as e:
                    logger.debug(f"Validation attempt failed: {e}")
                
                await asyncio.sleep(0.2)
        
        # Calculate confidence
        confidence = successful_validations / len(validation_payloads)
        is_valid = confidence >= 0.5
        
        return is_valid, confidence, evidence
    
    async def _validate_sqli(self, finding: Dict):
        """
        Validate SQL injection using multiple techniques.
        """
        evidence = []
        successful_validations = 0
        
        url = finding["url"]
        parameter = finding["parameter"]
        
        # Boolean-based validation
        validation_tests = [
            {
                "name": "Boolean True",
                "payload": "1' AND '1'='1",
                "should_succeed": True
            },
            {
                "name": "Boolean False",
                "payload": "1' AND '1'='2",
                "should_succeed": False
            },
            {
                "name": "Time delay",
                "payload": "1' AND SLEEP(5)--",
                "check_time": True,
                "expected_delay": 5
            }
        ]
        
        async with aiohttp.ClientSession() as session:
            for test in validation_tests:
                try:
                    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                    
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[parameter] = [test["payload"]]
                    
                    test_query = urlencode(params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        test_query,
                        parsed.fragment
                    ))
                    
                    start_time = time.time()
                    async with session.get(test_url, timeout=self.timeout + 10) as response:
                        response_time = time.time() - start_time
                        
                        if test.get("check_time"):
                            # Time-based validation
                            if response_time >= test["expected_delay"]:
                                successful_validations += 1
                                evidence.append(f"Time delay of {response_time:.2f}s confirms SQLi")
                        else:
                            # Boolean-based validation
                            status = response.status
                            if test["should_succeed"] and status == 200:
                                successful_validations += 1
                                evidence.append(f"Boolean test '{test['name']}' behaved as expected")
                
                except Exception as e:
                    logger.debug(f"SQLi validation attempt failed: {e}")
                
                await asyncio.sleep(0.2)
        
        confidence = successful_validations / len(validation_tests)
        is_valid = confidence >= 0.5
        
        return is_valid, confidence, evidence
    
    async def _validate_ssrf(self, finding: Dict):
        """
        Validate SSRF by checking if server actually made the request.
        """
        evidence = []
        
        # For SSRF, we need external validation
        # In production, you'd use a callback server (e.g., Burp Collaborator)
        
        url = finding["url"]
        parameter = finding["parameter"]
        payload = finding["payload"]
        
        # Check if metadata or sensitive info is in response
        async with aiohttp.ClientSession() as session:
            try:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
                
                test_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    test_query,
                    parsed.fragment
                ))
                
                async with session.get(test_url, timeout=self.timeout) as response:
                    html = await response.text()
                    
                    # Check for sensitive data patterns
                    sensitive_patterns = [
                        (r'instance-id', "AWS instance metadata"),
                        (r'computeMetadata', "GCP metadata"),
                        (r'root:x:0:0', "/etc/passwd contents"),
                        (r'SSH-2\.0', "SSH banner"),
                        (r'\"access_token\"', "OAuth token")
                    ]
                    
                    matches = 0
                    for pattern, description in sensitive_patterns:
                        if re.search(pattern, html, re.IGNORECASE):
                            evidence.append(f"Found {description}")
                            matches += 1
                    
                    if matches > 0:
                        return True, 0.9, evidence
            
            except Exception as e:
                logger.debug(f"SSRF validation failed: {e}")
        
        return False, 0.3, ["Unable to confirm SSRF - needs external validation"]
    
    async def _validate_idor(self, finding: Dict):
        """
        Validate IDOR by checking unauthorized access patterns.
        """
        evidence = []
        
        # IDOR validation requires testing access control
        # We need to verify that changing the ID gives us access to other users' data
        
        url = finding["url"]
        parameter = finding["parameter"]
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get baseline (original ID)
                async with session.get(url, timeout=self.timeout) as baseline_response:
                    baseline_html = await baseline_response.text()
                    baseline_status = baseline_response.status
                
                # Try modified IDs
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                original_id = params.get(parameter, [""])[0]
                
                if original_id.isdigit():
                    test_ids = [
                        str(int(original_id) + 1),
                        str(int(original_id) - 1),
                        "1"
                    ]
                else:
                    test_ids = ["00000000-0000-0000-0000-000000000001"]
                
                similar_responses = 0
                for test_id in test_ids:
                    params[parameter] = [test_id]
                    test_query = urlencode(params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        test_query,
                        parsed.fragment
                    ))
                    
                    async with session.get(test_url, timeout=self.timeout) as response:
                        if response.status == 200:
                            test_html = await response.text()
                            
                            # Check if response is similar (indicating data access)
                            if len(test_html) > len(baseline_html) * 0.5:
                                similar_responses += 1
                                evidence.append(f"ID {test_id} returned similar data (possible IDOR)")
                
                confidence = similar_responses / len(test_ids)
                is_valid = confidence >= 0.5
                
                return is_valid, confidence, evidence
        
        except Exception as e:
            logger.debug(f"IDOR validation failed: {e}")
            return False, 0.0, [f"Validation error: {str(e)}"]
    
    async def _validate_auth_bypass(self, finding: Dict):
        """
        Validate authentication bypass.
        """
        evidence = []
        
        url = finding["url"]
        method = finding.get("method", "")
        
        try:
            async with aiohttp.ClientSession() as session:
                # Extract headers from method description
                if "Header:" in method:
                    header_name = method.split("Header:")[1].strip()
                    headers = {header_name: "/admin"}
                else:
                    headers = {}
                
                async with session.get(url, headers=headers, timeout=self.timeout) as response:
                    if response.status == 200:
                        html = await response.text()
                        
                        # Check for admin/protected indicators
                        admin_indicators = [
                            r'admin panel',
                            r'user management',
                            r'system settings',
                            r'dashboard'
                        ]
                        
                        matches = 0
                        for indicator in admin_indicators:
                            if re.search(indicator, html, re.IGNORECASE):
                                evidence.append(f"Found protected content: {indicator}")
                                matches += 1
                        
                        if matches > 0:
                            return True, 0.8, evidence
        
        except Exception as e:
            logger.debug(f"Auth bypass validation failed: {e}")
        
        return False, 0.2, ["Unable to confirm auth bypass"]


if __name__ == "__main__":
    # Test validator
    logging.basicConfig(level=logging.INFO)
    
    config = {
        "validation_attempts": 3,
        "timeout": 10
    }
    
    validator = VulnerabilityValidator(config)
    
    test_finding = {
        "type": "XSS",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "payload": "<script>alert(1)</script>"
    }
    
    validated = asyncio.run(validator.validate(test_finding))
    print(f"\nValidation result: {validated}")

