#!/usr/bin/env python3
"""
Neurophysiology Fact-Checker Enhancement
Catches pseudoscientific frequency claims

RED FLAGS:
- Pain frequencies > 200 Hz (biophysically impossible for C-fibers)
- Bioresonance claims (900-3000 Hz range)
- Mixing carrier frequencies with neural coding
- Missing peer-reviewed neuroscience references

VERIFIED RANGES:
- C-fiber nociceptors: 0.02 - 30 Hz
- TENS therapy: 1-200 Hz
- Haptic perception: 1-1000 Hz (mechanoreceptors, not pain)
- Bone conduction audio: 20-20,000 Hz (auditory, not neural pain coding)

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.
"""

import json
import logging
from typing import Dict, List, Any
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('neurophysiology_fact_checker')


class NeurophysiologyFactChecker:
    """Enhanced fact-checker with neurophysiology verification"""

    def __init__(self):
        self.agent_id = "L6-NEURO-FACT-001"

        # VERIFIED frequency ranges from peer-reviewed research
        self.verified_ranges = {
            'c_fiber_pain': {
                'range': (0.02, 30),
                'unit': 'Hz',
                'description': 'C-fiber nociceptor firing rate',
                'references': ['Bessou & Perl 1969', 'Burgess & Perl 1973', 'Treede et al. 1995']
            },
            'tens_therapy': {
                'range': (1, 200),
                'unit': 'Hz',
                'description': 'TENS frequency for pain modulation',
                'references': ['FDA approved', 'Gate control theory (Melzack & Wall 1965)']
            },
            'haptic_perception': {
                'range': (1, 1000),
                'unit': 'Hz',
                'description': 'Mechanoreceptor response (touch, not pain)',
                'references': ['Pacinian corpuscles 40-800 Hz', 'Meissner corpuscles 10-200 Hz']
            },
            'bone_conduction_audio': {
                'range': (20, 20000),
                'unit': 'Hz',
                'description': 'Auditory frequency range via bone conduction',
                'references': ['Standard auditory physics']
            },
            'ultrasonic_carrier': {
                'range': (20000, 100000),
                'unit': 'Hz',
                'description': 'Ultrasonic frequencies (not neural coding)',
                'references': ['Used as carrier waves, not direct neural stimulation']
            }
        }

        # PSEUDOSCIENCE red flags
        self.red_flags = {
            'bioresonance_myth': {
                'range': (900, 3000),
                'claim': 'External pain frequencies',
                'verdict': 'PSEUDOSCIENCE',
                'reason': 'Biophysically impossible for C-fibers due to refractory limits'
            },
            'high_freq_pain': {
                'range': (200, float('inf')),
                'claim': 'Direct pain modulation above 200 Hz',
                'verdict': 'UNVERIFIED',
                'reason': 'No peer-reviewed evidence for neural pain coding above 200 Hz'
            }
        }

    def verify_frequency_claim(self, claim: Dict[str, Any]) -> Dict[str, Any]:
        """Verify a frequency-related claim"""

        claim_text = claim.get('claim', '').lower()

        # Extract frequency if present
        freq_info = self._extract_frequency(claim_text)

        if not freq_info:
            return {'verified': True, 'reason': 'No frequency claim detected'}

        logger.info(f"🔬 [{self.agent_id}] Verifying frequency claim: {freq_info['value']} {freq_info['unit']}")

        # Check against pseudoscience red flags
        for flag_name, flag_data in self.red_flags.items():
            if self._in_range(freq_info['value'], flag_data['range']):
                logger.error(f"  ❌ RED FLAG: {flag_name} - {flag_data['verdict']}")
                return {
                    'verified': False,
                    'hallucination': True,
                    'red_flag': flag_name,
                    'verdict': flag_data['verdict'],
                    'reason': flag_data['reason'],
                    'recommendation': 'REJECT - Pseudoscientific claim'
                }

        # Check against verified ranges
        verified_category = None
        for category, data in self.verified_ranges.items():
            if self._in_range(freq_info['value'], data['range']):
                verified_category = category
                logger.info(f"  ✅ VERIFIED: Matches {category} ({data['description']})")
                break

        if verified_category:
            return {
                'verified': True,
                'category': verified_category,
                'description': self.verified_ranges[verified_category]['description'],
                'references': self.verified_ranges[verified_category]['references'],
                'reason': f"Within verified range for {verified_category}"
            }
        else:
            logger.warning(f"  ⚠️  UNVERIFIED: Frequency {freq_info['value']} Hz not in known verified ranges")
            return {
                'verified': False,
                'hallucination': False,
                'reason': 'Frequency claim not in verified neuroscience ranges',
                'recommendation': 'Requires peer-reviewed neuroscience reference'
            }

    def verify_pain_modulation_claim(self, claim: Dict[str, Any]) -> Dict[str, Any]:
        """Specifically verify pain modulation claims"""

        claim_text = claim.get('claim', '').lower()

        # Keywords indicating pain modulation
        pain_keywords = ['pain', 'nociceptor', 'analgesia', 'tens', 'neuromodulation']

        if not any(kw in claim_text for kw in pain_keywords):
            return {'applicable': False}

        logger.info(f"🔬 [{self.agent_id}] Verifying pain modulation claim")

        # Extract frequency
        freq_info = self._extract_frequency(claim_text)

        if not freq_info:
            return {'verified': True, 'reason': 'No specific frequency claimed'}

        # Pain modulation via TENS: 1-200 Hz
        if 1 <= freq_info['value'] <= 200:
            logger.info(f"  ✅ VERIFIED: {freq_info['value']} Hz within TENS therapeutic range (1-200 Hz)")
            return {
                'verified': True,
                'mechanism': 'TENS/Gate control theory',
                'range': (1, 200),
                'references': ['FDA approved TENS therapy', 'Melzack & Wall 1965']
            }

        # C-fiber firing: 0.02-30 Hz (internal neural coding, not external stimulation)
        elif 0.02 <= freq_info['value'] <= 30:
            logger.warning(f"  ⚠️  AMBIGUOUS: {freq_info['value']} Hz matches C-fiber internal firing, but not external modulation")
            return {
                'verified': False,
                'ambiguous': True,
                'reason': 'This is internal C-fiber firing rate, not external therapeutic frequency',
                'recommendation': 'Clarify if claim is about neural coding or external stimulation'
            }

        # Above 200 Hz: RED FLAG
        elif freq_info['value'] > 200:
            logger.error(f"  ❌ PSEUDOSCIENCE: Pain modulation at {freq_info['value']} Hz is not supported by neuroscience")
            return {
                'verified': False,
                'hallucination': True,
                'verdict': 'PSEUDOSCIENCE',
                'reason': 'No peer-reviewed evidence for pain modulation above 200 Hz',
                'correct_range': '1-200 Hz for TENS therapy',
                'recommendation': 'REJECT'
            }

        return {'verified': False, 'reason': 'Frequency outside known pain modulation ranges'}

    def _extract_frequency(self, text: str) -> Dict[str, Any]:
        """Extract frequency value from text"""
        import re

        # Pattern: number followed by Hz, kHz, or similar
        patterns = [
            r'(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)\s*hz',  # Range: "1-200 Hz"
            r'(\d+(?:\.\d+)?)\s*hz',                          # Single: "50 Hz"
            r'(\d+(?:\.\d+)?)\s*khz',                         # kHz: "2.4 kHz"
            r'(\d+(?:\.\d+)?)\s*ma'                           # Current (for context)
        ]

        for pattern in patterns:
            match = re.search(pattern, text.lower())
            if match:
                if '-' in pattern:  # Range
                    low = float(match.group(1))
                    high = float(match.group(2))
                    value = (low + high) / 2  # Use midpoint
                else:
                    value = float(match.group(1))

                # Convert kHz to Hz
                if 'khz' in pattern:
                    value *= 1000

                unit = 'Hz' if 'hz' in pattern else 'mA'

                return {'value': value, 'unit': unit, 'text': match.group(0)}

        return None

    def _in_range(self, value: float, range_tuple: tuple) -> bool:
        """Check if value is within range"""
        return range_tuple[0] <= value <= range_tuple[1]


# Test the neurophysiology fact-checker
if __name__ == "__main__":
    logger.info("=" * 80)
    logger.info("NEUROPHYSIOLOGY FACT-CHECKER TESTING")
    logger.info("=" * 80)

    checker = NeurophysiologyFactChecker()

    # Test cases
    test_claims = [
        {
            'claim': 'VR Haptic system uses 1-200 Hz frequency range',
            'expected': 'PASS - TENS range'
        },
        {
            'claim': 'Pain modulation at 900-3000 Hz',
            'expected': 'FAIL - Pseudoscience (bioresonance myth)'
        },
        {
            'claim': 'C-fiber nociceptors fire at 0.02-30 Hz',
            'expected': 'AMBIGUOUS - Internal neural coding, not external stimulation'
        },
        {
            'claim': 'TENS unit operates at 50 Hz',
            'expected': 'PASS - Within therapeutic range'
        },
        {
            'claim': 'Bone conduction bass frequency 20-80 Hz',
            'expected': 'PASS - Auditory frequency'
        },
        {
            'claim': 'Ultrasonic carrier wave at 40 kHz',
            'expected': 'PASS - Carrier frequency (not neural coding)'
        },
        {
            'claim': 'Pain frequency treatment at 2.4 kHz',
            'expected': 'FAIL - Pseudoscience (above 200 Hz)'
        }
    ]

    logger.info("\n🧪 RUNNING TEST CASES:\n")

    for i, test in enumerate(test_claims, 1):
        logger.info(f"\nTest #{i}: {test['claim']}")
        logger.info(f"Expected: {test['expected']}")

        # Test frequency verification
        result = checker.verify_frequency_claim(test)
        logger.info(f"Result: {json.dumps(result, indent=2)}")

        # Test pain modulation specifically
        pain_result = checker.verify_pain_modulation_claim(test)
        if pain_result.get('applicable') != False:
            logger.info(f"Pain Modulation Check: {json.dumps(pain_result, indent=2)}")

        logger.info("-" * 80)

    logger.info("\n" + "=" * 80)
    logger.info("NEUROPHYSIOLOGY FACT-CHECKER TESTING COMPLETE")
    logger.info("=" * 80)
