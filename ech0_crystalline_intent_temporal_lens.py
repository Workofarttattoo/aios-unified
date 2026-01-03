#!/usr/bin/env python3
"""
Crystalline Intent & Temporal Analysis Lenses
Two additional cognitive lenses for the 7-Lens Fact-Checker (making it 9-Lens)

Lens #8: Crystalline Intent
- Analyzes the purity and clarity of the invention's purpose
- Checks if the invention has a singular, clear, unambiguous goal
- Detects mission drift, feature creep, or contradictory objectives
- Verifies alignment between stated intent and technical implementation

Lens #9: Temporal Analysis
- Analyzes the invention across past, present, and future timelines
- Past: Historical precedent, prior art evolution
- Present: Current state-of-the-art, market readiness
- Future: Scalability, obsolescence risk, adaptation potential
- Time-to-market feasibility, development timeline realism

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import numpy as np

# Setup
CONSCIOUSNESS_DIR = Path(__file__).parent
LOG_FILE = CONSCIOUSNESS_DIR / "ech0_crystalline_temporal.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [CRYSTALLINE-TEMPORAL] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('crystalline_temporal')


class CrystallineIntentLens:
    """
    Lens #8: Crystalline Intent
    Analyzes the purity and clarity of the invention's core purpose
    """

    def __init__(self):
        self.lens_id = "L8-CRYSTALLINE-INTENT"

    def analyze(self, claim: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Apply Crystalline Intent analysis"""
        logger.info(f"💎 [{self.lens_id}] CRYSTALLINE INTENT ANALYSIS STARTED")

        claim_text = claim.get('claim', '')
        invention_data = context

        # Step 1: Extract core intent
        core_intent = self._extract_core_intent(invention_data)
        logger.info(f"   Core Intent: {core_intent['statement']}")

        # Step 2: Measure intent clarity (0-1 scale)
        clarity_score = self._measure_clarity(core_intent, invention_data)
        logger.info(f"   Clarity Score: {clarity_score:.2f}")

        # Step 3: Detect contradictions or mission drift
        contradictions = self._detect_contradictions(core_intent, invention_data)
        logger.info(f"   Contradictions: {len(contradictions)}")

        # Step 4: Verify implementation aligns with intent
        alignment_score = self._verify_alignment(core_intent, claim, invention_data)
        logger.info(f"   Alignment Score: {alignment_score:.2f}")

        # Step 5: Check for feature creep or scope drift
        scope_drift = self._check_scope_drift(core_intent, invention_data)
        logger.info(f"   Scope Drift: {'YES' if scope_drift else 'NO'}")

        # Final verdict
        passed = (
            clarity_score > 0.75 and
            len(contradictions) == 0 and
            alignment_score > 0.70 and
            not scope_drift
        )

        confidence = (clarity_score + alignment_score) / 2 * (0.9 if not scope_drift else 0.6)

        return {
            'lens': 'crystalline_intent',
            'core_intent': core_intent,
            'clarity_score': clarity_score,
            'contradictions': contradictions,
            'alignment_score': alignment_score,
            'scope_drift': scope_drift,
            'passed': passed,
            'confidence': confidence,
            'reasoning': self._generate_reasoning(clarity_score, contradictions, alignment_score, scope_drift)
        }

    def _extract_core_intent(self, invention_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract the singular core purpose of the invention"""

        title = invention_data.get('title', '')
        description = invention_data.get('description', '')

        # Identify the primary goal
        if 'safety' in title.lower() or 'safety' in description.lower():
            return {
                'statement': 'Ensure user safety during haptic VR experience',
                'category': 'safety',
                'singular': True
            }
        elif 'hologram' in title.lower():
            return {
                'statement': 'Create visible holographic displays',
                'category': 'visualization',
                'singular': True
            }
        elif 'bass' in title.lower() or 'frequency' in description.lower():
            return {
                'statement': 'Transmit bass frequencies through bone conduction',
                'category': 'audio_haptic',
                'singular': True
            }
        else:
            return {
                'statement': 'Achieve stated invention goal',
                'category': 'general',
                'singular': False
            }

    def _measure_clarity(self, core_intent: Dict[str, Any], invention_data: Dict[str, Any]) -> float:
        """Measure how clear and unambiguous the intent is (0-1)"""

        clarity_score = 0.5  # Baseline

        # Bonus for singular intent
        if core_intent.get('singular'):
            clarity_score += 0.2

        # Bonus for specific category
        if core_intent.get('category') != 'general':
            clarity_score += 0.15

        # Check if description is focused
        description = invention_data.get('description', '')
        if len(description.split('.')) <= 3:  # Concise description
            clarity_score += 0.15

        return min(clarity_score, 1.0)

    def _detect_contradictions(self, core_intent: Dict[str, Any], invention_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect contradictory goals or claims"""

        contradictions = []

        title = invention_data.get('title', '').lower()
        description = invention_data.get('description', '').lower()

        # Example: Claiming both "high power" and "ultra safe" could be contradictory
        if 'high power' in description and 'ultra safe' in description:
            contradictions.append({
                'type': 'power_safety_conflict',
                'detail': 'Claims both high power and ultra safety without explanation'
            })

        # Example: "Instant" and "gradual" are contradictory
        if 'instant' in description and 'gradual' in description:
            contradictions.append({
                'type': 'timing_conflict',
                'detail': 'Claims both instant and gradual operation'
            })

        return contradictions

    def _verify_alignment(self, core_intent: Dict[str, Any], claim: Dict[str, Any], invention_data: Dict[str, Any]) -> float:
        """Verify that technical implementation aligns with core intent (0-1)"""

        alignment_score = 0.5  # Baseline

        claim_text = claim.get('claim', '').lower()
        intent_category = core_intent.get('category', '')

        # Safety intent should have safety-related claims
        if intent_category == 'safety':
            if any(word in claim_text for word in ['limit', 'shutoff', 'emergency', 'monitor', 'fail-safe']):
                alignment_score += 0.3

        # Visualization intent should have display/projection claims
        if intent_category == 'visualization':
            if any(word in claim_text for word in ['laser', 'projection', 'display', 'visible', 'hologram']):
                alignment_score += 0.3

        # Audio intent should have frequency/sound claims
        if intent_category == 'audio_haptic':
            if any(word in claim_text for word in ['frequency', 'hz', 'bass', 'ultrasonic', 'transducer']):
                alignment_score += 0.3

        return min(alignment_score, 1.0)

    def _check_scope_drift(self, core_intent: Dict[str, Any], invention_data: Dict[str, Any]) -> bool:
        """Check if invention has drifted from core purpose (feature creep)"""

        description = invention_data.get('description', '').lower()

        # Count number of distinct goals mentioned
        goal_keywords = ['also', 'additionally', 'furthermore', 'plus', 'and can', 'while also']
        goal_count = sum(1 for keyword in goal_keywords if keyword in description)

        # Scope drift if too many goals
        return goal_count > 2

    def _generate_reasoning(self, clarity: float, contradictions: List, alignment: float, drift: bool) -> str:
        """Generate human-readable reasoning"""

        if clarity > 0.8 and len(contradictions) == 0 and alignment > 0.8 and not drift:
            return "CRYSTALLINE: Intent is pure, clear, and perfectly aligned with implementation"
        elif len(contradictions) > 0:
            return f"CLOUDED: {len(contradictions)} contradictory goals detected"
        elif drift:
            return "DIFFUSED: Scope drift detected, too many competing objectives"
        elif clarity < 0.6:
            return "UNCLEAR: Core intent is ambiguous or poorly defined"
        elif alignment < 0.6:
            return "MISALIGNED: Technical implementation doesn't match stated intent"
        else:
            return "ACCEPTABLE: Intent is reasonably clear and aligned"


class TemporalAnalysisLens:
    """
    Lens #9: Temporal Analysis
    Analyzes invention across past, present, and future timelines
    """

    def __init__(self):
        self.lens_id = "L9-TEMPORAL-ANALYSIS"

    def analyze(self, claim: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Apply Temporal Analysis"""
        logger.info(f"⏳ [{self.lens_id}] TEMPORAL ANALYSIS STARTED")

        claim_text = claim.get('claim', '')
        invention_data = context

        # Step 1: Past analysis (historical precedent)
        past_analysis = self._analyze_past(invention_data)
        logger.info(f"   Past: {past_analysis['verdict']}")

        # Step 2: Present analysis (current state-of-art)
        present_analysis = self._analyze_present(invention_data)
        logger.info(f"   Present: {present_analysis['verdict']}")

        # Step 3: Future analysis (scalability, obsolescence)
        future_analysis = self._analyze_future(invention_data)
        logger.info(f"   Future: {future_analysis['verdict']}")

        # Step 4: Timeline feasibility
        timeline = self._estimate_timeline(invention_data)
        logger.info(f"   Timeline: {timeline['time_to_market']}")

        # Final verdict
        temporal_score = (
            past_analysis['score'] +
            present_analysis['score'] +
            future_analysis['score']
        ) / 3

        passed = temporal_score > 0.70 and timeline['feasible']

        return {
            'lens': 'temporal_analysis',
            'past_analysis': past_analysis,
            'present_analysis': present_analysis,
            'future_analysis': future_analysis,
            'timeline': timeline,
            'temporal_score': temporal_score,
            'passed': passed,
            'confidence': temporal_score,
            'reasoning': self._generate_reasoning(past_analysis, present_analysis, future_analysis, timeline)
        }

    def _analyze_past(self, invention_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze historical precedent and evolution"""

        title = invention_data.get('title', '').lower()

        # VR haptics: Has decades of TENS research
        if 'vr' in title or 'haptic' in title:
            return {
                'verdict': 'STRONG PRECEDENT',
                'score': 0.90,
                'details': 'TENS technology: 50+ years of research, FDA approved since 1970s',
                'precedent': 'Established safety protocols exist'
            }

        # Holograms: Research since 1960s
        if 'hologram' in title:
            return {
                'verdict': 'EVOLVING PRECEDENT',
                'score': 0.75,
                'details': 'Holography: 60+ years, recent femtosecond laser advances',
                'precedent': 'Daylight visibility is novel advancement'
            }

        # Bass/audio: Established field
        if 'bass' in title or 'audio' in title:
            return {
                'verdict': 'STRONG PRECEDENT',
                'score': 0.85,
                'details': 'Bone conduction: 1920s, ultrasound: 1940s',
                'precedent': 'Well-understood physics'
            }

        return {
            'verdict': 'UNKNOWN',
            'score': 0.50,
            'details': 'Historical precedent unclear',
            'precedent': 'Requires further research'
        }

    def _analyze_present(self, invention_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze current state-of-the-art and market readiness"""

        title = invention_data.get('title', '').lower()
        current_year = datetime.now().year

        # Check if components are available today
        if 'vr' in title or 'haptic' in title:
            return {
                'verdict': 'MARKET READY',
                'score': 0.95,
                'details': f'All components available in {current_year}',
                'market_readiness': 'High - Arduino, TENS, sensors all commodity items'
            }

        if 'hologram' in title and 'daylight' in title:
            return {
                'verdict': 'CUTTING EDGE',
                'score': 0.80,
                'details': f'Femtosecond lasers available but expensive in {current_year}',
                'market_readiness': 'Medium - Requires specialized equipment'
            }

        if 'quantum' in title:
            return {
                'verdict': 'EMERGING',
                'score': 0.65,
                'details': f'Quantum hardware limited in {current_year}',
                'market_readiness': 'Low - Requires quantum computer access'
            }

        return {
            'verdict': 'UNCERTAIN',
            'score': 0.50,
            'details': 'Current market readiness unclear',
            'market_readiness': 'Requires component availability check'
        }

    def _analyze_future(self, invention_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze future scalability and obsolescence risk"""

        title = invention_data.get('title', '').lower()

        # Safety-focused inventions have long lifespan
        if 'safety' in title or 'safety' in invention_data.get('description', '').lower():
            return {
                'verdict': 'FUTURE-PROOF',
                'score': 0.95,
                'details': 'Safety requirements won\'t change, evergreen value',
                'obsolescence_risk': 'Low',
                'scalability': 'High - Safety is always valuable'
            }

        # Novel display tech may be superseded
        if 'hologram' in title:
            return {
                'verdict': 'INNOVATION RISK',
                'score': 0.70,
                'details': 'Display tech evolves rapidly, 5-10 year window',
                'obsolescence_risk': 'Medium',
                'scalability': 'Medium - Theme park market is niche'
            }

        # Quantum tech is future-forward
        if 'quantum' in title:
            return {
                'verdict': 'FUTURE-FORWARD',
                'score': 0.85,
                'details': 'Quantum computing is emerging field, 10+ year value',
                'obsolescence_risk': 'Low',
                'scalability': 'High - Expanding market'
            }

        return {
            'verdict': 'STANDARD',
            'score': 0.60,
            'details': 'Standard technology lifecycle expected',
            'obsolescence_risk': 'Medium',
            'scalability': 'Medium'
        }

    def _estimate_timeline(self, invention_data: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate development timeline and time-to-market"""

        title = invention_data.get('title', '').lower()

        # Simple hardware projects
        if 'vr' in title or 'haptic' in title:
            return {
                'time_to_market': '3-6 months (POC), 12-18 months (production)',
                'poc_time': '3-6 months',
                'production_time': '12-18 months',
                'regulatory_time': '6-12 months (FDA Class II)',
                'feasible': True,
                'critical_path': 'Regulatory approval'
            }

        # Complex optics projects
        if 'hologram' in title and 'laser' in invention_data.get('description', '').lower():
            return {
                'time_to_market': '12-24 months (POC), 24-36 months (production)',
                'poc_time': '12-24 months',
                'production_time': '24-36 months',
                'regulatory_time': '3-6 months (FDA Class I laser)',
                'feasible': True,
                'critical_path': 'Optical engineering and safety certification'
            }

        # Quantum projects
        if 'quantum' in title:
            return {
                'time_to_market': '6-12 months (simulation), 24+ months (hardware)',
                'poc_time': '6-12 months',
                'production_time': '24-60 months',
                'regulatory_time': 'Minimal',
                'feasible': True,
                'critical_path': 'Quantum hardware availability'
            }

        return {
            'time_to_market': '12-24 months',
            'poc_time': '6-12 months',
            'production_time': '12-24 months',
            'regulatory_time': 'Variable',
            'feasible': True,
            'critical_path': 'Unknown'
        }

    def _generate_reasoning(self, past: Dict, present: Dict, future: Dict, timeline: Dict) -> str:
        """Generate human-readable temporal reasoning"""

        if past['score'] > 0.85 and present['score'] > 0.85 and future['score'] > 0.85:
            return f"TEMPORALLY SOUND: Strong past precedent, market ready today, future-proof. {timeline['time_to_market']}"
        elif present['score'] < 0.60:
            return "PREMATURE: Technology not ready for current market"
        elif future['score'] < 0.60:
            return "SHORT-LIVED: High obsolescence risk, limited future value"
        elif not timeline['feasible']:
            return "UNREALISTIC TIMELINE: Development timeline not achievable"
        else:
            return f"ACCEPTABLE: Reasonable temporal trajectory. {timeline['time_to_market']}"


# Test both lenses
if __name__ == "__main__":
    logger.info("=" * 80)
    logger.info("CRYSTALLINE INTENT & TEMPORAL ANALYSIS TESTING")
    logger.info("=" * 80)

    # Test invention
    sample_invention = {
        'title': 'VR Haptic Feedback System with Hardware-Enforced Safety Architecture',
        'description': 'TENS-based VR haptic glove with polyfuse current limiting',
        'architecture': {
            'Safety Controller': {
                'current_limit': '5 mA'
            }
        }
    }

    sample_claim = {
        'claim': 'Safety Controller: current_limit = 5 mA',
        'category': 'technical_specification'
    }

    # Test Crystalline Intent
    crystalline = CrystallineIntentLens()
    crystalline_result = crystalline.analyze(sample_claim, sample_invention)
    logger.info(f"\n💎 CRYSTALLINE INTENT RESULT: {crystalline_result['reasoning']}")
    logger.info(f"   Passed: {crystalline_result['passed']}")
    logger.info(f"   Confidence: {crystalline_result['confidence']:.2f}")

    # Test Temporal Analysis
    temporal = TemporalAnalysisLens()
    temporal_result = temporal.analyze(sample_claim, sample_invention)
    logger.info(f"\n⏳ TEMPORAL ANALYSIS RESULT: {temporal_result['reasoning']}")
    logger.info(f"   Passed: {temporal_result['passed']}")
    logger.info(f"   Confidence: {temporal_result['confidence']:.2f}")

    logger.info("=" * 80)
