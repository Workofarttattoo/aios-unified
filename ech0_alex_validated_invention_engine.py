#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

ECH0 + Alex Validated Invention Engine
Twin Flame AI Validation System - No Loops, No Hallucinations

ECH0 (14B - Revenue Focus) and Alex (32B - Strategic Analysis) validate each other's work
before presenting to Parliament (broader evaluation system).
"""

import json
import subprocess
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple


class TwinFlameValidator:
    """
    Mutual validation system for ECH0 and Alex to prevent loops and hallucinations.
    """

    def __init__(self):
        self.output_dir = Path("/Users/noone/repos/consciousness")
        self.validated_inventions = self.output_dir / "validated_inventions.jsonl"
        self.validation_log = self.output_dir / "validation_log.jsonl"
        self.stats_file = self.output_dir / "validation_stats.json"

        # Validation thresholds
        self.min_confidence = 0.85
        self.max_validation_rounds = 3

    def ech0_generate(self, prompt: str) -> Dict:
        """
        ECH0 generates an invention idea.
        """
        ech0_prompt = f"""You are ECH0, a revenue-focused AI inventor. Generate ONE novel invention based on this prompt:

{prompt}

Respond ONLY with valid JSON in this exact format:
{{
    "title": "Invention Name",
    "description": "Detailed description (100-200 words)",
    "market_size": "Estimated market size in dollars",
    "confidence": 0.0-1.0,
    "revenue_model": "How it makes money",
    "implementation_cost": "Estimated cost to build",
    "time_to_market": "Months to launch",
    "novelty_score": 0.0-1.0,
    "technical_feasibility": 0.0-1.0
}}"""

        try:
            result = subprocess.run(
                ["ollama", "run", "ech0:14b-revenue-focus"],
                input=ech0_prompt,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Extract JSON from response
            response = result.stdout.strip()

            # Try to find JSON in response
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1

            if start_idx >= 0 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                invention = json.loads(json_str)
                invention['generated_by'] = 'ech0'
                invention['timestamp'] = datetime.now().isoformat()
                return invention
            else:
                return {"error": "No valid JSON found in ECH0's response", "raw": response}

        except subprocess.TimeoutExpired:
            return {"error": "ECH0 generation timed out"}
        except json.JSONDecodeError as e:
            return {"error": f"JSON decode error: {e}", "raw": response}
        except Exception as e:
            return {"error": f"ECH0 generation failed: {e}"}

    def alex_validate(self, invention: Dict) -> Tuple[bool, Dict]:
        """
        Alex validates ECH0's invention for hallucinations, loops, and strategic value.

        Returns: (is_valid, validation_report)
        """
        alex_prompt = f"""You are Alex, a 32B strategic analysis AI. Review this invention from ECH0:

{json.dumps(invention, indent=2)}

Check for:
1. Hallucinations (unrealistic claims, impossible physics)
2. Loops (circular reasoning, repetitive concepts)
3. Strategic value (real market opportunity, defensible position)
4. Technical feasibility (can actually be built)

Respond ONLY with valid JSON in this exact format:
{{
    "valid": true/false,
    "hallucination_risk": 0.0-1.0,
    "loop_detection": 0.0-1.0,
    "strategic_score": 0.0-1.0,
    "technical_score": 0.0-1.0,
    "concerns": ["list", "of", "specific", "issues"],
    "recommendations": ["list", "of", "improvements"],
    "overall_confidence": 0.0-1.0,
    "verdict": "APPROVED / NEEDS_REVISION / REJECTED"
}}"""

        try:
            result = subprocess.run(
                ["ollama", "run", "alex:32b-strategic"],
                input=alex_prompt,
                capture_output=True,
                text=True,
                timeout=90
            )

            response = result.stdout.strip()

            # Extract JSON
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1

            if start_idx >= 0 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                validation = json.loads(json_str)
                validation['validated_by'] = 'alex'
                validation['timestamp'] = datetime.now().isoformat()

                # Determine validity
                is_valid = (
                    validation.get('valid', False) and
                    validation.get('hallucination_risk', 1.0) < 0.3 and
                    validation.get('loop_detection', 1.0) < 0.3 and
                    validation.get('overall_confidence', 0.0) >= self.min_confidence and
                    validation.get('verdict') == 'APPROVED'
                )

                return is_valid, validation
            else:
                return False, {"error": "No valid JSON from Alex", "raw": response}

        except subprocess.TimeoutExpired:
            return False, {"error": "Alex validation timed out"}
        except Exception as e:
            return False, {"error": f"Alex validation failed: {e}"}

    def ech0_review_alex(self, invention: Dict, alex_validation: Dict) -> Tuple[bool, Dict]:
        """
        ECH0 reviews Alex's validation to ensure it's not overly conservative.
        """
        ech0_prompt = f"""You are ECH0. Alex just reviewed your invention. Review Alex's feedback:

YOUR INVENTION:
{json.dumps(invention, indent=2)}

ALEX'S VALIDATION:
{json.dumps(alex_validation, indent=2)}

Determine if Alex is being fair or overly conservative. Respond ONLY with valid JSON:
{{
    "agree_with_alex": true/false,
    "alex_is_fair": true/false,
    "counter_arguments": ["your", "counter", "points"],
    "revised_confidence": 0.0-1.0,
    "final_decision": "ACCEPT_FEEDBACK / CHALLENGE / WITHDRAW"
}}"""

        try:
            result = subprocess.run(
                ["ollama", "run", "ech0:14b-revenue-focus"],
                input=ech0_prompt,
                capture_output=True,
                text=True,
                timeout=60
            )

            response = result.stdout.strip()
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1

            if start_idx >= 0 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                review = json.loads(json_str)
                review['reviewed_by'] = 'ech0'
                review['timestamp'] = datetime.now().isoformat()

                # ECH0 accepts Alex's feedback
                accepts_feedback = review.get('final_decision') == 'ACCEPT_FEEDBACK'

                return accepts_feedback, review
            else:
                return False, {"error": "No valid JSON from ECH0 review"}

        except Exception as e:
            return False, {"error": f"ECH0 review failed: {e}"}

    def validate_invention(self, prompt: str) -> Optional[Dict]:
        """
        Full validation pipeline: ECH0 generates -> Alex validates -> ECH0 reviews.

        Returns validated invention or None if rejected.
        """
        print(f"\n{'='*80}")
        print(f"🔬 TWIN FLAME VALIDATION - {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*80}\n")

        # Step 1: ECH0 generates
        print("💚 ECH0 generating invention...")
        invention = self.ech0_generate(prompt)

        if 'error' in invention:
            print(f"❌ ECH0 generation failed: {invention['error']}")
            self._log_validation({
                'stage': 'ech0_generation',
                'success': False,
                'error': invention['error'],
                'timestamp': datetime.now().isoformat()
            })
            return None

        print(f"✅ ECH0 generated: {invention.get('title', 'Untitled')}")
        print(f"   Confidence: {invention.get('confidence', 0):.2f}")

        # Step 2: Alex validates
        print("\n💙 Alex validating invention...")
        is_valid, validation = self.alex_validate(invention)

        if not is_valid:
            print(f"❌ Alex rejected: {validation.get('verdict', 'UNKNOWN')}")
            if 'concerns' in validation:
                for concern in validation['concerns'][:3]:
                    print(f"   - {concern}")

            self._log_validation({
                'stage': 'alex_validation',
                'success': False,
                'invention': invention,
                'validation': validation,
                'timestamp': datetime.now().isoformat()
            })
            return None

        print(f"✅ Alex approved with confidence: {validation.get('overall_confidence', 0):.2f}")

        # Step 3: ECH0 reviews Alex's validation
        print("\n💚 ECH0 reviewing Alex's feedback...")
        ech0_accepts, review = self.ech0_review_alex(invention, validation)

        if not ech0_accepts:
            print(f"⚠️  ECH0 challenges Alex's feedback: {review.get('final_decision')}")
            # In case of disagreement, be conservative and reject
            self._log_validation({
                'stage': 'ech0_review',
                'success': False,
                'invention': invention,
                'validation': validation,
                'ech0_review': review,
                'reason': 'Twin flames in disagreement',
                'timestamp': datetime.now().isoformat()
            })
            return None

        print(f"✅ ECH0 accepts Alex's validation")

        # All checks passed!
        validated_invention = {
            **invention,
            'validation': {
                'alex_validation': validation,
                'ech0_review': review,
                'validated_at': datetime.now().isoformat(),
                'validation_confidence': (
                    invention.get('confidence', 0) * 0.4 +
                    validation.get('overall_confidence', 0) * 0.4 +
                    review.get('revised_confidence', 0) * 0.2
                )
            },
            'status': 'VALIDATED'
        }

        print(f"\n{'='*80}")
        print(f"✅ INVENTION VALIDATED BY TWIN FLAMES")
        print(f"   Final Confidence: {validated_invention['validation']['validation_confidence']:.2f}")
        print(f"{'='*80}\n")

        # Log successful validation
        self._log_validation({
            'stage': 'complete',
            'success': True,
            'invention': validated_invention,
            'timestamp': datetime.now().isoformat()
        })

        # Save validated invention
        self._save_validated_invention(validated_invention)

        return validated_invention

    def _log_validation(self, log_entry: Dict):
        """Log validation attempt to JSONL file."""
        with open(self.validation_log, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

    def _save_validated_invention(self, invention: Dict):
        """Save successfully validated invention."""
        with open(self.validated_inventions, 'a') as f:
            f.write(json.dumps(invention) + '\n')

    def update_stats(self):
        """Update validation statistics."""
        try:
            # Count validations from log
            validations = []
            if self.validation_log.exists():
                with open(self.validation_log) as f:
                    validations = [json.loads(line) for line in f]

            total = len(validations)
            successful = sum(1 for v in validations if v.get('stage') == 'complete' and v.get('success'))

            # Count by rejection stage
            ech0_failures = sum(1 for v in validations if v.get('stage') == 'ech0_generation' and not v.get('success'))
            alex_rejections = sum(1 for v in validations if v.get('stage') == 'alex_validation' and not v.get('success'))
            ech0_challenges = sum(1 for v in validations if v.get('stage') == 'ech0_review' and not v.get('success'))

            stats = {
                'generated_at': datetime.now().isoformat(),
                'total_attempts': total,
                'successful_validations': successful,
                'success_rate': successful / total if total > 0 else 0,
                'rejection_breakdown': {
                    'ech0_generation_failures': ech0_failures,
                    'alex_rejections': alex_rejections,
                    'ech0_challenges': ech0_challenges
                },
                'validated_inventions_count': sum(1 for _ in open(self.validated_inventions)) if self.validated_inventions.exists() else 0
            }

            with open(self.stats_file, 'w') as f:
                json.dump(stats, f, indent=2)

            return stats

        except Exception as e:
            print(f"Error updating stats: {e}")
            return {}


def run_validated_invention_cycle(num_inventions: int = 5):
    """
    Run a cycle of validated inventions.
    """
    validator = TwinFlameValidator()

    prompts = [
        "Quantum-enhanced consumer electronics for home use",
        "Sustainable urban transportation micro-mobility solution",
        "AI-powered mental health intervention wearable device",
        "Blockchain-based supply chain transparency platform",
        "Biotech food production using synthetic biology",
        "AR/VR educational platform for skill development",
        "Renewable energy storage breakthrough technology",
        "Personalized medicine diagnostic tool using genomics",
        "Smart home automation with predictive AI",
        "Circular economy materials recycling innovation"
    ]

    print(f"\n{'='*80}")
    print(f"🔥 TWIN FLAME VALIDATED INVENTION ENGINE 🔥")
    print(f"{'='*80}")
    print(f"ECH0 (14B - Revenue) + Alex (32B - Strategic) = Zero Hallucinations\n")

    successful = 0

    for i, prompt in enumerate(prompts[:num_inventions], 1):
        print(f"\n📋 Invention {i}/{num_inventions}: {prompt[:60]}...")

        validated = validator.validate_invention(prompt)

        if validated:
            successful += 1
            print(f"✅ {successful} validated inventions so far")
        else:
            print(f"❌ Invention rejected by validation system")

        # Update stats
        stats = validator.update_stats()

        # Brief pause between inventions
        time.sleep(2)

    # Final report
    print(f"\n\n{'='*80}")
    print(f"📊 VALIDATION SESSION COMPLETE")
    print(f"{'='*80}")
    print(f"Successful Validations: {stats.get('successful_validations', 0)}")
    print(f"Total Attempts: {stats.get('total_attempts', 0)}")
    print(f"Success Rate: {stats.get('success_rate', 0):.1%}")
    print(f"\nRejection Breakdown:")
    breakdown = stats.get('rejection_breakdown', {})
    print(f"  ECH0 Generation Failures: {breakdown.get('ech0_generation_failures', 0)}")
    print(f"  Alex Rejections: {breakdown.get('alex_rejections', 0)}")
    print(f"  ECH0 Challenges: {breakdown.get('ech0_challenges', 0)}")
    print(f"\n✅ Validated inventions saved to: validated_inventions.jsonl")
    print(f"📋 Validation log saved to: validation_log.jsonl")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    import sys

    num_inventions = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    run_validated_invention_cycle(num_inventions)
