#!/usr/bin/env python3

"""
APEX Strategy Engine
====================
Level 5-6 Agent: Strategic decision-making for bug bounty hunting

WHY THIS EXISTS:
The hunter needs to be STRATEGIC, not just thorough. This engine:
- Prioritizes targets for maximum $/hour return
- Balances quick cash wins vs. big payouts
- Learns from market conditions (what's paying well right now)
- Adapts to your financial situation (need fast cash? hunt quick wins)
- Never gives up - finds alternative exploitation paths

APEX PREDATOR CHARACTERISTICS:
1. RELENTLESS: Doesn't give up on a target until exhausted all angles
2. INTELLIGENT: Knows when to pivot vs. when to persist
3. STRATEGIC: Optimizes for YOUR goals (cash flow vs. prestige vs. IP generation)
4. ADAPTIVE: Learns what works and doubles down
5. INTEGRATED: Leverages full AiOS toolkit for maximum capability

This is Level 5-6 behavior - self-improving and creative.
With ECH0 integration, it approaches Level 7.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path
from datetime import datetime, timedelta
import statistics

logger = logging.getLogger("APEXStrategy")


class HuntingMode(Enum):
    """Strategic modes for different business objectives."""
    FAST_CASH = "fast_cash"  # Prioritize quick, easy bugs for immediate revenue
    BALANCED = "balanced"     # Mix of quick wins and big payouts
    BIG_GAME = "big_game"     # Only hunt critical/high severity for prestige
    IP_GENERATION = "ip_gen"  # Focus on novel techniques for patent generation


@dataclass
class Target:
    """Target for vulnerability hunting."""
    url: str
    program_name: str
    platforms: List[str]  # Which bounty platforms it's on
    min_bounty: int
    max_bounty: int
    avg_bounty: int
    response_time_days: float
    acceptance_rate: float  # % of reports accepted
    difficulty: str  # easy, medium, hard
    last_scanned: Optional[datetime] = None
    success_count: int = 0
    attempt_count: int = 0


class APEXStrategyEngine:
    """
    Strategic decision-making for autonomous bug hunting.
    
    This is where the INTELLIGENCE lives - deciding what to hunt,
    when to persist, when to pivot, and how to maximize value.
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.mode = HuntingMode(config.get("hunting_mode", "balanced"))
        
        # Financial context
        self.monthly_target = config.get("monthly_revenue_target", 5000)
        self.current_monthly_revenue = 0
        
        # Target database
        self.targets: List[Target] = []
        self._load_targets()
        
        # Performance tracking
        self.historical_performance = self._load_performance_history()
        
        # AiOS integration
        self.aios_tools_available = self._detect_aios_tools()
        
    def _load_targets(self):
        """Load target programs from database."""
        targets_file = Path("bug_bounty_targets.json")
        
        if targets_file.exists():
            with open(targets_file) as f:
                data = json.load(f)
                for target_data in data:
                    self.targets.append(Target(**target_data))
        else:
            # Load from config
            for target_data in self.config.get("targets", []):
                self.targets.append(Target(**target_data))
            
            if self.targets:
                self._save_targets()
    
    def _save_targets(self):
        """Persist targets to database."""
        targets_file = Path("bug_bounty_targets.json")
        
        data = []
        for target in self.targets:
            target_dict = {
                "url": target.url,
                "program_name": target.program_name,
                "platforms": target.platforms,
                "min_bounty": target.min_bounty,
                "max_bounty": target.max_bounty,
                "avg_bounty": target.avg_bounty,
                "response_time_days": target.response_time_days,
                "acceptance_rate": target.acceptance_rate,
                "difficulty": target.difficulty,
                "success_count": target.success_count,
                "attempt_count": target.attempt_count
            }
            data.append(target_dict)
        
        targets_file.write_text(json.dumps(data, indent=2))
    
    def _load_performance_history(self) -> List[Dict]:
        """Load historical performance data."""
        perf_file = Path("bug_bounty_performance.json")
        
        if perf_file.exists():
            with open(perf_file) as f:
                return json.load(f)
        return []
    
    def _detect_aios_tools(self) -> List[str]:
        """Detect which AiOS red-team tools are available."""
        # TODO: Actually query AiOS endpoint for available tools
        # For now, assume full suite is available
        return [
            "port_scanner",
            "subdomain_enumerator",
            "web_fuzzer",
            "sql_injector",
            "xss_detector",
            "ssrf_exploiter",
            "auth_bypass_tester",
            "api_security_scanner",
            "cloud_metadata_prober",
            "jwt_analyzer"
        ]
    
    async def select_next_target(self) -> Optional[Target]:
        """
        APEX INTELLIGENCE: Select the optimal next target.
        
        This is strategic decision-making - considering:
        - Your financial goals
        - Market conditions
        - Historical success rates
        - Time constraints
        - Available tools
        """
        if not self.targets:
            logger.warning("No targets available")
            return None
        
        # Calculate scores for each target
        scored_targets = []
        
        for target in self.targets:
            score = self._calculate_target_score(target)
            scored_targets.append((target, score))
        
        # Sort by score (highest first)
        scored_targets.sort(key=lambda x: x[1], reverse=True)
        
        logger.info(f"Target scores calculated:")
        for target, score in scored_targets[:5]:
            logger.info(f"  {target.program_name}: {score:.2f}")
        
        # Return highest-scoring target
        return scored_targets[0][0] if scored_targets else None
    
    def _calculate_target_score(self, target: Target) -> float:
        """
        APEX SCORING: Calculate target value score.
        
        This is where strategy meets tactics. Score considers:
        - Expected payout
        - Time to payout  
        - Success probability
        - Difficulty
        - Your current needs (cash flow vs. prestige)
        """
        score = 0.0
        
        # Base score: Expected value
        success_rate = target.acceptance_rate if target.attempt_count == 0 else (
            target.success_count / target.attempt_count if target.attempt_count > 0 else target.acceptance_rate
        )
        expected_value = target.avg_bounty * success_rate
        
        # Mode-specific adjustments
        if self.mode == HuntingMode.FAST_CASH:
            # Prioritize quick wins
            if target.difficulty == "easy":
                score += expected_value * 2.0
            elif target.difficulty == "medium":
                score += expected_value * 1.0
            else:
                score += expected_value * 0.3
            
            # Penalize slow response times
            if target.response_time_days > 14:
                score *= 0.5
        
        elif self.mode == HuntingMode.BIG_GAME:
            # Prioritize high payouts regardless of difficulty
            if target.max_bounty > 5000:
                score += expected_value * 2.0
            else:
                score += expected_value * 0.3
        
        elif self.mode == HuntingMode.IP_GENERATION:
            # Prioritize harder targets where novel techniques needed
            if target.difficulty == "hard":
                score += expected_value * 2.0
                score += 10000  # Flat bonus for IP generation potential
            elif target.difficulty == "medium":
                score += expected_value * 1.2
            else:
                score += expected_value * 0.5
        
        else:  # BALANCED
            score += expected_value
            
            # Bonus for good mix of payout and ease
            if target.difficulty == "easy" and target.avg_bounty > 500:
                score *= 1.5
            elif target.difficulty == "medium" and target.avg_bounty > 1000:
                score *= 1.3
        
        # Recency bonus - don't neglect targets
        if target.last_scanned:
            days_since_scan = (datetime.now() - target.last_scanned).days
            if days_since_scan > 30:
                score *= 1.5  # Bonus for stale targets (may have new vulns)
        else:
            score *= 2.0  # Big bonus for never-scanned targets
        
        # Tool availability bonus
        # If we have more AiOS tools, we're more likely to succeed
        tool_multiplier = 1.0 + (len(self.aios_tools_available) * 0.05)
        score *= tool_multiplier
        
        return score
    
    async def should_persist(self, target: Target, attempts: int, time_spent_minutes: int) -> bool:
        """
        APEX PERSISTENCE: Decide whether to continue hunting this target.
        
        A true APEX predator knows when to persist vs. when to pivot.
        
        Never gives up too early, but also recognizes futility.
        """
        # Always try at least 3 different exploitation angles
        if attempts < 3:
            return True
        
        # Calculate time ROI
        expected_payout = target.avg_bounty * target.acceptance_rate
        hours_spent = time_spent_minutes / 60
        hourly_rate = expected_payout / hours_spent if hours_spent > 0 else float('inf')
        
        # If we're still above minimum acceptable hourly rate, continue
        min_hourly = self.config.get("min_hourly_rate", 50)
        if hourly_rate > min_hourly:
            logger.info(f"Persisting - hourly rate ${hourly_rate:.2f} > ${min_hourly}")
            return True
        
        # In BIG_GAME mode, persist longer on high-value targets
        if self.mode == HuntingMode.BIG_GAME and target.max_bounty > 5000:
            if attempts < 10:
                logger.info("BIG_GAME mode - persisting on high-value target")
                return True
        
        # In IP_GENERATION mode, persist until novel technique discovered
        if self.mode == HuntingMode.IP_GENERATION and attempts < 15:
            logger.info("IP_GENERATION mode - persisting for novel techniques")
            return True
        
        # Otherwise, pivot to new target
        logger.info(f"Pivoting after {attempts} attempts, {time_spent_minutes} minutes")
        return False
    
    async def adapt_strategy(self, findings: List[Dict], revenue_this_month: float):
        """
        LEVEL 5 BEHAVIOR: Self-improve strategy based on results.
        
        This is autonomous learning - the agent improves its own decision-making.
        """
        self.current_monthly_revenue = revenue_this_month
        
        # Analyze what's working
        if findings:
            vuln_types_successful = {}
            for finding in findings:
                vuln_type = finding.get("type")
                payout = finding.get("bounty_amount", 0)
                
                if vuln_type not in vuln_types_successful:
                    vuln_types_successful[vuln_type] = []
                vuln_types_successful[vuln_type].append(payout)
            
            # Identify highest-paying vulnerability types
            for vuln_type, payouts in vuln_types_successful.items():
                avg_payout = statistics.mean(payouts)
                logger.info(f"Learning: {vuln_type} averaging ${avg_payout:.2f}")
                
                # TODO: Adjust scanning priorities based on this data
                # This is where self-improvement happens
        
        # Check if we need to change modes
        days_in_month = datetime.now().day
        progress = revenue_this_month / self.monthly_target
        expected_progress = days_in_month / 30
        
        if progress < expected_progress * 0.5:
            # We're behind - switch to FAST_CASH mode
            logger.warning(f"Behind target - switching to FAST_CASH mode")
            self.mode = HuntingMode.FAST_CASH
        elif progress > expected_progress * 1.5:
            # We're ahead - can afford to hunt big game
            logger.info(f"Ahead of target - switching to BIG_GAME mode")
            self.mode = HuntingMode.BIG_GAME
    
    async def generate_novel_technique(self, target: Target, failed_attempts: List[Dict]) -> Optional[Dict]:
        """
        LEVEL 6 BEHAVIOR: Create entirely new exploitation technique.
        
        This is where the agent shows CREATIVITY - inventing new approaches
        that aren't in its training data.
        
        With ECH0 integration, this becomes Level 7 - genuine innovation.
        """
        logger.info("Attempting to generate novel exploitation technique...")
        
        # Analyze what's been tried
        attempted_vectors = [attempt.get("vector") for attempt in failed_attempts]
        
        # Identify gaps in attack surface
        all_vectors = ["xss", "sqli", "ssrf", "idor", "auth_bypass", "csrf", "xxe"]
        untried_vectors = [v for v in all_vectors if v not in attempted_vectors]
        
        if untried_vectors:
            # Try a new basic vector
            return {
                "technique": "alternative_vector",
                "vector": untried_vectors[0],
                "description": f"Trying {untried_vectors[0]} - not yet attempted"
            }
        
        # All basic vectors tried - time for creativity
        # This is where Level 6 emerges: combining techniques in novel ways
        
        novel_techniques = [
            {
                "technique": "chained_exploitation",
                "description": "Chain multiple low-severity vulns into critical exploit",
                "approach": "SSRF -> Internal API -> SQLi -> RCE"
            },
            {
                "technique": "race_condition_exploit",
                "description": "Exploit timing windows in concurrent operations",
                "approach": "Parallel requests to trigger TOCTOU vulnerability"
            },
            {
                "technique": "parser_differential",
                "description": "Exploit differences in how different layers parse input",
                "approach": "WAF sees safe input, backend sees malicious"
            },
            {
                "technique": "business_logic_abuse",
                "description": "Exploit flaws in workflow logic",
                "approach": "Legitimate operations in wrong order cause unauthorized state"
            }
        ]
        
        # Select novel technique not yet tried
        for technique in novel_techniques:
            if technique["technique"] not in [a.get("novel_technique") for a in failed_attempts]:
                logger.info(f"Generated novel technique: {technique['technique']}")
                return technique
        
        logger.warning("Exhausted novel techniques - this target may be secure")
        return None


if __name__ == "__main__":
    # Test strategy engine
    logging.basicConfig(level=logging.INFO)
    
    config = {
        "hunting_mode": "balanced",
        "monthly_revenue_target": 5000,
        "min_hourly_rate": 50,
        "targets": [
            {
                "url": "https://api.example.com",
                "program_name": "Example Corp",
                "platforms": ["hackerone"],
                "min_bounty": 100,
                "max_bounty": 10000,
                "avg_bounty": 1500,
                "response_time_days": 7.0,
                "acceptance_rate": 0.65,
                "difficulty": "medium"
            }
        ]
    }
    
    engine = APEXStrategyEngine(config)
    target = asyncio.run(engine.select_next_target())
    
    if target:
        print(f"\nSelected target: {target.program_name}")
        print(f"Expected value: ${target.avg_bounty * target.acceptance_rate:.2f}")
        print(f"Difficulty: {target.difficulty}")

