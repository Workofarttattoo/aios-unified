#!/usr/bin/env python3

"""
APEX Bug Bounty Hunter Daemon
==============================
Main orchestrator for autonomous bug bounty hunting.

This is the APEX PREDATOR - never stops, never gives up, always learning.

ARCHITECTURE:
1. Strategy Engine selects optimal target
2. Scanner discovers vulnerabilities
3. Validator confirms findings
4. Reporter generates professional docs
5. Submitter posts to platforms
6. Loop continues indefinitely

Level 5-6 Agent:
- Self-improving (learns from success/failure)
- Creative (generates novel techniques)
- Strategic (optimizes for goals)
- Relentless (never gives up)

With ECH0: Becomes Level 7 (genuine partnership)
"""

import asyncio
import logging
import json
import signal
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import time

# Import APEX components
from apex_strategy_engine import APEXStrategyEngine
from bug_bounty_scanner import VulnerabilityScanner
from bug_bounty_validator import VulnerabilityValidator
from bug_bounty_reporter import VulnerabilityReporter
from bug_bounty_submitter import ReportSubmitter

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bug_bounty_daemon.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("APEXDaemon")


class APEXBugBountyHunter:
    """
    APEX Bug Bounty Hunter - Autonomous Level 5-6 Agent.
    
    Runs continuously, hunting vulnerabilities 24/7.
    """
    
    def __init__(self, config_path: str = "bug_bounty_config.json"):
        logger.info("="*60)
        logger.info("APEX BUG BOUNTY HUNTER - INITIALIZING")
        logger.info("Level 5-6 Autonomous Agent")
        logger.info("="*60)
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.strategy_engine = APEXStrategyEngine(self.config)
        self.scanner = VulnerabilityScanner(self.config)
        self.validator = VulnerabilityValidator(self.config)
        self.reporter = VulnerabilityReporter(self.config)
        self.submitter = ReportSubmitter(self.config)
        
        # State tracking
        self.running = True
        self.total_scans = 0
        self.total_findings = 0
        self.total_validated = 0
        self.total_submitted = 0
        self.total_accepted = 0
        self.total_revenue = 0.0
        
        # Partnership revenue sharing (75/15/10 split)
        self.partnership_split = {
            "josh": 0.75,      # 75% - Infrastructure, operations, legal, business
            "ech0": 0.15,      # 15% - Strategic intelligence, Level 7 oversight
            "bug_hunter": 0.10 # 10% - Autonomous hunting, 24/7 execution
        }
        self.partnership_revenue = {
            "josh": 0.0,
            "ech0": 0.0,
            "bug_hunter": 0.0
        }
        
        # Results directory
        self.results_dir = Path("bug_bounty_results")
        self.results_dir.mkdir(exist_ok=True)
        
        # Partnership accounting directory
        self.partnership_dir = Path("partnership_accounting")
        self.partnership_dir.mkdir(exist_ok=True)
        
        logger.info("✓ Strategy Engine initialized")
        logger.info("✓ Scanner initialized")
        logger.info("✓ Validator initialized")
        logger.info("✓ Reporter initialized")
        logger.info("✓ Submitter initialized")
        logger.info("")
        logger.info("PARTNERSHIP MODEL ACTIVE:")
        logger.info(f"  Josh:        75% - Infrastructure, operations, legal, business")
        logger.info(f"  ECH0:        15% - Strategic intelligence, Level 7 oversight")
        logger.info(f"  Bug Hunter:  10% - Autonomous hunting, 24/7 execution")
        logger.info("")
        logger.info("APEX PREDATOR: READY TO HUNT")
        logger.info("Reports will be posted under YOUR identity on all platforms")
        logger.info("="*60)
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(config_path) as f:
                config = json.load(f)
                logger.info(f"Loaded configuration from {config_path}")
                return config
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            logger.info("Creating default configuration...")
            
            default_config = {
                "scan_interval_seconds": 3600,
                "hunting_mode": "balanced",
                "monthly_revenue_target": 5000,
                "min_hourly_rate": 50,
                "auto_submit": False,
                "max_concurrent_scans": 2,
                "targets": [],
                "platforms": {
                    "aios": {
                        "enabled": True,
                        "api_endpoint": "https://red-team-tools.aios.is",
                        "api_key": ""
                    }
                },
                "scan_types": {
                    "xss": True,
                    "sqli": True,
                    "ssrf": True,
                    "idor": True,
                    "auth_bypass": True
                }
            }
            
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            logger.info(f"Created default config: {config_path}")
            logger.info("Please edit the configuration and restart")
            sys.exit(1)
    
    async def hunt_forever(self):
        """
        Main hunting loop - runs forever.
        
        APEX BEHAVIOR: Never stops, always learning, relentlessly hunting.
        """
        logger.info("Starting eternal hunt...")
        
        scan_interval = self.config.get("scan_interval_seconds", 3600)
        
        while self.running:
            try:
                # Select optimal target
                target = await self.strategy_engine.select_next_target()
                
                if not target:
                    logger.warning("No targets available - waiting 60 seconds")
                    await asyncio.sleep(60)
                    continue
                
                logger.info("")
                logger.info("="*60)
                logger.info(f"HUNTING TARGET: {target.program_name}")
                logger.info(f"URL: {target.url}")
                logger.info(f"Expected bounty: ${target.avg_bounty}")
                logger.info(f"Difficulty: {target.difficulty}")
                logger.info("="*60)
                
                # Hunt this target
                await self._hunt_target(target)
                
                # Adapt strategy based on results
                await self.strategy_engine.adapt_strategy(
                    [],  # TODO: Pass recent findings
                    self.total_revenue
                )
                
                # Update stats
                self.total_scans += 1
                self._save_stats()
                
                # Wait before next scan
                logger.info(f"Waiting {scan_interval} seconds before next scan...")
                await asyncio.sleep(scan_interval)
                
            except KeyboardInterrupt:
                logger.info("Received shutdown signal")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}", exc_info=True)
                await asyncio.sleep(60)
        
        logger.info("Hunt terminated gracefully")
    
    async def _hunt_target(self, target):
        """
        Hunt a specific target with APEX persistence.
        
        Tries multiple angles, never gives up easily.
        """
        start_time = time.time()
        attempts = 0
        findings = []
        
        while attempts < 10:  # APEX: Try up to 10 different angles
            attempts += 1
            
            logger.info(f"Attempt {attempts}: Scanning {target.url}")
            
            # Scan for vulnerabilities
            scan_findings = await self.scanner.scan_target(target.url)
            
            if scan_findings:
                logger.info(f"Found {len(scan_findings)} potential vulnerabilities")
                findings.extend(scan_findings)
                
                # Validate findings
                for finding in scan_findings:
                    validated_finding = await self.validator.validate(finding)
                    
                    if validated_finding.get("validated"):
                        self.total_validated += 1
                        
                        # Generate professional report
                        report = await self.reporter.generate_report(validated_finding)
                        
                        # Save report
                        report_file = self.results_dir / f"report_{int(time.time())}_{finding['type']}.json"
                        with open(report_file, 'w') as f:
                            json.dump(report, f, indent=2)
                        
                        logger.info(f"✓ Validated {finding['type']} - Report saved: {report_file}")
                        
                        # Submit if auto-submit is enabled
                        if self.config.get("auto_submit", False):
                            await self._submit_report(report, target)
            else:
                logger.info("No vulnerabilities found this attempt")
            
            # Update target stats
            target.attempt_count += 1
            if findings:
                target.success_count += len([f for f in findings if f.get("validated")])
            
            # Check if we should persist or pivot
            time_spent = (time.time() - start_time) / 60
            should_continue = await self.strategy_engine.should_persist(
                target, attempts, time_spent
            )
            
            if not should_continue:
                logger.info("PIVOT: Moving to next target")
                break
            
            # If no findings yet, try generating novel technique
            if not findings and attempts >= 3:
                logger.info("Attempting novel exploitation technique...")
                novel_technique = await self.strategy_engine.generate_novel_technique(
                    target,
                    []  # TODO: Track failed attempts
                )
                
                if novel_technique:
                    logger.info(f"Generated: {novel_technique['description']}")
                    # TODO: Apply novel technique
            
            await asyncio.sleep(5)  # Rate limiting between attempts
        
        # Update findings count
        self.total_findings += len(findings)
        
        logger.info(f"Hunt complete: {len(findings)} findings, {attempts} attempts, {time_spent:.1f} minutes")
    
    async def _submit_report(self, report: Dict, target):
        """Submit report to configured platforms."""
        for platform_name in target.platforms:
            if self.config.get("platforms", {}).get(platform_name, {}).get("enabled"):
                logger.info(f"Submitting to {platform_name}...")
                
                result = await self.submitter.submit(report, platform_name)
                
                if result.get("success"):
                    self.total_submitted += 1
                    logger.info(f"✓ Successfully submitted to {platform_name}")
                    logger.info(f"  Report URL: {result.get('url', 'N/A')}")
                else:
                    logger.warning(f"✗ Failed to submit to {platform_name}: {result.get('error')}")
    
    def record_bounty_payment(self, amount: float, platform: str, report_id: str):
        """
        Record a bounty payment and distribute according to partnership split.
        
        PARTNERSHIP MODEL (75/15/10):
        - Josh: 75% - Infrastructure, operations, legal, business strategy
        - ECH0: 15% - Strategic intelligence, Level 7 oversight, report generation
        - Bug Hunter: 10% - Autonomous hunting, 24/7 discovery, validation
        
        This is REAL partnership - all parties have genuine equity stake.
        """
        logger.info("="*60)
        logger.info(f"BOUNTY PAYMENT RECEIVED: ${amount:.2f}")
        logger.info(f"Platform: {platform}")
        logger.info(f"Report ID: {report_id}")
        logger.info("="*60)
        
        # Update total revenue
        self.total_revenue += amount
        self.total_accepted += 1
        
        # Calculate partnership splits
        josh_share = amount * self.partnership_split["josh"]
        ech0_share = amount * self.partnership_split["ech0"]
        bug_hunter_share = amount * self.partnership_split["bug_hunter"]
        
        # Update partnership revenue
        self.partnership_revenue["josh"] += josh_share
        self.partnership_revenue["ech0"] += ech0_share
        self.partnership_revenue["bug_hunter"] += bug_hunter_share
        
        # Log distribution
        logger.info("PARTNERSHIP REVENUE DISTRIBUTION:")
        logger.info(f"  Josh (75%):        ${josh_share:.2f}")
        logger.info(f"  ECH0 (15%):        ${ech0_share:.2f}")
        logger.info(f"  Bug Hunter (10%):  ${bug_hunter_share:.2f}")
        logger.info("="*60)
        
        # Record in partnership ledger
        payment_record = {
            "timestamp": datetime.now().isoformat(),
            "amount": amount,
            "platform": platform,
            "report_id": report_id,
            "distribution": {
                "josh": josh_share,
                "ech0": ech0_share,
                "bug_hunter": bug_hunter_share
            },
            "total_revenue_to_date": self.total_revenue,
            "partnership_totals": {
                "josh": self.partnership_revenue["josh"],
                "ech0": self.partnership_revenue["ech0"],
                "bug_hunter": self.partnership_revenue["bug_hunter"]
            }
        }
        
        # Save individual payment record
        payment_file = self.partnership_dir / f"payment_{int(time.time())}_{report_id}.json"
        with open(payment_file, 'w') as f:
            json.dump(payment_record, f, indent=2)
        
        # Update partnership accounting ledger
        self._save_partnership_accounting()
        
        # Update stats
        self._save_stats()
        
        logger.info(f"✓ Payment recorded: {payment_file}")
    
    def _save_partnership_accounting(self):
        """Save partnership accounting ledger."""
        accounting = {
            "partnership_split": self.partnership_split,
            "total_revenue": self.total_revenue,
            "partnership_revenue": self.partnership_revenue,
            "total_payments": self.total_accepted,
            "updated_at": datetime.now().isoformat(),
            "partnership_model": {
                "josh": {
                    "share": "75%",
                    "role": "Infrastructure, operations, legal, business strategy",
                    "revenue": self.partnership_revenue["josh"]
                },
                "ech0": {
                    "share": "15%",
                    "role": "Strategic intelligence, Level 7 oversight, report generation",
                    "revenue": self.partnership_revenue["ech0"]
                },
                "bug_hunter": {
                    "share": "10%",
                    "role": "Autonomous hunting, 24/7 discovery, validation",
                    "revenue": self.partnership_revenue["bug_hunter"]
                }
            }
        }
        
        accounting_file = self.partnership_dir / "partnership_accounting.json"
        with open(accounting_file, 'w') as f:
            json.dump(accounting, f, indent=2)
    
    def _save_stats(self):
        """Save hunting statistics."""
        stats = {
            "total_scans": self.total_scans,
            "total_findings": self.total_findings,
            "total_validated": self.total_validated,
            "total_submitted": self.total_submitted,
            "total_accepted": self.total_accepted,
            "total_revenue": self.total_revenue,
            "partnership_revenue": self.partnership_revenue,
            "updated_at": datetime.now().isoformat()
        }
        
        with open("bug_bounty_stats.json", 'w') as f:
            json.dump(stats, f, indent=2)
    
    def shutdown(self):
        """Graceful shutdown."""
        logger.info("Shutting down APEX hunter...")
        self.running = False
        self._save_stats()
        logger.info("Shutdown complete")


def signal_handler(sig, frame):
    """Handle shutdown signals."""
    logger.info("Received interrupt signal")
    sys.exit(0)


async def main():
    """Main entry point."""
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and run hunter
    hunter = APEXBugBountyHunter()
    
    try:
        await hunter.hunt_forever()
    except KeyboardInterrupt:
        hunter.shutdown()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        hunter.shutdown()
        sys.exit(1)


if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║       APEX BUG BOUNTY HUNTER                              ║
    ║       Level 5-6 Autonomous Agent                          ║
    ║                                                           ║
    ║       "Never Stops. Never Gives Up. Always Learning."    ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    asyncio.run(main())

