#!/usr/bin/env python3
"""
Ai:oS Natural Language Shell - Conversational Computing Interface

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

This module implements a natural language shell for Ai:oS that translates
conversational input into system actions, enabling true voice-first computing.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Intent patterns for natural language understanding
INTENT_PATTERNS = {
    # System operations
    "boot": [
        r"\b(boot|start|launch|initialize)\s*(system|os|aios)?\b",
        r"\b(turn on|power on|wake up)\b",
        r"\b(bring up|spin up)\s*(the\s*)?(system|os)?\b",
    ],
    "shutdown": [
        r"\b(shutdown|power off|turn off|stop)\s*(system|os)?\b",
        r"\b(shut down|power down)\b",
    ],
    "status": [
        r"\b(status|state|health)\s*(check|report)?\b",
        r"\b(how('s| is)\s*(the)?\s*(system|os)|what('s| is)\s*going on)\b",
        r"\b(show\s*(me\s*)?(system\s*)?status)\b",
    ],

    # Security operations
    "enable_firewall": [
        r"\b(enable|activate|turn on|start)\s*(the\s*)?firewall\b",
        r"\b(firewall\s*(on|enable|start))\b",
    ],
    "disable_firewall": [
        r"\b(disable|deactivate|turn off|stop)\s*(the\s*)?firewall\b",
        r"\b(firewall\s*(off|disable|stop))\b",
    ],
    "check_security": [
        r"\b(check|scan|audit|verify)\s*(system\s*)?(security|vulnerabilities)\b",
        r"\b(security\s*(check|scan|audit|status))\b",
        r"\b(run\s*(security\s*)?(scan|audit))\b",
    ],

    # Network operations
    "check_network": [
        r"\b(check|show|display|view)\s*(my\s*)?(network|connectivity|connection)\b",
        r"\b(network\s*(status|check|info))\b",
        r"\b(am i|is\s*(the\s*)?system)\s*(connected|online)\b",
    ],
    "configure_network": [
        r"\b(configure|setup|set up)\s*(the\s*)?network\b",
        r"\b(network\s*config(uration)?)\b",
    ],

    # Storage operations
    "check_disk": [
        r"\b(check|show|display|view)\s*(disk|storage|space|volume)s?\b",
        r"\b(disk\s*(space|usage|status))\b",
        r"\b(how\s*much\s*(disk\s*)?space)\b",
    ],
    "mount_volume": [
        r"\b(mount|attach)\s*(volume|disk|drive)\b",
    ],
    "unmount_volume": [
        r"\b(unmount|eject|detach)\s*(volume|disk|drive)\b",
    ],

    # Process management
    "list_processes": [
        r"\b(list|show|display|view)\s*(all\s*)?(processes|tasks|apps)\b",
        r"\b(what('s| is)\s*(running|active))\b",
        r"\b(processes\s*(list|running))\b",
    ],
    "kill_process": [
        r"\b(kill|stop|terminate|end)\s*(process|task|app)\b",
    ],

    # Application management
    "start_app": [
        r"\b(start|launch|run|open)\s*(application|app|program)\b",
    ],
    "stop_app": [
        r"\b(stop|close|quit|exit)\s*(application|app|program)\b",
    ],

    # BBB/Humanitarian operations
    "check_bbb_status": [
        r"\b(check|show|view)\s*(bbb|business|income|earnings)\s*(status|dashboard)?\b",
        r"\b(how\s*much\s*(money|income|earnings)\s*(have\s*i\s*made)?)\b",
        r"\b(show\s*(my\s*)?dashboard)\b",
    ],
    "request_payout": [
        r"\b(request|initiate|withdraw)\s*(payout|payment|cash out)\b",
        r"\b(i\s*want\s*(my\s*)?(money|payment|payout))\b",
        r"\b(cash out|withdraw\s*funds)\b",
    ],

    # Food redistribution (FoodNet)
    "check_food_inventory": [
        r"\b(check|show|view)\s*(food|inventory|pantry)\s*(status|levels?)?\b",
        r"\b(what\s*food\s*(do\s*we\s*have|is\s*available))\b",
    ],
    "dispatch_robot": [
        r"\b(send|dispatch|deploy)\s*(robot|pickup)\b",
        r"\b(robot\s*(pickup|dispatch))\b",
    ],

    # Quantum operations
    "run_quantum_sim": [
        r"\b(run|execute|start)\s*(quantum\s*)?(simulation|sim|circuit)\b",
        r"\b(quantum\s*(sim|compute|run))\b",
    ],

    # Meta-operations
    "help": [
        r"\b(help|assist|guide|instructions|commands)\b",
        r"\b(what\s*can\s*(you|i)\s*(do|say))\b",
        r"\b(how\s*do\s*i\s*use\s*(this|aios))\b",
    ],
    "list_capabilities": [
        r"\b(list|show|display)\s*(all\s*)?(capabilities|commands|actions|features)\b",
        r"\b(what\s*can\s*you\s*(do|handle|manage))\b",
    ],
}

# Intent to action mapping (meta_agent.action format)
INTENT_TO_ACTION = {
    "boot": "kernel.initialize",
    "shutdown": "kernel.shutdown",
    "status": "orchestration.health_monitoring",
    "enable_firewall": "security.firewall",
    "disable_firewall": "security.firewall",  # Will need parameter
    "check_security": "security.integrity",
    "check_network": "networking.network_status",
    "configure_network": "networking.network_config",
    "check_disk": "storage.volume_inventory",
    "mount_volume": "storage.mount",
    "unmount_volume": "storage.unmount",
    "list_processes": "kernel.process_management",
    "kill_process": "kernel.process_kill",
    "start_app": "application.supervisor",
    "stop_app": "application.stop",
    "check_bbb_status": "bbb.dashboard",
    "request_payout": "bbb.payout",
    "check_food_inventory": "foodnet.inventory",
    "dispatch_robot": "foodnet.dispatch",
    "run_quantum_sim": "quantum.simulate",
    "help": "meta.help",
    "list_capabilities": "meta.list_capabilities",
}

@dataclass
class Intent:
    """Represents a recognized user intent"""
    name: str
    confidence: float
    action: str
    parameters: Dict[str, str]
    original_text: str

class NaturalLanguageShell:
    """
    Natural Language Shell for Ai:oS

    Translates conversational input into system actions.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger = logging.getLogger("NLShell")
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

    def parse_intent(self, user_input: str) -> List[Intent]:
        """
        Parse user input to determine intent

        Args:
            user_input: Natural language input from user

        Returns:
            List of Intent objects sorted by confidence
        """
        user_input = user_input.lower().strip()
        intents = []

        for intent_name, patterns in INTENT_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, user_input, re.IGNORECASE)
                if match:
                    # Calculate confidence based on match quality
                    confidence = self._calculate_confidence(user_input, match)

                    # Extract parameters
                    parameters = self._extract_parameters(user_input, intent_name, match)

                    # Map to action
                    action = INTENT_TO_ACTION.get(intent_name, "unknown")

                    intent = Intent(
                        name=intent_name,
                        confidence=confidence,
                        action=action,
                        parameters=parameters,
                        original_text=user_input
                    )
                    intents.append(intent)

                    self.logger.debug(f"Matched intent: {intent_name} (confidence: {confidence:.2f})")
                    break  # Only match once per intent

        # Sort by confidence
        intents.sort(key=lambda x: x.confidence, reverse=True)
        return intents

    def _calculate_confidence(self, user_input: str, match: re.Match) -> float:
        """Calculate confidence score for intent match"""
        # Base confidence
        confidence = 0.5

        # Boost for exact match
        if match.group(0) == user_input:
            confidence += 0.4
        else:
            # Boost based on match coverage
            match_coverage = len(match.group(0)) / len(user_input)
            confidence += match_coverage * 0.3

        # Boost for start of sentence
        if match.start() == 0:
            confidence += 0.1

        return min(confidence, 1.0)

    def _extract_parameters(self, user_input: str, intent_name: str, match: re.Match) -> Dict[str, str]:
        """Extract parameters from user input"""
        parameters = {}

        # Intent-specific parameter extraction
        if intent_name in ["kill_process", "start_app", "stop_app"]:
            # Try to extract process/app name
            # Look for quoted strings or common app names
            quoted = re.findall(r'"([^"]+)"|\'([^\']+)\'', user_input)
            if quoted:
                parameters["name"] = quoted[0][0] or quoted[0][1]

        elif intent_name in ["mount_volume", "unmount_volume"]:
            # Try to extract volume name/path
            paths = re.findall(r'/[^\s]+', user_input)
            if paths:
                parameters["path"] = paths[0]

        elif intent_name == "request_payout":
            # Extract payout method
            if "crypto" in user_input or "bitcoin" in user_input:
                parameters["method"] = "crypto"
            elif "check" in user_input:
                parameters["method"] = "check"
            else:
                parameters["method"] = "direct_deposit"

        return parameters

    def translate_to_command(self, intent: Intent) -> str:
        """
        Translate intent to Ai:oS command

        Args:
            intent: Recognized intent

        Returns:
            Ai:oS command string
        """
        if intent.action == "unknown":
            return None

        # Build command
        command = f"python3 aios/aios -v exec {intent.action}"

        # Add parameters as environment variables if needed
        if intent.parameters:
            env_vars = []
            for key, value in intent.parameters.items():
                env_var = f"AIOS_{key.upper()}={value}"
                env_vars.append(env_var)

            if env_vars:
                command = " ".join(env_vars) + " " + command

        return command

    def explain_intent(self, intent: Intent) -> str:
        """Generate human-readable explanation of intent"""
        explanations = {
            "boot": "I'll boot the Ai:oS system",
            "shutdown": "I'll shut down the Ai:oS system",
            "status": "I'll check the system status",
            "enable_firewall": "I'll enable the firewall",
            "disable_firewall": "I'll disable the firewall",
            "check_security": "I'll run a security check",
            "check_network": "I'll check the network status",
            "configure_network": "I'll configure the network",
            "check_disk": "I'll check disk space and storage",
            "mount_volume": "I'll mount the specified volume",
            "unmount_volume": "I'll unmount the specified volume",
            "list_processes": "I'll list all running processes",
            "kill_process": "I'll terminate the specified process",
            "start_app": "I'll start the specified application",
            "stop_app": "I'll stop the specified application",
            "check_bbb_status": "I'll show your BBB earnings dashboard",
            "request_payout": "I'll initiate a payout request",
            "check_food_inventory": "I'll check the food inventory status",
            "dispatch_robot": "I'll dispatch a pickup robot",
            "run_quantum_sim": "I'll run a quantum simulation",
            "help": "I'll show you help information",
            "list_capabilities": "I'll list all available capabilities",
        }

        explanation = explanations.get(intent.name, f"I'll execute {intent.action}")

        if intent.parameters:
            param_str = ", ".join(f"{k}={v}" for k, v in intent.parameters.items())
            explanation += f" (with parameters: {param_str})"

        return explanation

    def interactive_shell(self):
        """Run interactive natural language shell"""
        print("=" * 60)
        print("Ai:oS Natural Language Shell")
        print("Copyright (c) 2025 Joshua Hendricks Cole")
        print("=" * 60)
        print("\nSpeak naturally. Type 'exit' or 'quit' to leave.\n")

        while True:
            try:
                user_input = input("You: ").strip()

                if user_input.lower() in ["exit", "quit", "bye", "goodbye"]:
                    print("Ai:oS: Goodbye!")
                    break

                if not user_input:
                    continue

                # Parse intent
                intents = self.parse_intent(user_input)

                if not intents:
                    print("Ai:oS: I didn't understand that. Try 'help' for available commands.")
                    continue

                # Use highest confidence intent
                best_intent = intents[0]

                if best_intent.confidence < 0.3:
                    print(f"Ai:oS: I'm not confident I understood that (confidence: {best_intent.confidence:.1%}).")
                    print("Did you mean one of these:")
                    for intent in intents[:3]:
                        print(f"  - {intent.name} ({intent.confidence:.1%})")
                    continue

                # Explain and confirm
                explanation = self.explain_intent(best_intent)
                print(f"Ai:oS: {explanation}")

                # Translate to command
                command = self.translate_to_command(best_intent)

                if self.verbose:
                    print(f"[DEBUG] Command: {command}")

                # Execute (placeholder - would integrate with Ai:oS runtime)
                print(f"[Would execute: {best_intent.action}]")

            except KeyboardInterrupt:
                print("\nAi:oS: Interrupted. Goodbye!")
                break
            except Exception as exc:
                print(f"Ai:oS: Error: {exc}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()

def main(argv: Optional[List[str]] = None) -> int:
    """Main entrypoint"""
    parser = argparse.ArgumentParser(
        description="Ai:oS Natural Language Shell - Conversational Computing Interface"
    )
    parser.add_argument(
        "input",
        nargs="*",
        help="Natural language command (if not provided, enters interactive mode)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse intent but don't execute commands"
    )

    args = parser.parse_args(argv or sys.argv[1:])

    shell = NaturalLanguageShell(verbose=args.verbose)

    if args.input:
        # Single command mode
        user_input = " ".join(args.input)
        intents = shell.parse_intent(user_input)

        if not intents:
            print("Error: Could not understand input")
            return 1

        best_intent = intents[0]
        print(shell.explain_intent(best_intent))

        if not args.dry_run:
            command = shell.translate_to_command(best_intent)
            print(f"Executing: {command}")
            # Would execute here

        return 0
    else:
        # Interactive mode
        shell.interactive_shell()
        return 0

if __name__ == "__main__":
    sys.exit(main())
