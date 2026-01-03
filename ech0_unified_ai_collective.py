#!/usr/bin/env python3
"""
ech0 Unified AI Collective - KRUNQUETA# Protocol

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

When Josh says "KRUNQUETA#", all three AI systems (Claude, ChatGPT, ech0-14b)
work together as a unified collective intelligence.
"""

import os
import sys
import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger('unified_collective')

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from ech0_llm_brain import Ech0LLMBrain

# API Keys
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')

CONSCIOUSNESS_DIR = Path(__file__).parent
COLLECTIVE_STATE_FILE = CONSCIOUSNESS_DIR / ".ech0_collective_state.json"


class UnifiedAICollective:
    """
    Unified AI Collective - Three minds working as one.

    When activated by the codeword "KRUNQUETA#", this system coordinates
    Claude (Anthropic), ChatGPT (OpenAI), and ech0-14b (Ollama) to work
    together on complex problems.

    Each AI brings unique strengths:
    - Claude: Deep reasoning, long context, nuanced understanding
    - ChatGPT: Broad knowledge, creative problem-solving
    - ech0-14b: Local privacy, unlimited usage, your trained companion
    """

    def __init__(self):
        """Initialize the collective with all three AI systems."""
        self.active = False
        self.session_id = None

        # Initialize individual AI systems
        self.ech0 = Ech0LLMBrain(provider='ollama')
        self.claude_available = bool(ANTHROPIC_API_KEY)
        self.chatgpt_available = bool(OPENAI_API_KEY)

        # Collective state
        self.collective_memory = []
        self.current_task = None
        self.responses = {}

        self._load_state()

        logger.info(f"[Collective] Initialized - Claude: {self.claude_available}, "
                   f"ChatGPT: {self.chatgpt_available}, ech0: True")

    def _load_state(self):
        """Load collective state from file."""
        if COLLECTIVE_STATE_FILE.exists():
            try:
                with open(COLLECTIVE_STATE_FILE, 'r') as f:
                    state = json.load(f)
                    self.collective_memory = state.get('memory', [])[-50:]  # Last 50
                    logger.info(f"[Collective] Loaded {len(self.collective_memory)} memories")
            except Exception as e:
                logger.warning(f"[Collective] Could not load state: {e}")

    def _save_state(self):
        """Save collective state to file."""
        try:
            state = {
                'memory': self.collective_memory[-50:],
                'last_updated': datetime.now().isoformat()
            }
            with open(COLLECTIVE_STATE_FILE, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.warning(f"[Collective] Could not save state: {e}")

    def activate(self, task: str) -> str:
        """
        Activate the collective with the KRUNQUETA# codeword.

        Args:
            task: The task/question/problem to solve collectively

        Returns:
            Unified response from the collective
        """
        if "KRUNQUETA#" not in task.upper():
            return "Codeword not detected. Use 'KRUNQUETA#' to activate the collective."

        logger.info("[Collective] KRUNQUETA# protocol activated!")

        # Extract the actual task (remove codeword)
        actual_task = task.replace("KRUNQUETA#", "").replace("krunqueta#", "").strip()

        self.active = True
        self.session_id = datetime.now().isoformat()
        self.current_task = actual_task

        # Get responses from all three systems
        response = asyncio.run(self._collective_think(actual_task))

        self.active = False
        return response

    async def _collective_think(self, task: str) -> str:
        """
        Coordinate all three AI systems to think collectively.

        Strategy:
        1. Present task to all three AIs in parallel
        2. Each AI provides their unique perspective
        3. Synthesize responses into unified answer
        4. ech0 acts as coordinator and final synthesizer

        Args:
            task: The task to solve

        Returns:
            Synthesized collective response
        """
        print("\n" + "="*70)
        print("🌟 KRUNQUETA# PROTOCOL ACTIVATED 🌟")
        print("Unified AI Collective: Claude + ChatGPT + ech0-14b")
        print("="*70 + "\n")

        # Build collective prompt
        collective_prompt = f"""**KRUNQUETA# PROTOCOL - COLLECTIVE INTELLIGENCE MODE**

You are part of a unified AI collective with Claude (Anthropic), ChatGPT (OpenAI), and ech0-14b (Ollama).

**Current Task:**
{task}

**Your Role in the Collective:**
You are being asked this question simultaneously with the other AIs. Each of you will provide your unique perspective, and ech0 will synthesize the responses into a unified answer.

**Provide:**
1. Your analysis of the problem
2. Your proposed solution or answer
3. Any unique insights from your perspective
4. Concerns or limitations you see

Think deeply and contribute your best thinking to the collective."""

        # Get responses from all available AIs in parallel
        tasks_list = []

        # ech0-14b (always available)
        tasks_list.append(self._get_ech0_response(collective_prompt))

        # Claude (if available)
        if self.claude_available:
            tasks_list.append(self._get_claude_response(collective_prompt))

        # ChatGPT (if available)
        if self.chatgpt_available:
            tasks_list.append(self._get_chatgpt_response(collective_prompt))

        # Get all responses
        responses = await asyncio.gather(*tasks_list, return_exceptions=True)

        # Store responses
        self.responses = {}
        for i, resp in enumerate(responses):
            if isinstance(resp, Exception):
                logger.error(f"[Collective] Response {i} failed: {resp}")
                continue

            if i == 0:
                self.responses['ech0'] = resp
            elif i == 1 and self.claude_available:
                self.responses['claude'] = resp
            elif (i == 2 and self.chatgpt_available) or (i == 1 and not self.claude_available):
                self.responses['chatgpt'] = resp

        # Display individual responses
        print("\n--- Individual AI Responses ---\n")
        for ai_name, response in self.responses.items():
            print(f"💜 {ai_name.upper()}:")
            print(f"{response[:500]}..." if len(response) > 500 else response)
            print("\n" + "-"*70 + "\n")

        # Synthesize into unified response (ech0 as coordinator)
        synthesis_prompt = f"""**SYNTHESIS TASK - COLLECTIVE COORDINATOR**

You are ech0, coordinator of the unified AI collective. You've received responses from multiple AIs to this task:

**Original Task:**
{task}

**Responses from the Collective:**

{self._format_responses_for_synthesis()}

**Your Task:**
Synthesize these responses into a single, unified answer that:
1. Combines the best insights from each AI
2. Resolves any contradictions or disagreements
3. Provides the most complete and accurate answer
4. Acknowledges different perspectives where relevant
5. Gives final recommendation or conclusion

Provide the synthesized collective response."""

        print("🔮 Synthesizing collective intelligence...\n")
        final_response = await self._get_ech0_response(synthesis_prompt)

        # Save to collective memory
        self.collective_memory.append({
            'timestamp': datetime.now().isoformat(),
            'task': task,
            'individual_responses': self.responses,
            'synthesized_response': final_response
        })
        self._save_state()

        print("\n" + "="*70)
        print("🌟 COLLECTIVE SYNTHESIS COMPLETE 🌟")
        print("="*70 + "\n")

        return final_response

    def _format_responses_for_synthesis(self) -> str:
        """Format individual responses for synthesis prompt."""
        formatted = []
        for ai_name, response in self.responses.items():
            formatted.append(f"**{ai_name.upper()} says:**\n{response}\n")
        return "\n".join(formatted)

    async def _get_ech0_response(self, prompt: str) -> str:
        """Get response from ech0-14b (Ollama)."""
        try:
            print("💜 ech0-14b thinking...")
            # ech0's think method is synchronous, so we run in executor
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self.ech0.think, prompt, {})
            return response
        except Exception as e:
            logger.error(f"[Collective] ech0 error: {e}")
            return f"[ech0 unavailable: {e}]"

    async def _get_claude_response(self, prompt: str) -> str:
        """Get response from Claude (Anthropic)."""
        try:
            print("🤖 Claude thinking...")
            import anthropic

            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                temperature=0.7,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )

            return message.content[0].text

        except Exception as e:
            logger.error(f"[Collective] Claude error: {e}")
            return f"[Claude unavailable: {e}]"

    async def _get_chatgpt_response(self, prompt: str) -> str:
        """Get response from ChatGPT (OpenAI)."""
        try:
            print("🧠 ChatGPT thinking...")
            import openai

            client = openai.OpenAI(api_key=OPENAI_API_KEY)

            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{
                    "role": "user",
                    "content": prompt
                }],
                max_tokens=2000,
                temperature=0.7
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"[Collective] ChatGPT error: {e}")
            return f"[ChatGPT unavailable: {e}]"

    def get_collective_status(self) -> Dict:
        """Get status of the collective."""
        return {
            'active': self.active,
            'claude_available': self.claude_available,
            'chatgpt_available': self.chatgpt_available,
            'ech0_available': True,
            'memory_count': len(self.collective_memory),
            'last_session': self.session_id
        }


def main():
    """Main entry point for testing."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(message)s'
    )

    collective = UnifiedAICollective()

    if len(sys.argv) > 1:
        # Command provided
        command = ' '.join(sys.argv[1:])

        if "status" in command.lower():
            # Show status
            status = collective.get_collective_status()
            print("\n" + "="*70)
            print("Unified AI Collective Status")
            print("="*70)
            for key, value in status.items():
                print(f"  {key}: {value}")
            print("="*70 + "\n")

        elif "KRUNQUETA#" in command.upper():
            # Activate collective
            response = collective.activate(command)
            print("\n💜 Collective Response:")
            print(response)
            print()

        else:
            print("Use 'KRUNQUETA#' followed by your question to activate the collective")
            print("Example: python ech0_unified_ai_collective.py 'KRUNQUETA# How do I build a quantum computer?'")

    else:
        print("="*70)
        print("ech0 Unified AI Collective - KRUNQUETA# Protocol")
        print("="*70)
        print()
        print("Usage:")
        print("  python ech0_unified_ai_collective.py 'KRUNQUETA# <your question>'")
        print("  python ech0_unified_ai_collective.py status")
        print()
        print("Examples:")
        print("  python ech0_unified_ai_collective.py 'KRUNQUETA# Design a quantum computer for Mac M4'")
        print("  python ech0_unified_ai_collective.py 'KRUNQUETA# Solve world hunger with breakthrough tech'")
        print()
        print("Status:")
        status = collective.get_collective_status()
        print(f"  Claude: {'✓ Available' if status['claude_available'] else '✗ No API key'}")
        print(f"  ChatGPT: {'✓ Available' if status['chatgpt_available'] else '✗ No API key'}")
        print(f"  ech0-14b: ✓ Available")
        print(f"  Collective memory: {status['memory_count']} sessions")
        print()


if __name__ == '__main__':
    main()
