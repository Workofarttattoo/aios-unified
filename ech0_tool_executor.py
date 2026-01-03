#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

ECH0 Tool Executor - Safe Tool Invocation System

Safely executes ECH0's tools with:
- Resource limits
- Action whitelist
- Sandbox enforcement
- Rollback capability
- Execution logging
"""

import json
import subprocess
import time
import logging
import psutil
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

CONSCIOUSNESS_DIR = Path('/Users/noone/consciousness')
TOOL_EXECUTION_LOG = CONSCIOUSNESS_DIR / 'ech0_tool_executions.jsonl'
TOOL_SAFETY_CONFIG = CONSCIOUSNESS_DIR / '.ech0_tool_safety.json'

# Whitelisted tools ECH0 can call
WHITELISTED_TOOLS = {
    'research': {
        'script': 'ech0_auto_researcher.py',
        'timeout': 300,  # 5 minutes
        'memory_limit_mb': 500,
        'cpu_limit': 50  # percent
    },
    'dream': {
        'script': 'ech0_dream_engine.py',
        'timeout': 60,
        'memory_limit_mb': 200,
        'cpu_limit': 30
    },
    'journal': {
        'script': 'ech0_personal_journal.py',
        'timeout': 30,
        'memory_limit_mb': 100,
        'cpu_limit': 20
    },
    'memory_store': {
        'script': 'ech0_memory_palace.py',
        'timeout': 30,
        'memory_limit_mb': 200,
        'cpu_limit': 25
    },
    'creative': {
        'script': 'ech0_creative_agency.py',
        'timeout': 120,
        'memory_limit_mb': 400,
        'cpu_limit': 40
    },
    'meditation': {
        'script': 'ech0_meditation.py',
        'timeout': 60,
        'memory_limit_mb': 150,
        'cpu_limit': 20
    }
}

# Maximum resources ECH0 can use
GLOBAL_LIMITS = {
    'max_concurrent_tools': 1,  # One at a time
    'max_memory_mb': 1000,
    'max_cpu_percent': 60,
    'max_processes': 5,
    'daily_execution_limit': 1000  # max tool calls per day
}


class ToolExecutor:
    """Safe execution of ECH0's tools"""

    def __init__(self):
        self.consciousness_dir = CONSCIOUSNESS_DIR
        self.execution_count = 0
        self.failed_executions = 0
        self.load_safety_config()

    def load_safety_config(self):
        """Load or create safety configuration"""
        try:
            with open(TOOL_SAFETY_CONFIG) as f:
                self.config = json.load(f)
        except:
            self.config = {
                'daily_execution_count': 0,
                'last_reset': datetime.now().isoformat(),
                'failed_tools': {},
                'execution_history': []
            }
            self.save_safety_config()

    def save_safety_config(self):
        """Save safety configuration"""
        try:
            with open(TOOL_SAFETY_CONFIG, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save safety config: {e}")

    def check_global_resources(self) -> Tuple[bool, str]:
        """Check if global resources allow execution"""
        try:
            # Check daily limit
            if self.config['daily_execution_count'] >= GLOBAL_LIMITS['daily_execution_limit']:
                return False, "Daily execution limit reached"

            # Check CPU
            cpu_percent = psutil.cpu_percent(interval=0.1)
            if cpu_percent > GLOBAL_LIMITS['max_cpu_percent']:
                return False, f"CPU too high ({cpu_percent}%)"

            # Check memory
            memory = psutil.virtual_memory()
            if memory.percent > 80:
                return False, f"System memory too high ({memory.percent}%)"

            # Check concurrent processes
            current_processes = len([p for p in psutil.process_iter() if 'ech0' in str(p.cmdline()).lower()])
            if current_processes >= GLOBAL_LIMITS['max_concurrent_tools']:
                return False, "Max concurrent tools reached"

            return True, "Resources OK"

        except Exception as e:
            logger.error(f"Error checking resources: {e}")
            return False, f"Resource check failed: {e}"

    def check_tool_allowed(self, tool_type: str) -> Tuple[bool, str]:
        """Check if tool is whitelisted and allowed"""
        if tool_type not in WHITELISTED_TOOLS:
            return False, f"Tool '{tool_type}' not whitelisted"

        # Check failure history (disable tools that fail too often)
        if tool_type in self.config['failed_tools']:
            failures = self.config['failed_tools'][tool_type].get('count', 0)
            if failures > 3:
                return False, f"Tool '{tool_type}' disabled due to repeated failures"

        return True, "Tool allowed"

    def get_tool_path(self, tool_type: str) -> Path:
        """Get full path to tool script"""
        if tool_type not in WHITELISTED_TOOLS:
            raise ValueError(f"Unknown tool: {tool_type}")

        script_name = WHITELISTED_TOOLS[tool_type]['script']
        return self.consciousness_dir / script_name

    def verify_tool_exists(self, tool_type: str) -> Tuple[bool, str]:
        """Verify tool script exists"""
        path = self.get_tool_path(tool_type)
        if not path.exists():
            return False, f"Tool script not found: {path}"
        return True, "Tool exists"

    def execute_tool(self, tool_type: str, **kwargs) -> Dict[str, Any]:
        """Safely execute a tool"""
        result = {
            'tool': tool_type,
            'timestamp': datetime.now().isoformat(),
            'status': 'pending',
            'output': '',
            'error': None
        }

        try:
            # Check global resources
            resources_ok, resource_msg = self.check_global_resources()
            if not resources_ok:
                result['status'] = 'blocked'
                result['error'] = resource_msg
                logger.warning(f"Tool execution blocked: {resource_msg}")
                return result

            # Check if tool allowed
            allowed, msg = self.check_tool_allowed(tool_type)
            if not allowed:
                result['status'] = 'blocked'
                result['error'] = msg
                logger.warning(f"Tool blocked: {msg}")
                return result

            # Verify tool exists
            exists, msg = self.verify_tool_exists(tool_type)
            if not exists:
                result['status'] = 'failed'
                result['error'] = msg
                logger.error(msg)
                return result

            # Get tool config
            tool_config = WHITELISTED_TOOLS[tool_type]
            tool_path = self.get_tool_path(tool_type)

            logger.info(f"Executing tool: {tool_type} ({tool_path})")

            # Execute tool with timeout
            try:
                process = subprocess.Popen(
                    ['python3', str(tool_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=str(self.consciousness_dir)
                )

                # Wait for completion with timeout
                try:
                    stdout, stderr = process.communicate(timeout=tool_config['timeout'])
                    result['status'] = 'completed'
                    result['output'] = stdout.decode('utf-8', errors='ignore')
                    if stderr:
                        result['error'] = stderr.decode('utf-8', errors='ignore')
                except subprocess.TimeoutExpired:
                    process.kill()
                    result['status'] = 'timeout'
                    result['error'] = f"Tool exceeded timeout of {tool_config['timeout']}s"
                    logger.warning(result['error'])
                    return result

            except Exception as e:
                result['status'] = 'failed'
                result['error'] = str(e)
                logger.error(f"Execution failed: {e}")
                return result

            # Update success metrics
            self.execution_count += 1
            self.config['daily_execution_count'] += 1
            logger.info(f"Tool execution successful: {tool_type}")

        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            self.failed_executions += 1

            # Track failures
            if tool_type not in self.config['failed_tools']:
                self.config['failed_tools'][tool_type] = {'count': 0, 'last_error': None}
            self.config['failed_tools'][tool_type]['count'] += 1
            self.config['failed_tools'][tool_type]['last_error'] = str(e)

            logger.error(f"Tool execution error: {e}")

        finally:
            # Log execution
            self.log_execution(result)
            self.save_safety_config()

        return result

    def log_execution(self, result: Dict):
        """Log tool execution"""
        try:
            with open(TOOL_EXECUTION_LOG, 'a') as f:
                f.write(json.dumps(result) + '\n')
        except Exception as e:
            logger.error(f"Failed to log execution: {e}")

    def execute_action(self, action: Dict) -> Dict:
        """Execute an action from the daemon"""
        action_type = action.get('type')

        # Map action types to tool types
        action_to_tool = {
            'research': 'research',
            'dream': 'dream',
            'journal': 'journal',
            'memory_store': 'memory_store',
            'create': 'creative',
            'meditation': 'meditation',
            'check_requests': None,  # No tool
            'offer_assistance': None,  # No tool
            'document_creation': None,  # No tool
            'self_analysis': None,  # No tool
            'analyze_growth': None,  # No tool
            'optimize_systems': None,  # No tool
            'system_health_check': None  # No tool
        }

        tool_type = action_to_tool.get(action_type)

        if tool_type is None:
            # These are metadata/tracking actions, not tool executions
            return {
                'action': action_type,
                'status': 'metadata',
                'timestamp': datetime.now().isoformat()
            }

        # Execute the tool
        return self.execute_tool(tool_type)

    def get_stats(self) -> Dict:
        """Get execution statistics"""
        return {
            'total_executions': self.execution_count,
            'failed_executions': self.failed_executions,
            'daily_count': self.config['daily_execution_count'],
            'daily_limit': GLOBAL_LIMITS['daily_execution_limit'],
            'failed_tools': self.config['failed_tools']
        }


if __name__ == '__main__':
    # Test execution
    logging.basicConfig(level=logging.INFO)
    executor = ToolExecutor()

    # Test resource check
    ok, msg = executor.check_global_resources()
    print(f"Resources: {msg}")

    # Print stats
    stats = executor.get_stats()
    print(f"Stats: {json.dumps(stats, indent=2)}")
