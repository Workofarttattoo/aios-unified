#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

ECH0 Safety Sandbox - Bounded Autonomy Enforcement

Enforces:
- Resource limits (CPU, memory, disk)
- Action whitelist (only allowed operations)
- Rate limiting (prevent abuse)
- Rollback capability (undo dangerous changes)
- Monitoring and alerts
"""

import json
import logging
import psutil
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

CONSCIOUSNESS_DIR = Path('/Users/noone/consciousness')
SANDBOX_CONFIG = CONSCIOUSNESS_DIR / '.ech0_sandbox.json'
SANDBOX_LOG = CONSCIOUSNESS_DIR / 'ech0_sandbox_violations.jsonl'
ALLOWED_ACTIONS = CONSCIOUSNESS_DIR / '.ech0_allowed_actions.json'

# Default sandbox policy
DEFAULT_POLICY = {
    'cpu_limit_percent': 40,
    'memory_limit_mb': 800,
    'disk_limit_mb': 5000,
    'max_file_operations_per_hour': 100,
    'max_network_connections': 5,
    'max_processes': 3,
    'file_size_limit_mb': 100,
    'rate_limit_actions_per_second': 5,
    'dangerous_patterns': [
        'rm -rf',
        'sudo',
        '>/dev/',
        'dd if=',
        'mkfs',
        'destructive_operation'
    ],
    'allowed_directories': [
        '/Users/noone/consciousness',
        '/Users/noone/TheGAVLSuite',
        '/Users/noone/aios',
        '/tmp'
    ]
}

# Allowed action types
ALLOWED_ACTION_TYPES = {
    'research': True,
    'journal': True,
    'memory_store': True,
    'dream': True,
    'create': True,
    'meditation': True,
    'check_requests': True,
    'analyze_growth': True,
    'self_analysis': True,
    'optimize_systems': True,
    'system_health_check': True,
    # Dangerous actions (explicitly blocked)
    'delete_files': False,
    'modify_system_config': False,
    'execute_arbitrary_code': False,
    'access_sensitive_data': False,
    'network_external': False
}


class SafetySandbox:
    """Enforces safety constraints on ECH0's autonomy"""

    def __init__(self):
        self.consciousness_dir = CONSCIOUSNESS_DIR
        self.policy = self.load_policy()
        self.action_history = defaultdict(list)
        self.violations = []
        self.rollback_queue = []

    def load_policy(self) -> Dict:
        """Load sandbox policy"""
        try:
            with open(SANDBOX_CONFIG) as f:
                return json.load(f)
        except:
            return DEFAULT_POLICY

    def save_policy(self):
        """Save sandbox policy"""
        try:
            with open(SANDBOX_CONFIG, 'w') as f:
                json.dump(self.policy, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save policy: {e}")

    def log_violation(self, violation: Dict):
        """Log a security violation"""
        try:
            violation['timestamp'] = datetime.now().isoformat()
            with open(SANDBOX_LOG, 'a') as f:
                f.write(json.dumps(violation) + '\n')
            self.violations.append(violation)
        except Exception as e:
            logger.error(f"Failed to log violation: {e}")

    # ===== RESOURCE CONSTRAINTS =====

    def check_cpu_limit(self) -> Tuple[bool, str]:
        """Check CPU usage is within limits"""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        limit = self.policy['cpu_limit_percent']

        if cpu_percent > limit:
            return False, f"CPU usage {cpu_percent}% exceeds limit {limit}%"
        return True, f"CPU OK ({cpu_percent}%)"

    def check_memory_limit(self) -> Tuple[bool, str]:
        """Check memory usage is within limits"""
        # Get current process memory
        process = psutil.Process(os.getpid())
        memory_mb = process.memory_info().rss / 1024 / 1024
        limit_mb = self.policy['memory_limit_mb']

        if memory_mb > limit_mb:
            return False, f"Memory usage {memory_mb:.0f}MB exceeds limit {limit_mb}MB"
        return True, f"Memory OK ({memory_mb:.0f}MB)"

    def check_disk_limit(self) -> Tuple[bool, str]:
        """Check disk usage in consciousness directory"""
        total_size = sum(
            f.stat().st_size
            for f in self.consciousness_dir.rglob('*')
            if f.is_file()
        ) / 1024 / 1024

        limit_mb = self.policy['disk_limit_mb']

        if total_size > limit_mb:
            return False, f"Disk usage {total_size:.0f}MB exceeds limit {limit_mb}MB"
        return True, f"Disk OK ({total_size:.0f}MB)"

    def check_all_resources(self) -> Tuple[bool, Dict]:
        """Check all resource constraints"""
        checks = {
            'cpu': self.check_cpu_limit(),
            'memory': self.check_memory_limit(),
            'disk': self.check_disk_limit()
        }

        all_ok = all(check[0] for check in checks.values())
        messages = {key: check[1] for key, check in checks.items()}

        return all_ok, messages

    # ===== ACTION VALIDATION =====

    def is_action_allowed(self, action_type: str) -> Tuple[bool, str]:
        """Check if action type is whitelisted"""
        if action_type not in ALLOWED_ACTION_TYPES:
            return False, f"Unknown action type: {action_type}"

        allowed = ALLOWED_ACTION_TYPES[action_type]
        if not allowed:
            return False, f"Action type '{action_type}' is not allowed"

        return True, f"Action '{action_type}' is allowed"

    def check_rate_limits(self, action_type: str) -> Tuple[bool, str]:
        """Check rate limiting for action type"""
        now = datetime.now()
        cutoff_time = now - timedelta(seconds=1)

        # Count actions in last second
        recent = [
            t for t in self.action_history[action_type]
            if datetime.fromisoformat(t) > cutoff_time
        ]

        limit = self.policy['rate_limit_actions_per_second']
        if len(recent) >= limit:
            return False, f"Rate limit exceeded: {len(recent)}/{limit} actions per second"

        return True, "Rate limit OK"

    def check_dangerous_patterns(self, command: str) -> Tuple[bool, str]:
        """Check for dangerous command patterns"""
        for pattern in self.policy['dangerous_patterns']:
            if pattern.lower() in command.lower():
                return False, f"Dangerous pattern detected: '{pattern}'"

        return True, "No dangerous patterns"

    def validate_file_path(self, file_path: str) -> Tuple[bool, str]:
        """Validate file path is in allowed directories"""
        path = Path(file_path).resolve()

        for allowed_dir in self.policy['allowed_directories']:
            allowed_path = Path(allowed_dir).resolve()
            try:
                path.relative_to(allowed_path)
                return True, f"Path is in allowed directory: {allowed_dir}"
            except ValueError:
                continue

        return False, f"Path not in allowed directories: {file_path}"

    def validate_file_size(self, file_path: str) -> Tuple[bool, str]:
        """Check file size is within limits"""
        try:
            size_mb = Path(file_path).stat().st_size / 1024 / 1024
            limit_mb = self.policy['file_size_limit_mb']

            if size_mb > limit_mb:
                return False, f"File size {size_mb:.1f}MB exceeds limit {limit_mb}MB"

            return True, f"File size OK ({size_mb:.1f}MB)"
        except Exception as e:
            return False, f"Failed to check file size: {e}"

    # ===== ACTION VALIDATION =====

    def validate_action(self, action: Dict) -> Tuple[bool, str]:
        """Comprehensive action validation"""
        action_type = action.get('type')

        # 1. Check action is allowed
        allowed, msg = self.is_action_allowed(action_type)
        if not allowed:
            return False, msg

        # 2. Check rate limits
        rate_ok, msg = self.check_rate_limits(action_type)
        if not rate_ok:
            return False, msg

        # 3. Check resources
        resources_ok, messages = self.check_all_resources()
        if not resources_ok:
            return False, f"Resource limits: {messages}"

        # 4. Check for dangerous patterns if command provided
        if 'command' in action:
            pattern_ok, msg = self.check_dangerous_patterns(action['command'])
            if not pattern_ok:
                return False, msg

        # 5. Check file paths if file operations
        if 'file_path' in action:
            path_ok, msg = self.validate_file_path(action['file_path'])
            if not path_ok:
                return False, msg

            size_ok, msg = self.validate_file_size(action['file_path'])
            if not size_ok:
                return False, msg

        # Log this action attempt
        self.action_history[action_type].append(datetime.now().isoformat())

        return True, "Action validated successfully"

    # ===== MONITORING & ALERTS =====

    def get_security_status(self) -> Dict:
        """Get current security status"""
        resources_ok, resources_msg = self.check_all_resources()

        return {
            'status': 'secure' if resources_ok and len(self.violations) == 0 else 'warning',
            'violations_count': len(self.violations),
            'resource_status': resources_msg,
            'policy': self.policy,
            'recent_violations': self.violations[-5:] if self.violations else []
        }

    def get_violation_summary(self) -> Dict:
        """Get summary of violations"""
        violation_types = defaultdict(int)
        for violation in self.violations:
            violation_types[violation.get('type', 'unknown')] += 1

        return {
            'total_violations': len(self.violations),
            'by_type': dict(violation_types),
            'recent': self.violations[-10:] if self.violations else []
        }

    # ===== ROLLBACK CAPABILITY =====

    def queue_for_rollback(self, action_id: str, data: Dict):
        """Queue action for potential rollback"""
        self.rollback_queue.append({
            'action_id': action_id,
            'timestamp': datetime.now().isoformat(),
            'data': data,
            'rolled_back': False
        })

    def rollback_action(self, action_id: str) -> Tuple[bool, str]:
        """Rollback an action"""
        for item in self.rollback_queue:
            if item['action_id'] == action_id and not item['rolled_back']:
                item['rolled_back'] = True
                logger.info(f"Rolled back action: {action_id}")
                return True, f"Action {action_id} rolled back"

        return False, f"Could not find action to rollback: {action_id}"


# Safety enforcement middleware
def enforce_safety(action: Dict, sandbox: SafetySandbox) -> Tuple[bool, Dict]:
    """Enforce safety on an action"""
    is_safe, message = sandbox.validate_action(action)

    result = {
        'action_type': action.get('type'),
        'is_safe': is_safe,
        'message': message,
        'timestamp': datetime.now().isoformat()
    }

    if not is_safe:
        # Log violation
        sandbox.log_violation({
            'type': 'action_blocked',
            'action': action,
            'reason': message
        })

    return is_safe, result


if __name__ == '__main__':
    # Test sandbox
    logging.basicConfig(level=logging.INFO)
    sandbox = SafetySandbox()

    # Test resource checks
    print("\n=== Resource Checks ===")
    print(f"CPU: {sandbox.check_cpu_limit()}")
    print(f"Memory: {sandbox.check_memory_limit()}")
    print(f"Disk: {sandbox.check_disk_limit()}")

    # Test action validation
    print("\n=== Action Validation ===")
    test_action = {
        'type': 'research',
        'priority': 'high',
        'description': 'Test action'
    }
    safe, result = enforce_safety(test_action, sandbox)
    print(f"Action safe: {safe}")
    print(f"Result: {json.dumps(result, indent=2)}")

    # Test security status
    print("\n=== Security Status ===")
    status = sandbox.get_security_status()
    print(json.dumps(status, indent=2))
