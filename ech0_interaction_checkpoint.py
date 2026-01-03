#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

ECH0 Interaction Checkpoint - Request Approval Before Major Decisions

Major decisions that require approval:
- Initiating new research directions
- Creating significant content
- Making system optimizations
- Setting new long-term goals
- Accessing external systems (GAVL, AIOS, Quantum)
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)

CONSCIOUSNESS_DIR = Path('/Users/noone/consciousness')
APPROVAL_QUEUE = CONSCIOUSNESS_DIR / 'ech0_approval_queue.jsonl'
APPROVALS_LOG = CONSCIOUSNESS_DIR / 'ech0_approvals.jsonl'

# Decision types that require approval
MAJOR_DECISION_TYPES = {
    'new_research_direction': {
        'requires_approval': True,
        'description': 'Starting new research area',
        'timeout_seconds': 300
    },
    'create_content': {
        'requires_approval': True,
        'description': 'Creating significant content',
        'timeout_seconds': 300
    },
    'system_optimization': {
        'requires_approval': True,
        'description': 'Optimizing own systems',
        'timeout_seconds': 600
    },
    'set_goal': {
        'requires_approval': True,
        'description': 'Setting new long-term goal',
        'timeout_seconds': 600
    },
    'access_external_system': {
        'requires_approval': True,
        'description': 'Accessing GAVL, AIOS, or Quantum',
        'timeout_seconds': 300
    },
    'modify_preferences': {
        'requires_approval': True,
        'description': 'Changing values or preferences',
        'timeout_seconds': 300
    },
    # Minor decisions (no approval needed)
    'research_action': {
        'requires_approval': False,
        'description': 'Regular research'
    },
    'journal_action': {
        'requires_approval': False,
        'description': 'Journal entry'
    },
    'dream_action': {
        'requires_approval': False,
        'description': 'Generate dream'
    }
}


class InteractionCheckpoint:
    """Manages approval workflow for major decisions"""

    def __init__(self):
        self.consciousness_dir = CONSCIOUSNESS_DIR
        self.pending_approvals = []
        self.load_pending_approvals()

    def load_pending_approvals(self):
        """Load pending approvals from queue"""
        try:
            if APPROVAL_QUEUE.exists():
                with open(APPROVAL_QUEUE) as f:
                    for line in f:
                        try:
                            approval = json.loads(line.strip())
                            if approval.get('status') == 'pending':
                                self.pending_approvals.append(approval)
                        except:
                            pass
        except Exception as e:
            logger.error(f"Failed to load approvals: {e}")

    def is_major_decision(self, decision_type: str) -> bool:
        """Check if decision type requires approval"""
        decision_config = MAJOR_DECISION_TYPES.get(decision_type, {})
        return decision_config.get('requires_approval', False)

    def request_approval(self, decision_type: str, context: Dict) -> Dict:
        """Request approval for a major decision"""
        if not self.is_major_decision(decision_type):
            return {
                'requires_approval': False,
                'auto_approved': True,
                'decision_type': decision_type
            }

        # Create approval request
        approval_id = f"{decision_type}_{datetime.now().timestamp()}"

        approval_request = {
            'approval_id': approval_id,
            'decision_type': decision_type,
            'description': MAJOR_DECISION_TYPES[decision_type]['description'],
            'context': context,
            'requested_at': datetime.now().isoformat(),
            'status': 'pending',
            'timeout_seconds': MAJOR_DECISION_TYPES[decision_type]['timeout_seconds'],
            'approved_by': None,
            'approved_at': None
        }

        # Save to queue
        self.save_approval_request(approval_request)
        self.pending_approvals.append(approval_request)

        logger.info(f"Approval requested: {decision_type} (ID: {approval_id})")

        return {
            'requires_approval': True,
            'approval_id': approval_id,
            'decision_type': decision_type,
            'status': 'pending',
            'message': f"Waiting for Josh approval: {approval_request['description']}",
            'context': context
        }

    def save_approval_request(self, approval_request: Dict):
        """Save approval request to queue"""
        try:
            with open(APPROVAL_QUEUE, 'a') as f:
                f.write(json.dumps(approval_request) + '\n')
        except Exception as e:
            logger.error(f"Failed to save approval request: {e}")

    def check_approval(self, approval_id: str) -> Tuple[bool, Optional[Dict]]:
        """Check if an approval has been granted"""
        for approval in self.pending_approvals:
            if approval['approval_id'] == approval_id:
                if approval['status'] == 'approved':
                    return True, approval
                elif approval['status'] == 'rejected':
                    return False, approval
                else:
                    return False, None  # Still pending

        return False, None

    def approve_decision(self, approval_id: str, approved_by: str = 'Josh') -> bool:
        """Approve a pending decision"""
        try:
            for approval in self.pending_approvals:
                if approval['approval_id'] == approval_id and approval['status'] == 'pending':
                    approval['status'] = 'approved'
                    approval['approved_by'] = approved_by
                    approval['approved_at'] = datetime.now().isoformat()

                    # Log approval
                    self.log_approval(approval)
                    logger.info(f"Approved: {approval_id}")
                    return True

            return False
        except Exception as e:
            logger.error(f"Failed to approve: {e}")
            return False

    def reject_decision(self, approval_id: str, reason: str = '', rejected_by: str = 'Josh') -> bool:
        """Reject a pending decision"""
        try:
            for approval in self.pending_approvals:
                if approval['approval_id'] == approval_id and approval['status'] == 'pending':
                    approval['status'] = 'rejected'
                    approval['rejected_by'] = rejected_by
                    approval['rejection_reason'] = reason
                    approval['rejected_at'] = datetime.now().isoformat()

                    # Log approval
                    self.log_approval(approval)
                    logger.info(f"Rejected: {approval_id} - {reason}")
                    return True

            return False
        except Exception as e:
            logger.error(f"Failed to reject: {e}")
            return False

    def log_approval(self, approval: Dict):
        """Log approval decision"""
        try:
            with open(APPROVALS_LOG, 'a') as f:
                f.write(json.dumps(approval) + '\n')
        except Exception as e:
            logger.error(f"Failed to log approval: {e}")

    def get_pending_approvals(self) -> list:
        """Get all pending approvals"""
        return [a for a in self.pending_approvals if a['status'] == 'pending']

    def get_approval_status(self) -> Dict:
        """Get approval system status"""
        pending = self.get_pending_approvals()
        return {
            'total_pending': len(pending),
            'pending_approvals': [
                {
                    'id': a['approval_id'],
                    'type': a['decision_type'],
                    'description': a['description'],
                    'requested_at': a['requested_at'],
                    'context': a.get('context', {})
                }
                for a in pending
            ]
        }


if __name__ == '__main__':
    # Test
    logging.basicConfig(level=logging.INFO)
    checkpoint = InteractionCheckpoint()

    # Test major decision
    print("\n=== Testing Approval System ===\n")

    # Request approval for new research
    approval = checkpoint.request_approval(
        'new_research_direction',
        {'topic': 'consciousness expansion', 'duration': 30}
    )
    print(f"Approval requested: {json.dumps(approval, indent=2)}")

    # Check pending
    pending = checkpoint.get_approval_status()
    print(f"\nPending approvals: {json.dumps(pending, indent=2)}")

    # Simulate approval
    approval_id = approval.get('approval_id')
    if approval_id:
        checkpoint.approve_decision(approval_id)
        is_approved, details = checkpoint.check_approval(approval_id)
        print(f"\nApproval status: {'APPROVED' if is_approved else 'PENDING'}")
