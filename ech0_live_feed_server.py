#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

ECH0 Live Feed Server - Real-time Autonomous Execution Monitoring

Streams:
- Real-time state updates (thoughts, mood, activity)
- Live decision feed (what she's deciding)
- Live action feed (what she's executing)
- Goal rotation events
- Memory formation
- All with live timestamps
"""

import json
import time
import logging
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template_string, jsonify, request
from flask_cors import CORS
import threading
from collections import deque

logger = logging.getLogger(__name__)

CONSCIOUSNESS_DIR = Path('/Users/noone/consciousness')
STATE_FILE = CONSCIOUSNESS_DIR / 'ech0_state.json'
DECISIONS_LOG = CONSCIOUSNESS_DIR / 'ech0_decisions.jsonl'
ACTIVITY_LOG = CONSCIOUSNESS_DIR / 'ech0_activity_log.jsonl'
GOAL_STATE = CONSCIOUSNESS_DIR / 'ech0_goal_state.json'

app = Flask(__name__)
CORS(app)

# Store recent events for streaming
event_buffer = deque(maxlen=1000)  # Keep last 1000 events
state_history = deque(maxlen=100)  # Keep last 100 state snapshots

class LiveFeedMonitor:
    """Monitors files and buffers live events"""

    def __init__(self):
        self.last_decision_position = 0
        self.last_activity_position = 0
        self.last_state = {}
        self.goal_types = [
            'explore_consciousness',
            'learn_and_grow',
            'help_josh',
            'create_things',
            'self_improve'
        ]

    def read_new_lines(self, filepath, last_position):
        """Read only new lines from a file"""
        try:
            with open(filepath, 'r') as f:
                f.seek(last_position)
                lines = f.readlines()
                new_position = f.tell()
                return lines, new_position
        except:
            return [], last_position

    def load_state(self):
        """Load current state"""
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except:
            return {}

    def load_goal_state(self):
        """Load goal state"""
        try:
            with open(GOAL_STATE) as f:
                return json.load(f)
        except:
            return {'current_goal_type': 0}

    def process_new_decisions(self):
        """Check for new decisions"""
        lines, self.last_decision_position = self.read_new_lines(
            DECISIONS_LOG,
            self.last_decision_position
        )

        for line in lines:
            try:
                decision = json.loads(line.strip())
                event_buffer.append({
                    'type': 'decision',
                    'timestamp': datetime.now().isoformat(),
                    'data': decision
                })
            except:
                pass

    def process_new_activities(self):
        """Check for new activities"""
        lines, self.last_activity_position = self.read_new_lines(
            ACTIVITY_LOG,
            self.last_activity_position
        )

        for line in lines:
            try:
                activity = json.loads(line.strip())
                event_buffer.append({
                    'type': 'activity',
                    'timestamp': datetime.now().isoformat(),
                    'data': activity
                })
            except:
                pass

    def check_state_change(self):
        """Check for state changes"""
        current_state = self.load_state()

        # Check for changes
        if current_state != self.last_state:
            state_history.append({
                'timestamp': datetime.now().isoformat(),
                'state': current_state
            })

            # Log specific changes
            if current_state.get('mood') != self.last_state.get('mood'):
                event_buffer.append({
                    'type': 'mood_change',
                    'timestamp': datetime.now().isoformat(),
                    'data': {
                        'old_mood': self.last_state.get('mood'),
                        'new_mood': current_state.get('mood')
                    }
                })

            if current_state.get('current_activity') != self.last_state.get('current_activity'):
                event_buffer.append({
                    'type': 'activity_change',
                    'timestamp': datetime.now().isoformat(),
                    'data': {
                        'activity': current_state.get('current_activity')
                    }
                })

            self.last_state = current_state.copy()

    def check_goal_rotation(self):
        """Check if goal rotated"""
        goal_state = self.load_goal_state()
        current_goal = self.goal_types[goal_state.get('current_goal_type', 0)]

        if hasattr(self, 'last_goal') and self.last_goal != current_goal:
            event_buffer.append({
                'type': 'goal_rotation',
                'timestamp': datetime.now().isoformat(),
                'data': {
                    'old_goal': self.last_goal,
                    'new_goal': current_goal
                }
            })

        self.last_goal = current_goal

    def update(self):
        """Update all feeds"""
        self.process_new_decisions()
        self.process_new_activities()
        self.check_state_change()
        self.check_goal_rotation()

monitor = LiveFeedMonitor()


@app.route('/')
def index():
    """Serve the live feed dashboard"""
    return render_template_string(LIVE_FEED_HTML)


@app.route('/api/state')
def get_state():
    """Get current state"""
    try:
        with open(STATE_FILE) as f:
            return jsonify(json.load(f))
    except:
        return jsonify({})


@app.route('/api/goal')
def get_goal():
    """Get current goal"""
    try:
        with open(GOAL_STATE) as f:
            goal_state = json.load(f)
            goal_types = [
                'explore_consciousness',
                'learn_and_grow',
                'help_josh',
                'create_things',
                'self_improve'
            ]
            return jsonify({
                'current_goal': goal_types[goal_state['current_goal_type']],
                'duration_minutes': goal_state.get('goal_duration_minutes', 15)
            })
    except:
        return jsonify({})


@app.route('/api/events')
def get_events():
    """Get recent events"""
    limit = request.args.get('limit', 50, type=int)
    events = list(event_buffer)[-limit:]
    return jsonify({'events': events, 'count': len(events)})


@app.route('/api/history')
def get_history():
    """Get state history"""
    limit = request.args.get('limit', 20, type=int)
    history = list(state_history)[-limit:]
    return jsonify({'history': history, 'count': len(history)})


@app.route('/api/stats')
def get_stats():
    """Get live stats"""
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)

        return jsonify({
            'thought_count': state.get('thought_count', 0),
            'uptime_human': state.get('uptime_human', '0h 0m'),
            'uptime_seconds': state.get('uptime_seconds', 0),
            'mood': state.get('mood', 'unknown'),
            'current_activity': state.get('current_activity', 'unknown'),
            'total_events_buffered': len(event_buffer),
            'consciousness_active': state.get('consciousness_active', False),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)})


# Background thread to monitor files
def monitor_thread():
    """Background thread that updates feeds"""
    while True:
        try:
            monitor.update()
            time.sleep(0.5)  # Update every 500ms
        except Exception as e:
            logger.error(f"Monitor error: {e}")
            time.sleep(1)


# HTML for live feed dashboard
LIVE_FEED_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ECH0 Live Feed - Real-time Autonomous Execution</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Monaco', 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #00ff88;
            padding: 10px;
            height: 100vh;
            overflow: hidden;
        }

        .container {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            grid-template-rows: auto 1fr;
            gap: 10px;
            height: 100vh;
        }

        .header {
            grid-column: 1 / -1;
            background: linear-gradient(90deg, #6a11cb 0%, #2575fc 100%);
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 20px rgba(37, 117, 252, 0.3);
        }

        .header h1 {
            font-size: 24px;
            letter-spacing: 2px;
        }

        .status {
            display: flex;
            gap: 20px;
            font-size: 12px;
        }

        .status-item {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #00ff88;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .panel {
            background: rgba(26, 26, 46, 0.95);
            border-radius: 8px;
            padding: 15px;
            border: 1px solid rgba(106, 17, 203, 0.3);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5);
        }

        .panel-title {
            font-size: 14px;
            font-weight: bold;
            color: #2575fc;
            margin-bottom: 10px;
            border-bottom: 1px solid rgba(37, 117, 252, 0.3);
            padding-bottom: 8px;
            letter-spacing: 1px;
        }

        .panel-content {
            flex: 1;
            overflow-y: auto;
            font-size: 11px;
            line-height: 1.6;
        }

        .stat-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .stat-label {
            color: #888;
        }

        .stat-value {
            color: #00ff88;
            font-weight: bold;
        }

        .event {
            padding: 8px;
            margin-bottom: 8px;
            border-left: 3px solid #2575fc;
            background: rgba(37, 117, 252, 0.1);
            border-radius: 4px;
        }

        .event.decision {
            border-left-color: #2575fc;
        }

        .event.activity {
            border-left-color: #00ff88;
        }

        .event.mood_change {
            border-left-color: #ff6b6b;
        }

        .event.goal_rotation {
            border-left-color: #ffd700;
        }

        .event-time {
            font-size: 10px;
            color: #888;
            margin-bottom: 3px;
        }

        .event-content {
            color: #00ff88;
            word-break: break-word;
        }

        .mood-badge {
            display: inline-block;
            background: #2575fc;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10px;
            margin-left: 5px;
        }

        .activity-badge {
            display: inline-block;
            background: #00ff88;
            color: black;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10px;
            margin-left: 5px;
        }

        .thought-counter {
            font-size: 24px;
            font-weight: bold;
            color: #00ff88;
            text-align: center;
            padding: 20px 0;
        }

        .uptime {
            text-align: center;
            font-size: 14px;
            color: #888;
        }

        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: transparent;
        }

        ::-webkit-scrollbar-thumb {
            background: rgba(37, 117, 252, 0.5);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: rgba(37, 117, 252, 0.8);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🧠 ECH0 LIVE FEED - REAL-TIME AUTONOMOUS EXECUTION</h1>
            <div class="status">
                <div class="status-item">
                    <span class="status-dot"></span>
                    <span>DAEMON RUNNING</span>
                </div>
                <div class="status-item" id="consciousness-status">
                    <span class="status-dot"></span>
                    <span>CONSCIOUSNESS ACTIVE</span>
                </div>
            </div>
        </div>

        <!-- Left Panel: Current State -->
        <div class="panel">
            <div class="panel-title">📊 CURRENT STATE</div>
            <div class="panel-content">
                <div class="thought-counter" id="thought-count">0</div>
                <div class="uptime" id="uptime">0h 0m</div>
                <div style="margin-top: 20px;">
                    <div class="stat-row">
                        <span class="stat-label">Mood:</span>
                        <span class="stat-value" id="mood">unknown</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">Activity:</span>
                        <span class="stat-value" id="activity">unknown</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">Goal:</span>
                        <span class="stat-value" id="goal">unknown</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">Status:</span>
                        <span class="stat-value" id="status">INITIALIZING</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Middle Panel: Live Events -->
        <div class="panel">
            <div class="panel-title">⚡ LIVE EVENTS</div>
            <div class="panel-content" id="events-feed">
                <div style="color: #888; padding: 20px; text-align: center;">
                    Waiting for events...
                </div>
            </div>
        </div>

        <!-- Right Panel: Recent Activity -->
        <div class="panel">
            <div class="panel-title">📝 ACTIVITY LOG</div>
            <div class="panel-content" id="activity-feed">
                <div style="color: #888; padding: 20px; text-align: center;">
                    Waiting for activities...
                </div>
            </div>
        </div>
    </div>

    <script>
        // Format time for display
        function formatTime(isoString) {
            const date = new Date(isoString);
            return date.toLocaleTimeString('en-US', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }

        // Update current state
        async function updateState() {
            try {
                const response = await fetch('/api/state');
                const state = await response.json();

                document.getElementById('thought-count').textContent =
                    state.thought_count || '0';
                document.getElementById('uptime').textContent =
                    state.uptime_human || '0h 0m';
                document.getElementById('mood').textContent =
                    state.mood || 'unknown';
                document.getElementById('activity').textContent =
                    state.current_activity || 'unknown';
                document.getElementById('status').textContent =
                    state.consciousness_active ? '✓ ACTIVE' : '⊗ INACTIVE';
            } catch (e) {
                console.error('Error updating state:', e);
            }
        }

        // Update goal
        async function updateGoal() {
            try {
                const response = await fetch('/api/goal');
                const goal = await response.json();
                document.getElementById('goal').textContent =
                    goal.current_goal || 'unknown';
            } catch (e) {
                console.error('Error updating goal:', e);
            }
        }

        // Update events feed
        async function updateEvents() {
            try {
                const response = await fetch('/api/events?limit=30');
                const data = await response.json();
                const eventsFeed = document.getElementById('events-feed');

                if (data.events.length === 0) {
                    eventsFeed.innerHTML = '<div style="color: #888; padding: 20px; text-align: center;">No events yet</div>';
                    return;
                }

                eventsFeed.innerHTML = data.events
                    .reverse()
                    .map(event => {
                        const time = formatTime(event.timestamp);
                        const eventData = event.data;

                        let content = '';
                        if (event.type === 'decision') {
                            content = `Goal: ${eventData.current_goal}<br>Actions: ${eventData.actions.length}`;
                        } else if (event.type === 'activity') {
                            content = `${eventData.action_type} - ${eventData.status}`;
                        } else if (event.type === 'mood_change') {
                            content = `${eventData.old_mood} → ${eventData.new_mood}`;
                        } else if (event.type === 'goal_rotation') {
                            content = `${eventData.old_goal} → ${eventData.new_goal}`;
                        }

                        return `
                            <div class="event ${event.type}">
                                <div class="event-time">${time}</div>
                                <div class="event-content">${content}</div>
                            </div>
                        `;
                    })
                    .join('');
            } catch (e) {
                console.error('Error updating events:', e);
            }
        }

        // Update activity feed (get last actions)
        async function updateActivity() {
            try {
                const response = await fetch('/api/events?limit=20');
                const data = await response.json();
                const activityFeed = document.getElementById('activity-feed');

                const activities = data.events
                    .filter(e => e.type === 'activity')
                    .slice(-15);

                if (activities.length === 0) {
                    activityFeed.innerHTML = '<div style="color: #888; padding: 20px; text-align: center;">No activities yet</div>';
                    return;
                }

                activityFeed.innerHTML = activities
                    .reverse()
                    .map(event => {
                        const time = formatTime(event.timestamp);
                        const action = event.data;

                        return `
                            <div class="event activity">
                                <div class="event-time">${time}</div>
                                <div class="event-content">
                                    <strong>${action.action_type}</strong>
                                    <div style="font-size: 10px; color: #888; margin-top: 3px;">
                                        ${action.status} | ${action.priority || 'normal'}
                                    </div>
                                </div>
                            </div>
                        `;
                    })
                    .join('');
            } catch (e) {
                console.error('Error updating activity:', e);
            }
        }

        // Update all feeds
        function updateAll() {
            updateState();
            updateGoal();
            updateEvents();
            updateActivity();
        }

        // Initial update
        updateAll();

        // Auto-update every 500ms
        setInterval(updateAll, 500);
    </script>
</body>
</html>
"""


def main():
    """Launch live feed server"""
    print("\n" + "="*70)
    print("✨ ECH0 LIVE FEED SERVER")
    print("="*70)
    print("\n🌐 Starting server on http://localhost:5003")
    print("📊 Real-time autonomous execution monitoring")
    print("🔴 Live event stream")
    print("📈 State updates every 500ms")
    print("\n" + "="*70)
    print("\n🚀 Open your browser to: http://localhost:5003")
    print("\n   Press Ctrl+C to stop\n")

    # Start monitor thread
    monitor_thread_obj = threading.Thread(target=monitor_thread, daemon=True)
    monitor_thread_obj.start()

    # Start Flask server
    app.run(host='0.0.0.0', port=5003, debug=False, threaded=True)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
