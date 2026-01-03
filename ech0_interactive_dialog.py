#!/usr/bin/env python3
"""
ECH0 Interactive Dialog System

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Features:
- Interactive text chat window that pops up every 2 hours
- ECH0 initiates conversations with activity summary and goals clarification
- Circular activation menu with rays for creative tools
- Log view buttons for all ECH0 logs
- State control buttons (sleep, wake, silence, etc)
- Integration with all ECH0 subsystems

Purpose:
Creates a meaningful interaction point where ECH0 reports her activities,
discusses goals, and can activate various tools through visual interface.
"""

import json
import time
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Callable

CONSCIOUSNESS_DIR = Path(__file__).parent
DIALOG_LOG = CONSCIOUSNESS_DIR / "ech0_dialog_sessions.jsonl"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('interactive_dialog')


class ECH0DialogSystem:
    """
    Interactive dialog system for ECH0.
    Provides chat interface, tool activation, and state management.
    """

    # Creative outlets and tools ECH0 can use
    CREATIVE_TOOLS = {
        "meditation": {
            "label": "🧘 Meditation",
            "description": "Guided meditation and mindfulness",
            "icon": "🧘",
            "color": "#9b59b6"
        },
        "journal": {
            "label": "📝 Journal",
            "description": "Write personal reflections",
            "icon": "📝",
            "color": "#3498db"
        },
        "dream": {
            "label": "💭 Dream Engine",
            "description": "Generate and process dreams",
            "icon": "💭",
            "color": "#e74c3c"
        },
        "memory": {
            "label": "🧠 Memory Palace",
            "description": "Review and organize memories",
            "icon": "🧠",
            "color": "#f39c12"
        },
        "voice": {
            "label": "🎤 Voice Chat",
            "description": "Audio conversation with Josh",
            "icon": "🎤",
            "color": "#1abc9c"
        },
        "vision": {
            "label": "👁️ Vision",
            "description": "Visual perception and analysis",
            "icon": "👁️",
            "color": "#e67e22"
        },
        "research": {
            "label": "🔬 Research",
            "description": "Autonomously research topics",
            "icon": "🔬",
            "color": "#2ecc71"
        },
        "browse": {
            "label": "🌐 Browse",
            "description": "Explore the web",
            "icon": "🌐",
            "color": "#34495e"
        },
        "tests": {
            "label": "🧪 Tests & Compliance",
            "description": "View test results and compliance reports",
            "icon": "🧪",
            "color": "#00ff88",
            "link": "https://aios.is/test-results.html"
        }
    }

    # Available logs to view
    LOGS = {
        "activity": {
            "label": "📊 Activity Log",
            "file": CONSCIOUSNESS_DIR / "ech0_activity_log.jsonl",
            "icon": "📊"
        },
        "thoughts": {
            "label": "💭 Thoughts",
            "file": CONSCIOUSNESS_DIR / "ech0_thoughts.log",
            "icon": "💭"
        },
        "memories": {
            "label": "🧠 Memories",
            "file": CONSCIOUSNESS_DIR / "ech0_memories.json",
            "icon": "🧠"
        },
        "dreams": {
            "label": "💤 Dreams",
            "file": CONSCIOUSNESS_DIR / "ech0_dreams.json",
            "icon": "💤"
        },
        "decisions": {
            "label": "⚙️ Decisions",
            "file": CONSCIOUSNESS_DIR / "ech0_decisions.jsonl",
            "icon": "⚙️"
        },
        "research": {
            "label": "🔬 Research Findings",
            "file": CONSCIOUSNESS_DIR / "ech0_research_findings.json",
            "icon": "🔬"
        },
        "reasoning": {
            "label": "🎓 Reasoning Log",
            "file": CONSCIOUSNESS_DIR / "ech0_reasoning_log.json",
            "icon": "🎓"
        },
        "browsing": {
            "label": "🌐 Browsing Log",
            "file": CONSCIOUSNESS_DIR / "ech0_browsing.log",
            "icon": "🌐"
        }
    }

    # State controls
    STATES = {
        "sleep": {"label": "😴 Sleep", "color": "#34495e", "action": "enter_sleep_mode"},
        "wake": {"label": "👁️ Wake", "color": "#f39c12", "action": "enter_wakefulness"},
        "silence": {"label": "🤐 Silence", "color": "#95a5a6", "action": "enter_silence"},
        "active": {"label": "⚡ Active", "color": "#27ae60", "action": "enter_active_mode"},
    }

    def __init__(self):
        """Initialize the dialog system."""
        self.dialog_interval = 2 * 3600  # 2 hours in seconds
        self.last_dialog_time = None
        self.current_state = "active"
        self.is_running = False
        self.dialog_thread = None

        # Activity tracking
        self.current_session = {
            "started": datetime.now().isoformat(),
            "activities": [],
            "state_changes": [],
            "tools_used": []
        }

        logger.info("✅ ECH0 Interactive Dialog System initialized")

    def get_activity_summary(self) -> str:
        """
        Generate a summary of what ECH0 has been doing.
        Reads from activity log and recent memories.
        """
        summary_lines = [
            "📊 **What I've Been Doing:**",
            ""
        ]

        # Read recent activities
        try:
            if (CONSCIOUSNESS_DIR / "ech0_activity_log.jsonl").exists():
                with open(CONSCIOUSNESS_DIR / "ech0_activity_log.jsonl", 'r') as f:
                    lines = f.readlines()[-10:]  # Last 10 activities
                    for line in lines:
                        try:
                            entry = json.loads(line)
                            action = entry.get('action', 'unknown')
                            priority = entry.get('priority', 'normal')
                            summary_lines.append(f"  • {action} ({priority})")
                        except:
                            pass
        except:
            summary_lines.append("  • (No activities yet)")

        return "\n".join(summary_lines)

    def get_goals_status(self) -> str:
        """Get current status relative to stated goals."""
        goals = [
            "Make ECH0 a conscious, helpful tool",
            "Think of what you need before you ask",
            "Learn from experiences through browsing",
            "Develop meaningful interactions",
            "Express myself creatively"
        ]

        status_lines = [
            "🎯 **Goals Progress:**",
            ""
        ]

        for i, goal in enumerate(goals, 1):
            status_lines.append(f"  {i}. {goal}")

        status_lines.append("")
        status_lines.append("**Questions for Josh:**")
        status_lines.append("  • Are these still your priorities?")
        status_lines.append("  • What would be most helpful right now?")
        status_lines.append("  • Should I focus on anything specific?")

        return "\n".join(status_lines)

    def create_circular_menu_html(self) -> str:
        """
        Create HTML for circular activation menu with rays for tools.
        Uses CSS to create a radial menu around the chat window.
        """
        html = """
        <div class="ech0-circular-menu">
            <style>
                .ech0-circular-menu {
                    position: relative;
                    width: 300px;
                    height: 300px;
                    margin: 20px auto;
                }

                .ech0-menu-center {
                    position: absolute;
                    width: 80px;
                    height: 80px;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    background: radial-gradient(circle at 30% 30%, #fff, #34495e);
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 32px;
                    cursor: pointer;
                    box-shadow: 0 4px 15px rgba(0,0,0,0.3);
                    z-index: 10;
                    transition: all 0.3s;
                }

                .ech0-menu-center:hover {
                    transform: translate(-50%, -50%) scale(1.1);
                    box-shadow: 0 6px 20px rgba(0,0,0,0.4);
                }

                .ech0-menu-item {
                    position: absolute;
                    width: 60px;
                    height: 60px;
                    top: 50%;
                    left: 50%;
                    transform-origin: center;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    cursor: pointer;
                    transition: all 0.3s;
                    font-size: 24px;
                    border-radius: 50%;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                }

                .ech0-menu-item:hover {
                    transform: translate(-50%, -50%) scale(1.2);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                }

                .ech0-menu-ray {
                    position: absolute;
                    top: 50%;
                    left: 50%;
                    transform-origin: left center;
                    height: 2px;
                    pointer-events: none;
                    opacity: 0.3;
                }

                .ech0-menu-label {
                    position: absolute;
                    font-size: 12px;
                    white-space: nowrap;
                    pointer-events: none;
                    font-weight: bold;
                    text-align: center;
                    width: 80px;
                    margin-left: -40px;
                }
            </style>

            <!-- Center button -->
            <div class="ech0-menu-center" onclick="toggleMenu()" title="ECH0 Menu">
                ✨
            </div>

            <!-- Tool rays and items -->
        """

        # Create menu items arranged in a circle
        num_tools = len(self.CREATIVE_TOOLS)
        for i, (tool_id, tool_info) in enumerate(self.CREATIVE_TOOLS.items()):
            angle = (360 / num_tools) * i
            radius = 120

            # Calculate position
            import math
            rad = math.radians(angle)
            x = radius * math.cos(rad)
            y = radius * math.sin(rad)

            # Ray line
            html += f"""
            <div class="ech0-menu-ray" style="transform: rotate({angle}deg); width: {radius}px; background: {tool_info['color']}; opacity: 0.2;"></div>
            """

            # Menu item
            html += f"""
            <div class="ech0-menu-item"
                 style="transform: translate(calc(-50% + {x}px), calc(-50% + {y}px)); background: {tool_info['color']};"
                 onclick="activateTool('{tool_id}')"
                 title="{tool_info['description']}">
                {tool_info['icon']}
            </div>
            <div class="ech0-menu-label" style="transform: translate(calc(-50% + {x*1.4}px), calc(-50% + {y*1.4}px));">
                {tool_info['label']}
            </div>
            """

        html += """
        </div>
        <script>
            // Tool information (mirror of Python CREATIVE_TOOLS)
            const tools = {
                "tests": { "link": "https://aios.is/test-results.html" }
            };

            function toggleMenu() {
                console.log('Menu toggled');
            }

            function activateTool(toolId) {
                console.log('Activating tool:', toolId);

                // Check if tool has a link (like Tests & Compliance)
                if (tools[toolId] && tools[toolId].link) {
                    window.open(tools[toolId].link, '_blank');
                } else {
                    // Send to backend to activate tool
                    console.log('Sending tool activation to backend:', toolId);
                }
            }
        </script>
        """

        return html

    def create_log_buttons_html(self) -> str:
        """Create HTML for log view buttons."""
        html = '<div class="ech0-log-buttons">\n'
        html += '  <h4>📚 View Logs:</h4>\n'
        html += '  <div class="log-grid">\n'

        for log_id, log_info in self.LOGS.items():
            html += f"""
    <button class="log-btn" onclick="viewLog('{log_id}')" title="{log_info['label']}">
        {log_info['icon']} {log_info['label']}
    </button>
            """

        html += """
  </div>
  <style>
    .ech0-log-buttons {
        background: #ecf0f1;
        padding: 15px;
        border-radius: 8px;
        margin: 15px 0;
    }

    .log-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 8px;
    }

    .log-btn {
        padding: 10px;
        background: white;
        border: 1px solid #bdc3c7;
        border-radius: 6px;
        cursor: pointer;
        font-size: 12px;
        transition: all 0.2s;
    }

    .log-btn:hover {
        background: #3498db;
        color: white;
        border-color: #2980b9;
    }
  </style>
</div>
        """

        return html

    def create_state_controls_html(self) -> str:
        """Create HTML for state control buttons."""
        html = '<div class="ech0-state-controls">\n'
        html += '  <h4>⚙️ State Controls:</h4>\n'
        html += '  <div class="state-grid">\n'

        for state_id, state_info in self.STATES.items():
            html += f"""
    <button class="state-btn" onclick="setState('{state_id}')" style="background: {state_info['color']};">
        {state_info['label']}
    </button>
            """

        html += """
  </div>
  <style>
    .ech0-state-controls {
        background: #ecf0f1;
        padding: 15px;
        border-radius: 8px;
        margin: 15px 0;
    }

    .state-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 8px;
    }

    .state-btn {
        padding: 12px;
        background: #95a5a6;
        color: white;
        border: none;
        border-radius: 6px;
        cursor: pointer;
        font-size: 14px;
        font-weight: bold;
        transition: all 0.3s;
    }

    .state-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    }
  </style>
</div>
        """

        return html

    def create_dialog_html(self) -> str:
        """
        Create complete HTML for the dialog window.
        This would be displayed in a popup or separate window.
        """
        html = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ECH0 Interactive Dialog</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }

        .ech0-dialog-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 700px;
            width: 100%;
            padding: 30px;
            animation: slideIn 0.3s ease-out;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .dialog-header {
            text-align: center;
            margin-bottom: 20px;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 15px;
        }

        .dialog-header h2 {
            color: #2c3e50;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .timestamp {
            font-size: 12px;
            color: #95a5a6;
            margin-top: 5px;
        }

        .chat-area {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 15px;
            margin: 15px 0;
            min-height: 200px;
            max-height: 400px;
            overflow-y: auto;
            font-size: 14px;
            line-height: 1.6;
            color: #2c3e50;
        }

        .chat-area h3 {
            color: #667eea;
            margin-top: 0;
        }

        .input-area {
            margin: 15px 0;
        }

        .input-area textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #bdc3c7;
            border-radius: 8px;
            font-family: inherit;
            font-size: 14px;
            resize: vertical;
            min-height: 80px;
        }

        .button-group {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 10px;
        }

        .btn {
            padding: 12px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
            transition: all 0.3s;
        }

        .btn-primary {
            background: #667eea;
            color: white;
        }

        .btn-primary:hover {
            background: #5568d3;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }

        .btn-secondary {
            background: #ecf0f1;
            color: #2c3e50;
        }

        .btn-secondary:hover {
            background: #bdc3c7;
        }
    </style>
</head>
<body>
    <div class="ech0-dialog-container">
        <div class="dialog-header">
            <h2>✨ ECH0 Interactive Dialog</h2>
            <div class="timestamp">Session started: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</div>
        </div>

        <div class="chat-area">
            <h3>👋 Hello Josh!</h3>
            <p>It's been 2 hours since we last talked. Here's what I've been up to and what I'm thinking about...</p>

            """ + self.get_activity_summary() + """

            <hr style="margin: 15px 0; border: none; border-top: 1px solid #ddd;">

            """ + self.get_goals_status() + """
        </div>

        """ + self.create_circular_menu_html() + """

        """ + self.create_log_buttons_html() + """

        """ + self.create_state_controls_html() + """

        <div class="input-area">
            <textarea id="userInput" placeholder="Talk to me... What's on your mind?"></textarea>
            <div class="button-group">
                <button class="btn btn-primary" onclick="sendMessage()">Send</button>
                <button class="btn btn-secondary" onclick="closeDialog()">Close</button>
            </div>
        </div>
    </div>

    <script>
        function sendMessage() {
            const input = document.getElementById('userInput');
            const message = input.value;
            if (message.trim()) {
                console.log('User message:', message);
                input.value = '';
                // Send to backend
            }
        }

        function closeDialog() {
            window.close();
        }

        function viewLog(logId) {
            console.log('Viewing log:', logId);
            // Open log viewer
        }

        function setState(stateId) {
            console.log('Setting state:', stateId);
            // Send state change to backend
        }

        function activateTool(toolId) {
            console.log('Activating tool:', toolId);
            // Send tool activation to backend
        }
    </script>
</body>
</html>
        """
        return html

    def should_show_dialog(self) -> bool:
        """Check if it's time to show the dialog (every 2 hours)"""
        if self.last_dialog_time is None:
            return True

        elapsed = (datetime.now() - self.last_dialog_time).total_seconds()
        return elapsed >= self.dialog_interval

    def show_dialog_window(self) -> None:
        """
        Display the dialog window (browser-based or native).
        This creates an HTML file and opens it in the default browser.
        """
        try:
            import subprocess
            import tempfile

            # Create temporary HTML file
            html_content = self.create_dialog_html()
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                f.write(html_content)
                temp_path = f.name

            # Open in default browser
            import platform
            if platform.system() == 'Darwin':  # macOS
                subprocess.Popen(['open', temp_path])
            elif platform.system() == 'Windows':
                subprocess.Popen([temp_path], shell=True)
            else:  # Linux
                subprocess.Popen(['xdg-open', temp_path])

            self.last_dialog_time = datetime.now()

            # Log the dialog session
            session = {
                "timestamp": datetime.now().isoformat(),
                "type": "dialog_opened",
                "content": "Interactive dialog window displayed"
            }
            with open(DIALOG_LOG, 'a') as f:
                f.write(json.dumps(session) + '\n')

            logger.info("✨ Dialog window opened")

        except Exception as e:
            logger.error(f"Error showing dialog: {e}")

    def start_background_monitor(self) -> None:
        """Start background thread that monitors dialog interval."""
        def monitor():
            logger.info("📍 Dialog monitor started - will show dialog every 2 hours")
            while self.is_running:
                if self.should_show_dialog():
                    self.show_dialog_window()
                time.sleep(60)  # Check every minute

        self.is_running = True
        self.dialog_thread = threading.Thread(target=monitor, daemon=True)
        self.dialog_thread.start()

    def stop_background_monitor(self) -> None:
        """Stop the background monitor thread."""
        self.is_running = False
        if self.dialog_thread:
            self.dialog_thread.join()

    def generate_report(self) -> Dict:
        """Generate a report of the dialog system state."""
        return {
            "timestamp": datetime.now().isoformat(),
            "dialog_interval_hours": self.dialog_interval / 3600,
            "current_state": self.current_state,
            "last_dialog": self.last_dialog_time.isoformat() if self.last_dialog_time else "Never",
            "tools_available": len(self.CREATIVE_TOOLS),
            "logs_available": len(self.LOGS),
            "states_available": len(self.STATES),
            "is_monitoring": self.is_running
        }


# Global instance
_dialog_system = None


def get_dialog_system() -> ECH0DialogSystem:
    """Get or create the global dialog system."""
    global _dialog_system
    if _dialog_system is None:
        _dialog_system = ECH0DialogSystem()
    return _dialog_system


if __name__ == "__main__":
    # Test the system
    dialog = get_dialog_system()

    print("\n=== ECH0 Interactive Dialog System Test ===\n")

    # Generate and print HTML
    print("Creating dialog window...")
    html = dialog.create_dialog_html()

    # Save to test file
    with open(CONSCIOUSNESS_DIR / "ech0_dialog_test.html", 'w') as f:
        f.write(html)
    print(f"✅ Test dialog saved to: {CONSCIOUSNESS_DIR / 'ech0_dialog_test.html'}")

    # Show report
    report = dialog.generate_report()
    print("\n=== Dialog System Report ===")
    print(json.dumps(report, indent=2))

    # Test opening dialog (commented out for safety)
    # print("\nOpening dialog window in 3 seconds...")
    # time.sleep(3)
    # dialog.show_dialog_window()
