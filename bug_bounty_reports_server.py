#!/usr/bin/env python3
"""
Bug Bounty Reports API Server
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from pathlib import Path

REPORTS_DIR = Path('/Users/noone/aios/bug_bounty_reports/')
PORT = 8888

class VulnHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/vulnerabilities':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            vulns = []
            try:
                for file in sorted(REPORTS_DIR.glob('*.json'), key=lambda x: x.stat().st_mtime, reverse=True):
                    try:
                        with open(file) as f:
                            data = json.load(f)
                            vulns.append(data)
                    except Exception as e:
                        print(f"Error reading {file}: {e}")

                response = {
                    'vulnerabilities': vulns,
                    'total': len(vulns)
                }

                self.wfile.write(json.dumps(response, indent=2).encode())
            except Exception as e:
                error = {'error': str(e), 'vulnerabilities': []}
                self.wfile.write(json.dumps(error).encode())
        else:
            self.send_error(404, "Not Found")

    def log_message(self, format, *args):
        return  # Suppress logging

if __name__ == '__main__':
    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║         Bug Bounty Reports API Server                               ║
║                                                                      ║
║  API: http://localhost:{PORT}/api/vulnerabilities{' ' * 26} ║
║  Dashboard: /Users/noone/Desktop/BugBountyDashboard.html            ║
║                                                                      ║
║  Copyright (c) 2025 Corporation of Light. PATENT PENDING            ║
╚══════════════════════════════════════════════════════════════════════╝

✅ Server running on http://localhost:{PORT}
📁 Serving from: {REPORTS_DIR}
🔄 Dashboard auto-refreshes every 5 seconds

Press Ctrl+C to stop
""")

    try:
        server = HTTPServer(('localhost', PORT), VulnHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped")
