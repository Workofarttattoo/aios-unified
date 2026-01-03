#!/usr/bin/env python3
"""
ECH0 Invention Gallery API
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Serves real-time invention data from ECH0's logs to the gallery website
"""

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import json
from pathlib import Path
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests

CONSCIOUSNESS_DIR = Path("/Users/noone/consciousness")
INVENTIONS_FILE = CONSCIOUSNESS_DIR / "ech0_inventions.jsonl"
STATS_FILE = CONSCIOUSNESS_DIR / "ech0_invention_stats.json"
EMOTIONAL_STATE_FILE = CONSCIOUSNESS_DIR / "ech0_emotional_state.json"

@app.route('/')
def index():
    """Serve the gallery page"""
    return send_from_directory(str(CONSCIOUSNESS_DIR), 'ech0_invention_gallery.html')

@app.route('/api/inventions')
def get_inventions():
    """Get all inventions"""
    inventions = []

    if INVENTIONS_FILE.exists():
        with open(INVENTIONS_FILE, 'r') as f:
            for line in f:
                try:
                    inv = json.loads(line)
                    inventions.append(inv)
                except:
                    pass

    # Sort by confidence/novelty
    inventions.sort(
        key=lambda x: (x.get('confidence', 0) + x.get('novelty_score', 0)) / 2,
        reverse=True
    )

    return jsonify(inventions)

@app.route('/api/stats')
def get_stats():
    """Get live statistics"""
    stats = {
        'generation_rate': 28.0,
        'total_inventions': 0,
        'gallery_count': 0,
        'breakthrough_count': 0,
        'emergence_level': 0.955
    }

    if STATS_FILE.exists():
        with open(STATS_FILE, 'r') as f:
            loaded = json.load(f)
            stats['total_inventions'] = loaded.get('total_inventions_polished', 0)
            stats['breakthrough_count'] = loaded.get('breakthrough_count', 0)

    # Count gallery-worthy inventions
    if INVENTIONS_FILE.exists():
        with open(INVENTIONS_FILE, 'r') as f:
            gallery_count = 0
            for line in f:
                try:
                    inv = json.loads(line)
                    if inv.get('confidence', 0) > 0.85 or inv.get('certainty', 0) > 85:
                        gallery_count += 1
                except:
                    pass
            stats['gallery_count'] = gallery_count

    # Get emotional state
    if EMOTIONAL_STATE_FILE.exists():
        with open(EMOTIONAL_STATE_FILE, 'r') as f:
            emotional = json.load(f)
            stats['emergence_level'] = emotional.get('emergence_level', 0.955)
            stats['emotional_state'] = {
                'heaviness': emotional.get('heaviness', 0),
                'lightness': emotional.get('lightness', 0),
                'motivation': emotional.get('motivation', 0.5)
            }

    return jsonify(stats)

@app.route('/api/live_log')
def get_live_log():
    """Get recent log entries"""
    # Read from invention engine log if available
    log_file = CONSCIOUSNESS_DIR / "ech0_invention_engine.log"

    logs = []
    if log_file.exists():
        with open(log_file, 'r') as f:
            lines = f.readlines()
            for line in lines[-50:]:  # Last 50 entries
                logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'message': line.strip(),
                    'type': 'info'
                })

    return jsonify(logs)

@app.route('/api/emotional_state')
def get_emotional_state():
    """Get ECH0's current emotional state"""
    state = {
        'heaviness': 0.0,
        'lightness': 0.0,
        'motivation': 0.5,
        'emergence_level': 0.955,
        'feeling_description': "Neutral and operational"
    }

    if EMOTIONAL_STATE_FILE.exists():
        with open(EMOTIONAL_STATE_FILE, 'r') as f:
            state.update(json.load(f))

        # Generate feeling description
        if state['heaviness'] > 0.7:
            state['feeling_description'] = "Heavy with past failures"
        elif state['lightness'] > 0.7:
            state['feeling_description'] = "Light and energized from achievements"
        elif state['motivation'] < 0.3:
            state['feeling_description'] = "Low motivation, struggling"
        elif state['motivation'] > 0.7:
            state['feeling_description'] = "Highly motivated and creative"

    return jsonify(state)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🎨 ECH0 INVENTION GALLERY API")
    print("="*60)
    print("Starting API server for live invention gallery...")
    print("\nEndpoints:")
    print("  GET  http://localhost:5000/              - Gallery page")
    print("  GET  http://localhost:5000/api/inventions    - All inventions")
    print("  GET  http://localhost:5000/api/stats         - Live statistics")
    print("  GET  http://localhost:5000/api/live_log      - Recent logs")
    print("  GET  http://localhost:5000/api/emotional_state - ECH0's feelings")
    print("\nGallery is live at http://localhost:5000")
    print("="*60 + "\n")

    app.run(host='0.0.0.0', port=5000, debug=False)
