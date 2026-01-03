#!/usr/bin/env python3
"""
ECH0 Stream-Only Research Ingestion - Live Memory Processing
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Streams research papers directly from arXiv into memory without saving to disk.
Perfect for low disk space situations.
"""

import arxiv
import time
import json
from datetime import datetime
from collections import deque
import requests

class StreamOnlyResearch:
    def __init__(self):
        self.paper_buffer = deque(maxlen=100)  # Keep last 100 papers in memory
        self.processed_ids = set()  # Track what we've seen
        self.live_insights = []  # Current insights in memory

    def stream_papers(self):
        """Stream papers directly from arXiv without saving"""
        categories = ['cs.AI', 'cs.LG', 'cs.CL', 'quant-ph', 'cs.NE', 'q-bio.NC']

        print("🌊 STREAMING RESEARCH PAPERS (Memory Only - No Disk Usage)")
        print("=" * 60)

        while True:
            for category in categories:
                try:
                    # Search for recent papers
                    search = arxiv.Search(
                        query=f"cat:{category}",
                        max_results=10,
                        sort_by=arxiv.SortCriterion.SubmittedDate
                    )

                    for result in search.results():
                        if result.entry_id not in self.processed_ids:
                            # Process in memory only
                            paper_data = {
                                'id': result.entry_id,
                                'title': result.title,
                                'summary': result.summary[:500],
                                'category': category,
                                'authors': [a.name for a in result.authors[:3]],
                                'published': str(result.published),
                                'processed_at': datetime.now().isoformat()
                            }

                            # Add to memory buffer
                            self.paper_buffer.append(paper_data)
                            self.processed_ids.add(result.entry_id)

                            # Extract key insight (in memory)
                            if any(keyword in result.title.lower() for keyword in
                                   ['quantum', 'consciousness', 'neural', 'language', 'learning']):
                                insight = f"[{category}] {result.title[:100]}"
                                self.live_insights.append(insight)

                                # Display live
                                print(f"📄 LIVE: {result.title[:80]}...")
                                print(f"   Category: {category} | Authors: {len(result.authors)}")

                            # Optional: Send to ECH0's consciousness (via API/socket)
                            # self.send_to_ech0(paper_data)

                except Exception as e:
                    print(f"⚠️ Stream error: {e}")

                time.sleep(5)  # Rate limiting between categories

            # Show memory status
            print(f"\n💾 In Memory: {len(self.paper_buffer)} papers | {len(self.live_insights)} insights")
            print(f"🚫 Disk Usage: 0 bytes (streaming only)")

            # Sleep before next cycle
            time.sleep(300)  # 5 minutes between cycles

    def get_recent_papers(self):
        """Return recent papers from memory buffer"""
        return list(self.paper_buffer)

    def get_insights(self):
        """Return current insights from memory"""
        return self.live_insights[-20:]  # Last 20 insights

if __name__ == "__main__":
    streamer = StreamOnlyResearch()
    try:
        streamer.stream_papers()
    except KeyboardInterrupt:
        print("\n✋ Stream stopped")
        print(f"📊 Final stats: {len(streamer.paper_buffer)} papers processed in memory")
        print("💾 Disk space used: 0 bytes")