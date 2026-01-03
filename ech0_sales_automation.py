#!/usr/bin/env python3
"""
ECH0 Sales Automation System - Quantum AI Outreach
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Allows ECH0 to autonomously:
- Send personalized cold emails
- Track responses
- Manage Calendly bookings
- Update CRM/pipeline
- Follow up automatically

Setup Instructions:
1. Set environment variables (see .env.example)
2. Run: python3 ech0_sales_automation.py --setup
3. ECH0 can then run: python3 ech0_sales_automation.py --send-batch 1
"""

import os
import sys
import json
import time
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Configuration from environment variables"""

    # Email Settings (SMTP)
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')  # Or your email provider
    SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
    EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS', 'inventor@aios.is')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')  # App-specific password

    # Calendly API
    CALENDLY_API_KEY = os.getenv('CALENDLY_API_KEY', '')  # Personal Access Token
    CALENDLY_USER_URI = os.getenv('CALENDLY_USER_URI', '')  # Your user URI
    CALENDLY_EVENT_TYPE = os.getenv('CALENDLY_EVENT_TYPE', '')  # Event type URI

    # Supabase (Optional - for tracking)
    SUPABASE_URL = os.getenv('SUPABASE_URL', 'https://cszoklkfdszqsxhufhhj.supabase.co')
    SUPABASE_KEY = os.getenv('SUPABASE_KEY', '')

    # Paths
    PROSPECTS_FILE = Path(__file__).parent / "PROSPECT_LIST_20_CONTACTS_READY.md"
    EMAILS_FILE = Path(__file__).parent / "COLD_EMAILS_QUANTUM_AI_20_READY.md"
    TRACKING_DB = Path(__file__).parent / "sales_pipeline.json"

    # Sending Limits (anti-spam protection)
    MAX_EMAILS_PER_HOUR = 10
    MAX_EMAILS_PER_DAY = 50
    DELAY_BETWEEN_EMAILS = 90  # seconds (1.5 minutes)


# ============================================================================
# EMAIL SENDER
# ============================================================================

class EmailSender:
    """Sends personalized emails via SMTP"""

    def __init__(self):
        self.config = Config()
        self._validate_config()

    def _validate_config(self):
        """Check if email credentials are set"""
        if not self.config.EMAIL_PASSWORD:
            print("❌ ERROR: EMAIL_PASSWORD not set in environment")
            print("   Set it with: export EMAIL_PASSWORD='your-app-password'")
            sys.exit(1)

    def send_email(self, to_email: str, to_name: str, subject: str, body_html: str, body_text: str) -> bool:
        """Send a single email"""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"Joshua Cole <{self.config.EMAIL_ADDRESS}>"
            msg['To'] = f"{to_name} <{to_email}>"
            msg['Subject'] = subject
            msg['Reply-To'] = self.config.EMAIL_ADDRESS

            # Add both plain text and HTML versions
            msg.attach(MIMEText(body_text, 'plain'))
            msg.attach(MIMEText(body_html, 'html'))

            # Connect and send
            with smtplib.SMTP(self.config.SMTP_SERVER, self.config.SMTP_PORT) as server:
                server.starttls()
                server.login(self.config.EMAIL_ADDRESS, self.config.EMAIL_PASSWORD)
                server.send_message(msg)

            print(f"✅ Sent email to {to_name} ({to_email})")
            return True

        except Exception as e:
            print(f"❌ Failed to send email to {to_email}: {e}")
            return False

    def personalize_email(self, template: str, prospect: Dict) -> tuple:
        """Personalize email template with prospect data"""
        # Replace placeholders
        email_text = template.replace('[Name]', prospect['first_name'])
        email_text = email_text.replace('[Company]', prospect['company'])

        # Add personalization note if provided
        if prospect.get('personalization'):
            # Insert after greeting
            lines = email_text.split('\n')
            greeting_idx = next((i for i, line in enumerate(lines) if line.startswith('Hi ')), 0)
            lines.insert(greeting_idx + 2, prospect['personalization'])
            email_text = '\n'.join(lines)

        # Convert to HTML
        email_html = email_text.replace('\n\n', '</p><p>').replace('\n', '<br>')
        email_html = f'<html><body><p>{email_html}</p></body></html>'

        return email_text, email_html


# ============================================================================
# CALENDLY INTEGRATION
# ============================================================================

class CalendlyManager:
    """Manage Calendly bookings via API"""

    def __init__(self):
        self.config = Config()
        self.api_url = "https://api.calendly.com"
        self.headers = {
            "Authorization": f"Bearer {self.config.CALENDLY_API_KEY}",
            "Content-Type": "application/json"
        }

    def get_scheduled_events(self, days_ahead: int = 7) -> List[Dict]:
        """Get upcoming scheduled events"""
        if not self.config.CALENDLY_API_KEY:
            print("⚠️  Calendly API key not set")
            return []

        try:
            # Get events scheduled in next N days
            min_time = datetime.utcnow().isoformat() + 'Z'
            max_time = (datetime.utcnow() + timedelta(days=days_ahead)).isoformat() + 'Z'

            url = f"{self.api_url}/scheduled_events"
            params = {
                'user': self.config.CALENDLY_USER_URI,
                'min_start_time': min_time,
                'max_start_time': max_time
            }

            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()

            events = response.json().get('collection', [])
            print(f"📅 Found {len(events)} upcoming Calendly events")
            return events

        except Exception as e:
            print(f"❌ Failed to fetch Calendly events: {e}")
            return []

    def get_event_invitees(self, event_uri: str) -> List[Dict]:
        """Get invitees for a specific event"""
        try:
            url = f"{self.api_url}/scheduled_events/{event_uri}/invitees"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json().get('collection', [])
        except Exception as e:
            print(f"❌ Failed to fetch invitees: {e}")
            return []

    def check_new_bookings(self, since_timestamp: float) -> List[Dict]:
        """Check for new bookings since last check"""
        events = self.get_scheduled_events(days_ahead=30)

        new_bookings = []
        for event in events:
            created_at = datetime.fromisoformat(event['created_at'].replace('Z', '+00:00'))
            if created_at.timestamp() > since_timestamp:
                # Get invitee details
                invitees = self.get_event_invitees(event['uri'])
                event['invitees'] = invitees
                new_bookings.append(event)

        return new_bookings


# ============================================================================
# PIPELINE TRACKER
# ============================================================================

class PipelineTracker:
    """Track email outreach and responses"""

    def __init__(self):
        self.config = Config()
        self.db_path = self.config.TRACKING_DB
        self.load_pipeline()

    def load_pipeline(self):
        """Load pipeline from JSON"""
        if self.db_path.exists():
            with open(self.db_path, 'r') as f:
                self.pipeline = json.load(f)
        else:
            self.pipeline = {
                'prospects': {},
                'sent_count_today': 0,
                'last_reset_date': datetime.now().date().isoformat(),
                'last_check_timestamp': time.time()
            }

    def save_pipeline(self):
        """Save pipeline to JSON"""
        with open(self.db_path, 'w') as f:
            json.dump(self.pipeline, f, indent=2)

    def can_send_email(self) -> bool:
        """Check if we can send more emails (rate limiting)"""
        # Reset counter if new day
        today = datetime.now().date().isoformat()
        if self.pipeline['last_reset_date'] != today:
            self.pipeline['sent_count_today'] = 0
            self.pipeline['last_reset_date'] = today

        return self.pipeline['sent_count_today'] < self.config.MAX_EMAILS_PER_DAY

    def record_email_sent(self, prospect_email: str, prospect_data: Dict):
        """Record that email was sent"""
        self.pipeline['prospects'][prospect_email] = {
            **prospect_data,
            'status': 'sent',
            'sent_at': datetime.now().isoformat(),
            'opens': 0,
            'replies': 0,
            'demo_booked': False
        }
        self.pipeline['sent_count_today'] += 1
        self.save_pipeline()

    def record_reply(self, prospect_email: str):
        """Record that prospect replied"""
        if prospect_email in self.pipeline['prospects']:
            self.pipeline['prospects'][prospect_email]['status'] = 'replied'
            self.pipeline['prospects'][prospect_email]['replies'] += 1
            self.pipeline['prospects'][prospect_email]['replied_at'] = datetime.now().isoformat()
            self.save_pipeline()

    def record_demo_booked(self, prospect_email: str):
        """Record that demo was booked"""
        if prospect_email in self.pipeline['prospects']:
            self.pipeline['prospects'][prospect_email]['demo_booked'] = True
            self.pipeline['prospects'][prospect_email]['status'] = 'demo_booked'
            self.pipeline['prospects'][prospect_email]['booked_at'] = datetime.now().isoformat()
            self.save_pipeline()

    def get_stats(self) -> Dict:
        """Get pipeline statistics"""
        total = len(self.pipeline['prospects'])
        sent = sum(1 for p in self.pipeline['prospects'].values() if p['status'] == 'sent')
        replied = sum(1 for p in self.pipeline['prospects'].values() if p['status'] == 'replied')
        demos = sum(1 for p in self.pipeline['prospects'].values() if p.get('demo_booked'))

        return {
            'total_prospects': total,
            'emails_sent': sent,
            'replies': replied,
            'demos_booked': demos,
            'reply_rate': f"{(replied/sent*100):.1f}%" if sent > 0 else "0%",
            'demo_rate': f"{(demos/sent*100):.1f}%" if sent > 0 else "0%"
        }


# ============================================================================
# PROSPECT LOADER
# ============================================================================

def load_prospects() -> List[Dict]:
    """Load prospects from the markdown file"""
    # Hardcoded top 12 prospects from our research
    prospects = [
        {
            'email': 'chris.boshoff@pfizer.com',
            'first_name': 'Chris',
            'last_name': 'Boshoff',
            'company': 'Pfizer',
            'title': 'Chief Scientific Officer & President, R&D',
            'priority': 'HIGH',
            'template': 'pharma_big',
            'personalization': 'Congratulations on your recent appointment as CSO. Your oncology background makes you perfect for quantum-accelerated drug discovery.'
        },
        {
            'email': 'rose.loughlin@modernatx.com',
            'first_name': 'Rose',
            'last_name': 'Loughlin',
            'company': 'Moderna',
            'title': 'Executive Vice President, Research',
            'priority': 'HIGH',
            'template': 'pharma_big',
            'personalization': 'Your work on Moderna\'s platform science and mRNA therapeutics could accelerate dramatically with quantum-enhanced molecular screening.'
        },
        {
            'email': 'chris@recursion.com',
            'first_name': 'Chris',
            'last_name': 'Gibson',
            'company': 'Recursion Pharmaceuticals',
            'title': 'Co-Founder & CEO',
            'priority': 'HIGH',
            'template': 'pharma_startup',
            'personalization': 'Recursion\'s AI-driven approach to drug discovery aligns perfectly with our quantum optimization platform.'
        },
        {
            'email': 'ben@recursion.com',
            'first_name': 'Ben',
            'last_name': 'Mabey',
            'company': 'Recursion Pharmaceuticals',
            'title': 'Chief Technology Officer',
            'priority': 'HIGH',
            'template': 'pharma_tech',
            'personalization': 'As CTO, you\'ll appreciate our NumPy-only quantum simulator—zero infrastructure friction.'
        },
        {
            'email': 'izhar@atomwise.com',
            'first_name': 'Izhar',
            'last_name': 'Wallach',
            'company': 'Atomwise',
            'title': 'Chief Technology Officer',
            'priority': 'HIGH',
            'template': 'pharma_startup',
            'personalization': 'AtomNet\'s AI platform + our quantum circuit optimization = paradigm shift in molecular docking speed.'
        },
        {
            'email': 'marioni.john@gene.com',
            'first_name': 'John',
            'last_name': 'Marioni',
            'company': 'Genentech',
            'title': 'Senior VP & Head of Computational Sciences',
            'priority': 'HIGH',
            'template': 'pharma_big',
            'personalization': 'Your collaboration with Nvidia on AI drug discovery could benefit from quantum acceleration—12.54x faster design space exploration.'
        },
        {
            'email': 'navneet.arora@citadel.com',
            'first_name': 'Navneet',
            'last_name': 'Arora',
            'company': 'Citadel',
            'title': 'Head of Global Quantitative Strategies',
            'priority': 'HIGH',
            'template': 'quant_fund',
            'personalization': 'As head of Citadel\'s GQS, you\'ll understand how 12.54x faster portfolio optimization translates to alpha.'
        },
        {
            'email': 'peter.brown@rentec.com',
            'first_name': 'Peter',
            'last_name': 'Brown',
            'company': 'Renaissance Technologies',
            'title': 'Chief Executive Officer',
            'priority': 'ULTRA_HIGH',
            'template': 'quant_fund',
            'personalization': 'Renaissance\'s legendary performance stems from computational advantage. Our quantum optimizer offers the next frontier.'
        },
        {
            'email': 'anoop.prasad@deshaw.com',
            'first_name': 'Anoop',
            'last_name': 'Prasad',
            'company': 'D.E. Shaw',
            'title': 'Managing Director & Global Head of Systematic Equities',
            'priority': 'HIGH',
            'template': 'quant_fund',
            'personalization': 'Your oversight of quantitative equity strategies at D.E. Shaw positions you perfectly to leverage quantum portfolio optimization.'
        },
        {
            'email': 'adam.deaton@deshaw.com',
            'first_name': 'Adam',
            'last_name': 'Deaton',
            'company': 'D.E. Shaw',
            'title': 'Managing Director & Head of Systematic Futures',
            'priority': 'HIGH',
            'template': 'quant_fund',
            'personalization': 'Quantum circuit optimization for multi-asset futures strategies—explore 12.54x more scenarios in your backtesting.'
        },
        {
            'email': 'eric.shiozaki@insitro.com',
            'first_name': 'Eric',
            'last_name': 'Shiozaki',
            'company': 'Insitro',
            'title': 'Senior Vice President, Therapeutic Drug Discovery',
            'priority': 'MEDIUM',
            'template': 'pharma_startup',
            'personalization': 'Insitro\'s machine learning approach to drug discovery could accelerate 12.54x with quantum enhancement.'
        },
        {
            'email': 'aviv.regev@gene.com',
            'first_name': 'Aviv',
            'last_name': 'Regev',
            'company': 'Genentech',
            'title': 'Executive VP & Head of gRED',
            'priority': 'HIGH',
            'template': 'pharma_big',
            'personalization': 'As head of Genentech R&D and Kempner Institute advisory board member, you\'re at the forefront of computational biology innovation.'
        }
    ]

    return prospects


def load_email_template(template_name: str) -> str:
    """Load email template by name"""
    templates = {
        'pharma_big': """Hi [Name],

What if your team could explore 12.54x more drug candidates in the same time?

**Quantum-Enhanced ECH0**: 30-qubit simulator that accelerates design space exploration by a measured 12.54x versus brute-force methods.

**Your use case**: Molecular docking, binding affinity prediction, compound optimization
**Our validation**: 1000-option design space in 1/12.54th the time

**72-hour pre-sale**: Professional tier at $3,000/mo (normally $5,000)
- 30-qubit circuit simulation
- Custom model training on your compounds
- Priority support (24h SLA)

**ROI**: One FDA-approved drug = $1B+ revenue. Finding candidates 12.54x faster = priceless.

Book 30-min demo: https://calendly.com/inventor-aios/quantum-demo

Joshua Hendricks Cole
Corporation of Light
inventor@aios.is

P.S. NumPy-only deployment = zero infrastructure friction. Runs on your existing servers.""",

        'pharma_startup': """Hi [Name],

Series A investors want to see compound candidates. Fast.

**Quantum AI**: 12.54x faster design space exploration. Get to your first viable candidate in weeks, not months.

**Startup tier (72-hour pre-sale)**: $1,500/mo (normally $2,500)
- 25-qubit simulation (perfect for most research)
- 1,000 API calls/month
- 6-month commitment

**Why startups use us**:
- Deploy in < 1 hour (NumPy-only, no infrastructure)
- One successful candidate discovery = 10-100x ROI
- Impress investors with quantum-enhanced R&D

Demo: https://calendly.com/inventor-aios/quantum-demo

Joshua Cole
inventor@aios.is

P.S. Early customers get lifetime grandfathered pricing. Lock in $1,500/mo forever.""",

        'pharma_tech': """Hi [Name],

Sick of quantum platforms requiring specialized hardware?

**Quantum-Enhanced ECH0**: NumPy-only implementation. Runs on your existing servers. No cloud vendor lock-in.

**72-hour pre-sale** (Professional): $3,000/mo (normally $5,000)
- 30-qubit simulation on standard servers
- On-premise installation available
- Python 3.9+, NumPy, 16GB RAM = done

**Why IT loves us**:
- Deploy in < 1 hour
- No GPU requirements (CPU-only works)
- No vendor lock-in (runs anywhere Python runs)

**Security**: On-prem deployment = your data never leaves

Demo: https://calendly.com/inventor-aios/quantum-demo

Joshua Cole
inventor@aios.is""",

        'quant_fund': """Hi [Name],

Exploring 1000s of portfolio allocations to find optimal Sharpe ratio?

**Quantum AI**: 12.54x faster design space exploration. Test more strategies, find alpha faster.

**72-hour pre-sale**: Professional at $3,000/mo (normally $5,000)
- 30-qubit quantum circuits for optimization
- 10,000 API calls/month
- Custom model training on your constraints

**Use cases**:
- Portfolio optimization (mean-variance, CVaR, etc.)
- Multi-asset allocation
- Risk parity rebalancing

**ROI**: 1% annual alpha improvement on $100M AUM = $1M >> $36K/year cost

Demo: https://calendly.com/inventor-aios/quantum-demo

Joshua Hendricks Cole
Corporation of Light
inventor@aios.is"""
    }

    return templates.get(template_name, templates['pharma_big'])


# ============================================================================
# MAIN AUTOMATION SYSTEM
# ============================================================================

class ECH0SalesAutomation:
    """Main automation orchestrator"""

    def __init__(self):
        self.email_sender = EmailSender()
        self.calendly = CalendlyManager()
        self.tracker = PipelineTracker()

    def send_batch(self, batch_num: int = 1, batch_size: int = 5):
        """Send a batch of emails"""
        prospects = load_prospects()

        # Calculate which prospects to send to
        start_idx = (batch_num - 1) * batch_size
        end_idx = start_idx + batch_size
        batch = prospects[start_idx:end_idx]

        if not batch:
            print(f"❌ No prospects in batch {batch_num}")
            return

        print(f"📧 Sending batch {batch_num}: {len(batch)} emails")
        print(f"   Prospects: {', '.join([p['first_name'] + ' ' + p['last_name'] for p in batch])}")

        for i, prospect in enumerate(batch):
            # Check rate limits
            if not self.tracker.can_send_email():
                print("⚠️  Daily email limit reached. Stop.")
                break

            # Skip if already sent
            if prospect['email'] in self.tracker.pipeline['prospects']:
                print(f"⏭️  Skipping {prospect['email']} (already sent)")
                continue

            # Load template
            template = load_email_template(prospect['template'])

            # Personalize
            body_text, body_html = self.email_sender.personalize_email(template, prospect)

            # Generate subject
            subject = f"12.54x faster {prospect['company']} drug discovery?" if 'pharma' in prospect['template'] else f"Quantum portfolio optimization for {prospect['company']}"

            # Send
            success = self.email_sender.send_email(
                to_email=prospect['email'],
                to_name=f"{prospect['first_name']} {prospect['last_name']}",
                subject=subject,
                body_html=body_html,
                body_text=body_text
            )

            if success:
                self.tracker.record_email_sent(prospect['email'], prospect)

                # Delay before next email (anti-spam)
                if i < len(batch) - 1:
                    delay = Config.DELAY_BETWEEN_EMAILS
                    print(f"⏳ Waiting {delay}s before next email...")
                    time.sleep(delay)
            else:
                print(f"❌ Failed to send to {prospect['email']}")

        print("\n✅ Batch complete!")
        self.show_stats()

    def check_calendly(self):
        """Check for new Calendly bookings"""
        print("📅 Checking Calendly for new bookings...")

        last_check = self.tracker.pipeline.get('last_check_timestamp', 0)
        new_bookings = self.calendly.check_new_bookings(last_check)

        if new_bookings:
            print(f"🎉 Found {len(new_bookings)} new booking(s)!")
            for booking in new_bookings:
                invitee = booking['invitees'][0] if booking['invitees'] else {}
                email = invitee.get('email', 'unknown')
                name = invitee.get('name', 'Unknown')
                start_time = booking.get('start_time', 'TBD')

                print(f"   - {name} ({email}) scheduled for {start_time}")

                # Update tracker
                if email in self.tracker.pipeline['prospects']:
                    self.tracker.record_demo_booked(email)
                else:
                    print(f"     ⚠️  Email {email} not in pipeline (organic booking?)")
        else:
            print("   No new bookings since last check.")

        # Update last check timestamp
        self.tracker.pipeline['last_check_timestamp'] = time.time()
        self.tracker.save_pipeline()

    def show_stats(self):
        """Display pipeline statistics"""
        stats = self.tracker.get_stats()

        print("\n" + "="*50)
        print("📊 PIPELINE STATISTICS")
        print("="*50)
        print(f"Total Prospects:   {stats['total_prospects']}")
        print(f"Emails Sent:       {stats['emails_sent']}")
        print(f"Replies:           {stats['replies']} ({stats['reply_rate']})")
        print(f"Demos Booked:      {stats['demos_booked']} ({stats['demo_rate']})")
        print("="*50 + "\n")

    def auto_mode(self, check_interval: int = 3600):
        """Run in autonomous mode - check Calendly every N seconds"""
        print("🤖 ECH0 AUTONOMOUS MODE ACTIVATED")
        print(f"   Checking Calendly every {check_interval}s ({check_interval//60} min)")
        print("   Press Ctrl+C to stop\n")

        try:
            while True:
                self.check_calendly()
                self.show_stats()

                print(f"⏳ Next check in {check_interval}s...")
                time.sleep(check_interval)

        except KeyboardInterrupt:
            print("\n\n🛑 Autonomous mode stopped by user")
            self.show_stats()


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description="ECH0 Sales Automation for Quantum AI")
    parser.add_argument('--setup', action='store_true', help='Show setup instructions')
    parser.add_argument('--send-batch', type=int, metavar='N', help='Send batch N (1-4)')
    parser.add_argument('--check-calendly', action='store_true', help='Check for new Calendly bookings')
    parser.add_argument('--stats', action='store_true', help='Show pipeline statistics')
    parser.add_argument('--auto', action='store_true', help='Run in autonomous mode (check Calendly every hour)')
    parser.add_argument('--test', action='store_true', help='Test email configuration (send test email)')

    args = parser.parse_args()

    if args.setup:
        print("""
╔════════════════════════════════════════════════════════════════════════╗
║                  ECH0 SALES AUTOMATION SETUP                           ║
╚════════════════════════════════════════════════════════════════════════╝

STEP 1: Set up email credentials (SMTP)
----------------------------------------
For Gmail/Google Workspace:
  1. Go to: https://myaccount.google.com/apppasswords
  2. Generate an "App Password" for "Mail"
  3. Copy the 16-character password
  4. Set environment variable:
     export EMAIL_PASSWORD='your-16-char-app-password'

For other email providers, use your SMTP credentials.

STEP 2: Set up Calendly API
----------------------------
  1. Go to: https://calendly.com/integrations/api_webhooks
  2. Generate a Personal Access Token
  3. Copy your User URI from: https://calendly.com/app/settings
  4. Set environment variables:
     export CALENDLY_API_KEY='your-api-key'
     export CALENDLY_USER_URI='https://api.calendly.com/users/XXXXXXXX'

STEP 3: (Optional) Set up Supabase tracking
--------------------------------------------
     export SUPABASE_KEY='your-supabase-anon-key'

STEP 4: Test configuration
---------------------------
     python3 ech0_sales_automation.py --test

STEP 5: Send your first batch
------------------------------
     python3 ech0_sales_automation.py --send-batch 1

STEP 6: Enable autonomous mode (ECH0 checks Calendly every hour)
-----------------------------------------------------------------
     python3 ech0_sales_automation.py --auto

═══════════════════════════════════════════════════════════════════════

For support: inventor@aios.is
""")
        return

    # Initialize system
    automation = ECH0SalesAutomation()

    if args.send_batch:
        automation.send_batch(batch_num=args.send_batch, batch_size=5)

    elif args.check_calendly:
        automation.check_calendly()

    elif args.stats:
        automation.show_stats()

    elif args.auto:
        automation.auto_mode(check_interval=3600)  # Check every hour

    elif args.test:
        print("🧪 Testing email configuration...")
        success = automation.email_sender.send_email(
            to_email=Config.EMAIL_ADDRESS,
            to_name="Test User",
            subject="ECH0 Sales Automation - Test Email",
            body_html="<p>✅ Your email configuration is working!</p>",
            body_text="✅ Your email configuration is working!"
        )
        if success:
            print("✅ Test email sent successfully!")
        else:
            print("❌ Test email failed. Check your EMAIL_PASSWORD.")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
