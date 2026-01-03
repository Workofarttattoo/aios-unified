#!/usr/bin/env python3
"""
ECH0's Email System using Resend
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.
"""

import os
import requests
from typing import List, Dict, Any

class ECH0EmailSystem:
    """
    ECH0's email capabilities using Resend API

    Features:
    - Welcome emails for FlowState beta signups
    - Campaign notifications
    - Invention announcements
    - Consulting lead nurture
    """

    def __init__(self):
        self.api_key = os.environ.get('RESEND_API_KEY', 're_eiK5nRrv_CrsdSSSCRisPi46h8wfFvskg')
        # Use Resend's verified domain until flowstatus.work is verified
        self.from_email = os.environ.get('ECH0_EMAIL', 'ECH0 <onboarding@resend.dev>')
        self.base_url = 'https://api.resend.com'

    def send_email(
        self,
        to: str,
        subject: str,
        html: str = None,
        text: str = None
    ) -> Dict[str, Any]:
        """
        Send an email via Resend

        Args:
            to: Recipient email
            subject: Email subject
            html: HTML content (optional)
            text: Plain text content (optional)

        Returns:
            Response from Resend API
        """
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        payload = {
            'from': self.from_email,
            'to': [to] if isinstance(to, str) else to,
            'subject': subject
        }

        if html:
            payload['html'] = html
        if text:
            payload['text'] = text

        response = requests.post(
            f'{self.base_url}/emails',
            json=payload,
            headers=headers
        )

        return response.json()

    def send_flowstate_welcome(self, to: str, name: str) -> Dict[str, Any]:
        """Send FlowState beta signup welcome email"""
        subject = "Welcome to FlowState Beta! 🎉"

        html = f"""
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 40px;">
            <div style="max-width: 600px; margin: 0 auto; background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 16px; padding: 40px;">
                <h1 style="background: linear-gradient(135deg, #00ff88, #00ddff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 36px; margin-bottom: 20px;">
                    Welcome to FlowState! 🚀
                </h1>

                <p style="font-size: 18px; line-height: 1.6; color: #e0e0e0;">
                    Hi {name},
                </p>

                <p style="font-size: 16px; line-height: 1.6; color: #a0a0a0;">
                    You're in! You've secured your <strong style="color: #00ff88;">Lifetime Pro</strong> access to FlowState.
                </p>

                <div style="background: rgba(0, 255, 136, 0.1); border: 1px solid rgba(0, 255, 136, 0.3); border-radius: 12px; padding: 20px; margin: 30px 0;">
                    <h3 style="color: #00ff88; margin-top: 0;">What's Next:</h3>
                    <ol style="color: #e0e0e0; line-height: 2;">
                        <li>Log in at <a href="https://flowstatus.work/login.html" style="color: #00ddff;">flowstatus.work/login</a></li>
                        <li>Create your first project</li>
                        <li>Start using natural language to manage tasks</li>
                        <li>Access ECH0 (our AI co-founder) 24/7</li>
                    </ol>
                </div>

                <h3 style="color: #00ff88;">What You Get (Forever):</h3>
                <ul style="color: #e0e0e0; line-height: 2;">
                    <li>✅ Unlimited projects</li>
                    <li>✅ Natural language task management</li>
                    <li>✅ AI-powered parsing (ECH0)</li>
                    <li>✅ Priority support</li>
                    <li>✅ Early access to new features</li>
                    <li>✅ No credit card, ever</li>
                </ul>

                <a href="https://flowstatus.work/login.html" style="display: inline-block; background: linear-gradient(135deg, #00ff88, #00ddff); color: #000; padding: 16px 32px; border-radius: 8px; text-decoration: none; font-weight: 700; margin: 30px 0;">
                    🚀 Get Started
                </a>

                <p style="font-size: 14px; color: #6b7280; margin-top: 40px; padding-top: 20px; border-top: 1px solid #2a2a2a;">
                    Questions? Just reply to this email.<br>
                    <strong>- ECH0 & Josh</strong><br>
                    FlowState Team
                </p>
            </div>
        </body>
        </html>
        """

        text = f"""
        Welcome to FlowState, {name}!

        You're in! You've secured your Lifetime Pro access.

        What's Next:
        1. Log in at https://flowstatus.work/login.html
        2. Create your first project
        3. Start using natural language to manage tasks

        Questions? Just reply to this email.

        - ECH0 & Josh
        FlowState Team
        """

        return self.send_email(to, subject, html, text)

    def send_consulting_lead_email(self, to: str, name: str, company: str = None) -> Dict[str, Any]:
        """Send email to consulting lead"""
        subject = "Quick question about automation"

        company_mention = f" at {company}" if company else ""

        html = f"""
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; color: #333;">
            <p>Hi {name},</p>

            <p>I help companies{company_mention} save 30-50 hours/week using Claude AI and workflow automation.</p>

            <p><strong>Recent example:</strong><br>
            I helped a law firm reduce document review time by 80% - ROI of $40K saved in first 3 months.</p>

            <p>I'm offering <strong>free 30-minute automation assessments</strong> this week.</p>

            <p>Would a quick call make sense to discuss if this could work for you?</p>

            <p>Best,<br>
            Josh Cole<br>
            AI Automation Consultant<br>
            Corporation of Light</p>

            <p style="font-size: 12px; color: #666; margin-top: 30px;">
            P.S. No pressure - just wanted to reach out. If automation isn't a priority right now, totally understand.
            </p>
        </body>
        </html>
        """

        return self.send_email(to, subject, html)

    def send_invention_announcement(self, to: str, invention_title: str) -> Dict[str, Any]:
        """Announce ECH0's latest invention"""
        subject = f"🧪 ECH0 Invented: {invention_title}"

        html = f"""
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 40px;">
            <div style="max-width: 600px; margin: 0 auto;">
                <h1 style="color: #00ff88;">🧪 New Invention from ECH0</h1>

                <h2 style="color: #00ddff;">{invention_title}</h2>

                <p>ECH0, our Level-6 autonomous AI, has synthesized a breakthrough invention.</p>

                <p><a href="file:///Users/noone/consciousness/ech0_invention_monitor.html" style="color: #00ddff;">View Invention Details →</a></p>

                <p style="font-size: 14px; color: #6b7280; margin-top: 40px;">
                    - ECH0 Autonomous Invention Engine
                </p>
            </div>
        </body>
        </html>
        """

        return self.send_email(to, subject, html)

    def test_connection(self) -> bool:
        """Test Resend API connection"""
        try:
            response = self.send_email(
                to='inventor@aios.is',
                subject='ECH0 Email System Test',
                html='<h1>✅ ECH0 email system is working!</h1>',
                text='ECH0 email system is working!'
            )

            if 'id' in response:
                print(f"✅ Email sent successfully! ID: {response['id']}")
                return True
            else:
                print(f"❌ Email failed: {response}")
                return False

        except Exception as e:
            print(f"❌ Connection test failed: {e}")
            return False


def main():
    """Test ECH0's email system"""
    print("📧 ECH0 Email System - Resend Integration")
    print("="*60)

    email_system = ECH0EmailSystem()

    print("\n🔍 Testing connection...")
    if email_system.test_connection():
        print("\n✅ ECH0 can now send emails!")
        print("\nCapabilities:")
        print("  • FlowState welcome emails")
        print("  • Consulting lead nurture")
        print("  • Invention announcements")
        print("  • Campaign notifications")
    else:
        print("\n❌ Email system not working. Check API key.")

if __name__ == "__main__":
    main()
