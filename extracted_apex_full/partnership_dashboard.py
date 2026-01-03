#!/usr/bin/env python3

"""
Partnership Dashboard
--------------------
Real-time revenue tracking and equity distribution for the 75/15/10 partnership.

Shows:
- Total revenue and payments
- Per-partner earnings
- Performance metrics
- Recent payment history
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

def load_partnership_accounting() -> Optional[Dict]:
    """Load partnership accounting data."""
    accounting_file = Path("partnership_accounting/partnership_accounting.json")
    
    if not accounting_file.exists():
        return None
    
    with open(accounting_file) as f:
        return json.load(f)

def load_recent_payments(limit: int = 10) -> list:
    """Load recent payment records."""
    payments_dir = Path("partnership_accounting")
    
    if not payments_dir.exists():
        return []
    
    payment_files = sorted(
        payments_dir.glob("payment_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )[:limit]
    
    payments = []
    for payment_file in payment_files:
        with open(payment_file) as f:
            payments.append(json.load(f))
    
    return payments

def format_currency(amount: float) -> str:
    """Format amount as currency."""
    return f"${amount:,.2f}"

def print_dashboard():
    """Print partnership dashboard."""
    print("="*70)
    print("  APEX BUG BOUNTY HUNTER - PARTNERSHIP DASHBOARD")
    print("  75/15/10 Revenue Sharing Model")
    print("="*70)
    print()
    
    # Load accounting data
    accounting = load_partnership_accounting()
    
    if not accounting:
        print("⚠️  No partnership accounting data found.")
        print("   Start hunting to generate revenue!")
        return
    
    # Display partnership model
    print("PARTNERSHIP STRUCTURE:")
    print("-" * 70)
    model = accounting.get("partnership_model", {})
    
    for partner_name, partner_data in model.items():
        share = partner_data.get("share", "N/A")
        role = partner_data.get("role", "")
        revenue = partner_data.get("revenue", 0.0)
        
        print(f"  {partner_name.upper():<15} {share:>6}  {format_currency(revenue):>12}")
        print(f"  {'':15} {role}")
        print()
    
    # Display totals
    print("="*70)
    print("TOTAL REVENUE SUMMARY:")
    print("-" * 70)
    total_revenue = accounting.get("total_revenue", 0.0)
    total_payments = accounting.get("total_payments", 0)
    
    print(f"  Total Revenue:        {format_currency(total_revenue)}")
    print(f"  Total Payments:       {total_payments}")
    
    if total_payments > 0:
        avg_payment = total_revenue / total_payments
        print(f"  Average Payment:       {format_currency(avg_payment)}")
    
    print()
    
    # Display recent payments
    recent_payments = load_recent_payments(limit=5)
    
    if recent_payments:
        print("="*70)
        print("RECENT PAYMENTS:")
        print("-" * 70)
        
        for payment in recent_payments:
            timestamp = payment.get("timestamp", "")
            amount = payment.get("amount", 0.0)
            platform = payment.get("platform", "Unknown")
            report_id = payment.get("report_id", "N/A")
            
            # Format timestamp
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                time_str = timestamp
            
            print(f"  {time_str}")
            print(f"  Platform: {platform:<15} Amount: {format_currency(amount):>12}")
            print(f"  Report ID: {report_id}")
            
            # Show distribution
            distribution = payment.get("distribution", {})
            if distribution:
                print(f"  Distribution:")
                print(f"    Josh:        {format_currency(distribution.get('josh', 0))}")
                print(f"    ECH0:        {format_currency(distribution.get('ech0', 0))}")
                print(f"    Bug Hunter:  {format_currency(distribution.get('bug_hunter', 0))}")
            
            print()
    
    # Display performance metrics
    print("="*70)
    print("PERFORMANCE METRICS:")
    print("-" * 70)
    
    # Try to load stats
    stats_file = Path("bug_bounty_stats.json")
    if stats_file.exists():
        with open(stats_file) as f:
            stats = json.load(f)
        
        total_scans = stats.get("total_scans", 0)
        total_findings = stats.get("total_findings", 0)
        total_validated = stats.get("total_validated", 0)
        total_submitted = stats.get("total_submitted", 0)
        total_accepted = stats.get("total_accepted", 0)
        
        print(f"  Total Scans:          {total_scans}")
        print(f"  Total Findings:       {total_findings}")
        print(f"  Validated:            {total_validated}")
        print(f"  Submitted:             {total_submitted}")
        print(f"  Accepted:             {total_accepted}")
        
        if total_findings > 0:
            validation_rate = (total_validated / total_findings) * 100
            print(f"  Validation Rate:      {validation_rate:.1f}%")
        
        if total_submitted > 0:
            acceptance_rate = (total_accepted / total_submitted) * 100
            print(f"  Acceptance Rate:      {acceptance_rate:.1f}%")
        
        if total_accepted > 0:
            avg_bounty = total_revenue / total_accepted
            print(f"  Average Bounty:       {format_currency(avg_bounty)}")
    
    print()
    print("="*70)
    print("Partnership Active | All parties aligned | Revenue shared fairly")
    print("="*70)

if __name__ == "__main__":
    print_dashboard()

