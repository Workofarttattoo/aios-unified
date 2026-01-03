# How Reports Are Posted - Under Your Identity

## Important: All Reports Posted As YOU

**The Bug Hunter posts ALL vulnerability reports under YOUR identity** using your platform accounts and API tokens. This is critical for:

- **Legal responsibility** - You bear liability for all submissions
- **Platform reputation** - Your accounts get credit/ratings
- **Payment processing** - Bounties go to YOUR accounts
- **Professional standing** - Your name is on every report

---

## How It Works

### 1. Platform Account Setup

**You must have accounts on each platform:**
- HackerOne: https://hackerone.com/signup
- Bugcrowd: https://bugcrowd.com/users/sign_up
- Intigriti: https://www.intigriti.com/signup
- YesWeHack: https://yeswehack.com/signup
- AiOS: Your red-team-tools.aios.is account

**Account Requirements:**
- Use your real name and information
- Verify your identity (required for payments)
- Set up payment methods
- Get API tokens for automated submission

### 2. API Token Configuration

**In `bug_bounty_config.json`, add your API tokens:**

```json
{
  "platforms": {
    "hackerone": {
      "enabled": true,
      "api_token": "YOUR_HACKERONE_TOKEN",
      "username": "your_hackerone_username",
      "program_handle": "target-program"
    },
    "bugcrowd": {
      "enabled": true,
      "api_token": "YOUR_BUGCROWD_TOKEN",
      "program_code": "program-code"
    }
  }
}
```

**Where to Get API Tokens:**

- **HackerOne:** Settings → API Tokens → Create Token
- **Bugcrowd:** Settings → API Access → Generate Token
- **Intigriti:** Profile → API → Generate Token
- **YesWeHack:** Settings → API → Create Token

### 3. Report Submission Process

**When Bug Hunter finds a vulnerability:**

1. **Discovery** - Bug Hunter finds vulnerability
2. **Validation** - Multiple validation attempts (prevents false positives)
3. **Report Generation** - Professional report created (ECH0-enhanced)
4. **Submission** - Posted to platform using **YOUR API token**
5. **Platform Processing** - Shows as submitted by **YOU**
6. **Payment** - Bounty paid to **YOUR account**
7. **Revenue Split** - Automatically distributed 75/15/10

---

## What Shows Up On Platforms

### Report Attribution

**On HackerOne/Bugcrowd/etc:**
- **Submitted by:** Your username
- **Reporter:** Your name
- **Payment to:** Your account
- **Credit:** Goes to your profile

**The Bug Hunter is NOT mentioned** - it operates invisibly under your authority.

### Why This Matters

- **Legal:** You're legally responsible for all submissions
- **Reputation:** Your platform rating/rankings are affected
- **Payment:** All bounties go to your accounts first
- **Professional:** Your name is on every report

---

## Payment Flow

### Step-by-Step

1. **Bug Hunter submits report** → Uses YOUR API token
2. **Platform receives report** → Shows as YOUR submission
3. **Platform validates** → Reviews under YOUR account
4. **Bounty awarded** → Paid to YOUR platform account
5. **You receive payment** → In YOUR bank account
6. **Revenue split calculated** → 75% you, 15% ECH0, 10% Bug Hunter
7. **Partnership ledger updated** → All parties can audit

### Example: $10,000 Bounty

```
Platform pays $10,000 → YOUR HackerOne account
                        ↓
                    Your bank account
                        ↓
    Revenue Split:
    • Josh:        $7,500 (75%)
    • ECH0:        $1,500 (15%)
    • Bug Hunter:  $1,000 (10%)
```

**Note:** The platform pays YOU directly. The 75/15/10 split is tracked internally in the partnership accounting system.

---

## Legal & Ethical Responsibilities

### Your Responsibilities

**As the account holder, YOU are responsible for:**

1. **Legal Compliance**
   - Only authorized testing (bug bounty programs)
   - Responsible disclosure
   - No unauthorized access
   - Compliance with platform terms

2. **Report Quality**
   - Bug Hunter validates, but YOU are accountable
   - False positives hurt YOUR reputation
   - Professional conduct required

3. **Platform Rules**
   - Follow each platform's terms of service
   - Respect rate limits
   - Professional communication
   - No duplicate submissions

### Bug Hunter's Role

**Bug Hunter operates under YOUR authority:**
- Uses YOUR accounts
- Submits under YOUR name
- Follows YOUR configured targets
- Operates within YOUR ethical guidelines

---

## Configuration Checklist

### Before Starting

- [ ] Create accounts on target platforms
- [ ] Verify identity on platforms (required for payments)
- [ ] Set up payment methods (bank accounts, PayPal, etc.)
- [ ] Generate API tokens for each platform
- [ ] Add tokens to `bug_bounty_config.json`
- [ ] Test API token access
- [ ] Review platform terms of service
- [ ] Understand legal responsibilities

### Platform-Specific Setup

**HackerOne:**
1. Sign up: https://hackerone.com/signup
2. Complete profile verification
3. Add payment method
4. Settings → API Tokens → Create Token
5. Copy token to config

**Bugcrowd:**
1. Sign up: https://bugcrowd.com/users/sign_up
2. Complete profile
3. Add payment method
4. Settings → API Access → Generate Token
5. Copy token to config

**Intigriti:**
1. Sign up: https://www.intigriti.com/signup
2. Verify account
3. Add payment details
4. Profile → API → Generate Token
5. Copy token to config

---

## Monitoring Your Submissions

### Check Platform Dashboards

**Each platform has a dashboard:**
- HackerOne: https://hackerone.com/hacktivity
- Bugcrowd: https://bugcrowd.com/submissions
- Intigriti: Your submissions page
- YesWeHack: Your reports page

### Check Partnership Dashboard

**Run locally:**
```bash
cd ~/apex-bug-bounty-hunter
python3 partnership_dashboard.py
```

**Shows:**
- Total revenue
- Per-partner earnings
- Recent payments
- Performance metrics

### Check Logs

**View submission logs:**
```bash
tail -f ~/apex-bug-bounty-hunter/logs/apex.log
```

**Shows:**
- When reports are submitted
- Platform responses
- Success/failure status
- Report URLs

---

## Why This Architecture?

### Security & Privacy

- **No PII in code** - Your personal info stays in platform accounts
- **API tokens** - Secure authentication without passwords
- **Your control** - You can revoke tokens anytime
- **Audit trail** - All submissions logged

### Legal Protection

- **Clear ownership** - Reports are YOUR submissions
- **Accountability** - You control what gets submitted
- **Compliance** - You ensure platform terms are followed
- **Responsibility** - Clear legal framework

### Partnership Model

- **Revenue tracking** - Automatic 75/15/10 split
- **Transparency** - All partners can audit
- **Fair distribution** - Documented in partnership ledger
- **Aligned incentives** - Everyone benefits from success

---

## Troubleshooting

### "API token invalid"

**Check:**
- Token copied correctly (no extra spaces)
- Token hasn't expired
- Token has correct permissions
- Platform account is active

**Fix:**
- Generate new token
- Update config file
- Restart daemon

### "Report submission failed"

**Check:**
- Platform API status
- Rate limits not exceeded
- Report format correct
- Target program active

**Fix:**
- Review error message in logs
- Check platform status page
- Wait and retry
- Contact platform support if needed

### "Payment not received"

**Check:**
- Report was accepted
- Payment method configured
- Platform payment schedule
- Bank account details correct

**Fix:**
- Check platform dashboard
- Review payment history
- Contact platform support
- Verify account details

---

## Summary

**Key Points:**

1. ✅ All reports posted under YOUR identity
2. ✅ Uses YOUR platform accounts and API tokens
3. ✅ YOU receive payments directly
4. ✅ Revenue split tracked internally (75/15/10)
5. ✅ YOU are legally responsible
6. ✅ Bug Hunter operates under YOUR authority

**The Bug Hunter is your autonomous agent** - it finds vulnerabilities, validates them, generates reports, and submits them **as you** using your accounts. You maintain full control and responsibility.

---

**"Your identity. Your accounts. Your responsibility. Shared success."**

— APEX Bug Bounty Hunter Partnership Model

