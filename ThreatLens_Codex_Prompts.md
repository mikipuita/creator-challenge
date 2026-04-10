# 🔒 ThreatLens — Codex Prompt Suite

> **How to use this:** Feed each prompt to OpenAI Codex **in order**. Each prompt builds on the previous one. Wait for Codex to finish before moving to the next. Copy-paste the entire block — the structure is intentional.

---

## PROMPT 1 — Project Scaffold & Backend Core

```
Create a full-stack web application called "ThreatLens" — an AI-powered attack surface monitor for small businesses.

## Tech Stack
- **Backend:** Python 3.12 + FastAPI
- **Frontend:** Next.js 14 (App Router) + TypeScript + Tailwind CSS
- **AI:** OpenAI API (gpt-4o) for natural-language report generation
- **Deployment-ready:** Docker Compose with separate frontend/backend services

## Project Structure
```
threatlens/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app entry point
│   │   ├── config.py            # Settings via pydantic-settings (OPENAI_API_KEY, SHODAN_API_KEY)
│   │   ├── routers/
│   │   │   ├── scan.py          # POST /api/scan — accepts {domain: string}, returns scan_id
│   │   │   ├── results.py       # GET /api/results/{scan_id} — returns scan results
│   │   │   └── report.py        # GET /api/report/{scan_id}/pdf — returns PDF download
│   │   ├── services/
│   │   │   ├── dns_recon.py     # DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA)
│   │   │   ├── subdomain_enum.py # Passive subdomain discovery via crt.sh API
│   │   │   ├── ssl_check.py     # TLS/SSL certificate analysis (expiry, issuer, SANs, protocol version)
│   │   │   ├── email_security.py # SPF, DKIM, DMARC record parsing and validation
│   │   │   ├── header_analysis.py # HTTP security headers check (CSP, HSTS, X-Frame, etc.)
│   │   │   ├── port_scan.py     # Shodan API integration for open port enumeration
│   │   │   ├── tech_fingerprint.py # Technology stack detection from headers & response
│   │   │   ├── risk_scorer.py   # Aggregates all findings into a weighted risk score (A-F letter grade)
│   │   │   └── ai_reporter.py   # Sends findings to OpenAI API, returns plain-English report
│   │   ├── models/
│   │   │   ├── scan.py          # Pydantic models: ScanRequest, ScanResult, Finding, RiskScore
│   │   │   └── report.py        # Pydantic models: ReportSection, FullReport
│   │   └── utils/
│   │       ├── pdf_generator.py # Generates branded PDF report from FullReport model
│   │       └── helpers.py       # Domain validation, rate limiting helpers
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── ... (Next.js scaffold)
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

## Backend Implementation Details

### main.py
- FastAPI app with CORS middleware (allow all origins for demo)
- Include all routers under /api prefix
- Add a health check endpoint at GET /api/health
- Use background tasks for scan execution

### Scan Flow (scan.py router)
1. Validate domain input (reject IPs, localhost, internal ranges)
2. Generate UUID scan_id
3. Kick off background task that runs ALL recon modules in parallel using asyncio.gather()
4. Store results in an in-memory dict (keyed by scan_id) — no database needed
5. Return {scan_id, status: "scanning"} immediately

### DNS Recon (dns_recon.py)
- Use the `dns.resolver` library (dnspython)
- Query: A, AAAA, MX, TXT, NS, CNAME, SOA records
- Return structured list of findings with record type, value, and any anomalies
- Flag: missing expected records, dangling CNAMEs, wildcard DNS

### Subdomain Enumeration (subdomain_enum.py)
- Query crt.sh: GET https://crt.sh/?q=%25.{domain}&output=json
- Deduplicate and clean results
- Return list of discovered subdomains with first/last seen dates
- Flag: unexpected subdomains, expired cert references

### SSL/TLS Check (ssl_check.py)
- Use Python `ssl` and `socket` modules to connect on port 443
- Extract: certificate expiry date, issuer, subject, SANs, protocol version
- Flag: expired certs, self-signed certs, weak protocols (TLS 1.0/1.1), cert-domain mismatch
- Calculate days until expiry

### Email Security (email_security.py)
- Parse SPF record from TXT records: check for ~all vs -all vs ?all
- Check for DMARC record at _dmarc.{domain}: parse policy (none/quarantine/reject)
- Check for DKIM selector (try common selectors: default, google, selector1, selector2)
- Each check returns: present (bool), record_value, policy, risk_level, explanation

### HTTP Security Headers (header_analysis.py)
- Send GET request to https://{domain} and http://{domain}
- Check for presence and values of:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Content-Type-Options
  - X-Frame-Options
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy
- Check for HTTP→HTTPS redirect
- Flag each missing header with severity and explanation

### Port Scan (port_scan.py)
- If SHODAN_API_KEY is set: query Shodan API for host info
- If no Shodan key: skip gracefully, return empty with note
- Parse: open ports, services, banners, known vulns
- Flag: unexpected open ports (telnet, FTP, RDP, SMB exposed to internet)

### Tech Fingerprint (tech_fingerprint.py)
- Parse HTTP response headers: Server, X-Powered-By, X-Generator, etc.
- Check HTML meta tags and common file paths (/wp-admin, /wp-login, etc.)
- Identify: web server (nginx/apache/IIS), CMS (WordPress/Drupal), frameworks, CDN
- Flag: outdated server versions if detectable

### Risk Scorer (risk_scorer.py)
- Weight categories: Email Security (25%), SSL/TLS (20%), Headers (20%), Open Ports (15%), DNS (10%), Tech Stack (10%)
- Each category scores 0-100
- Weighted average → letter grade: A (90-100), B (80-89), C (70-79), D (60-69), F (<60)
- Return: overall_grade, overall_score, category_scores[], critical_findings_count, high_findings_count

### AI Reporter (ai_reporter.py)
- Accept full scan results as input
- Build a system prompt that instructs GPT-4o to:
  - Write for a non-technical small business owner
  - Use the "Attacker's Perspective" narrative: "Here's what a hacker would see when they look at your domain..."
  - Organize into sections: Executive Summary, Attacker Narrative, Category Breakdowns, Prioritized Action Items
  - For each finding: explain what it is, why it matters, and exactly how to fix it (step-by-step)
  - Use analogies (e.g., "No DMARC is like leaving your mailbox unlocked — anyone can send letters pretending to be you")
- Parse the response into a FullReport pydantic model
- Handle API errors gracefully

### PDF Generator (pdf_generator.py)
- Use reportlab to create a branded PDF
- Page 1: Cover page with ThreatLens logo (text-based), domain scanned, date, letter grade (large, colored: A=green, B=blue, C=yellow, D=orange, F=red)
- Page 2: Executive Summary + Attacker Narrative
- Pages 3+: Category breakdowns with findings, risk indicators, and remediation steps
- Final page: Prioritized action items checklist
- Style: clean, professional, monospace for technical values, color-coded severity badges

### requirements.txt
Include: fastapi, uvicorn, httpx, dnspython, python-whois, reportlab, pydantic, pydantic-settings, openai, python-multipart

Build the complete backend. Every file should be fully implemented with real logic, not placeholder TODOs. Include comprehensive error handling and input validation. Add detailed docstrings.
```

---

## PROMPT 2 — Frontend: Landing + Scan UI

```
Now build the Next.js 14 frontend for ThreatLens.

## Design Direction
Dark, cybersecurity-themed UI — think "hacker terminal meets clean SaaS." Not cheesy Matrix green-on-black. Think more: dark navy/charcoal backgrounds, electric blue and amber accent colors, clean typography, subtle scan-line or grid textures.

## Color Palette (CSS variables)
--bg-primary: #0a0e1a
--bg-secondary: #111827
--bg-card: #1a2035
--accent-blue: #3b82f6
--accent-amber: #f59e0b
--accent-red: #ef4444
--accent-green: #10b981
--text-primary: #e2e8f0
--text-secondary: #94a3b8
--border: #1e293b

## Font
Use "JetBrains Mono" for monospace/technical elements, "Plus Jakarta Sans" for headings and body text. Import from Google Fonts.

## Pages & Components

### Landing Page (app/page.tsx)
- Hero section:
  - Large headline: "See Your Business Through a Hacker's Eyes"
  - Subheadline: "ThreatLens scans your domain and tells you exactly what an attacker would find — in plain English."
  - Domain input field: large, centered, with placeholder "yourbusiness.com"
  - CTA button: "Scan My Domain" with a subtle pulse animation
  - Below: "Free • No signup • Results in 60 seconds"
- Background: subtle animated grid pattern (CSS only, no canvas) with a radial gradient glow behind the input
- Trust bar below hero: "Checks 7 attack vectors" with small icons for DNS, SSL, Email, Headers, Ports, Subdomains, Tech Stack
- How It Works section: 3 step cards with icons
  1. "Enter Your Domain" 
  2. "We Run 7 Passive Recon Checks"
  3. "Get Your Security Report Card"
- Footer: "Built for the Codex Creator Challenge" + GitHub link placeholder

### Scanning Page (app/scan/[id]/page.tsx)
- After submitting domain, redirect here with the scan_id
- Show an animated scanning visualization:
  - Central domain name displayed prominently
  - 7 "module cards" arranged around it, each representing a check
  - Each card starts in "pending" state (gray), transitions to "scanning" (pulsing blue), then "complete" (green check or red alert)
  - Use polling (GET /api/results/{scan_id} every 2 seconds) to update progress
  - Smooth animations between states using framer-motion or CSS transitions
- Progress bar at top showing overall completion percentage
- When all complete, auto-redirect to results page

### Results Dashboard (app/results/[id]/page.tsx)
- Top banner: Letter grade (massive, colored), domain name, scan date
- Score gauge: circular progress indicator showing 0-100 score
- Stats row: Critical findings (red), High (orange), Medium (yellow), Low (blue), Info (gray) — clickable to filter
- Category cards (grid layout, 2 columns on desktop):
  - Each card: category name, category score bar, finding count, expand/collapse for details
  - Inside expanded: individual findings with severity badge, title, plain-English explanation
- "Attacker's Perspective" section: the AI-generated narrative in a styled blockquote/card
- Action Items section: numbered list of prioritized fixes, each with estimated difficulty (Easy/Medium/Hard badge)
- "Download PDF Report" button: calls /api/report/{scan_id}/pdf
- "Scan Another Domain" button to go back to landing

### Shared Components
- components/ui/Navbar.tsx — logo + "New Scan" button
- components/ui/SeverityBadge.tsx — colored pill: Critical/High/Medium/Low/Info
- components/ui/ScoreGauge.tsx — circular SVG gauge with animated fill
- components/ui/GradeDisplay.tsx — large letter grade with color and glow effect
- components/ui/FindingCard.tsx — expandable card for individual findings
- components/ui/CategoryCard.tsx — category summary with expandable findings
- components/ui/LoadingPulse.tsx — animated scanning indicator

### API Integration
- lib/api.ts: typed API client functions
  - startScan(domain: string): Promise<{scan_id: string}>
  - getScanResults(scanId: string): Promise<ScanResults>
  - getReportPdf(scanId: string): downloads blob
- lib/types.ts: TypeScript types matching the backend Pydantic models

### Important Implementation Notes
- All pages must be fully responsive (mobile-first)
- Use framer-motion for page transitions and card animations
- Add proper loading and error states for every API call
- The scan input should validate domain format client-side before submission
- Use Next.js App Router conventions (layout.tsx, loading.tsx, error.tsx)
- No placeholder components — every component must be fully styled and functional

Build every file completely. This should be demo-ready.
```

---

## PROMPT 3 — AI Report Prompt Engineering

```
I need you to write the exact system prompt and user prompt templates that will be used inside the ai_reporter.py service to generate the ThreatLens security report via the OpenAI API.

## Context
ThreatLens is a tool for non-technical small business owners. The AI receives structured JSON scan results and must produce a plain-English security report that is:
- Understandable by someone who doesn't know what DNS or TLS means
- Actionable — every finding includes step-by-step fix instructions
- Engaging — uses the "attacker's perspective" narrative to make security tangible
- Professional — suitable for sharing with a business partner or IT consultant

## Deliverables

### 1. SYSTEM_PROMPT (string constant)
Write a detailed system prompt for GPT-4o that instructs it to:
- Role: "You are a cybersecurity analyst writing a security assessment for a small business owner who has zero technical background."
- Always explain jargon in parentheses on first use
- Use real-world analogies for every technical concept
- Structure the output as valid JSON matching this exact schema:
```json
{
  "executive_summary": "2-3 paragraph overview of the domain's security posture...",
  "attacker_narrative": "A first-person narrative from an attacker's perspective: 'If I were targeting yourbusiness.com, the first thing I'd notice is...'",
  "categories": [
    {
      "name": "Email Security",
      "grade": "D",
      "summary": "1-2 sentence category overview",
      "findings": [
        {
          "title": "No DMARC Policy Configured",
          "severity": "high",
          "explanation": "Plain English explanation with analogy...",
          "impact": "What could happen if this isn't fixed...",
          "remediation": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
          "difficulty": "easy"
        }
      ]
    }
  ],
  "action_items": [
    {
      "priority": 1,
      "title": "Set up DMARC email authentication",
      "category": "Email Security",
      "difficulty": "easy",
      "time_estimate": "15 minutes",
      "impact_if_ignored": "Attackers can send emails impersonating your business"
    }
  ]
}
```
- Severity levels: critical, high, medium, low, info
- Difficulty levels: easy, medium, hard
- Sort action_items by priority (most critical first)
- Never invent findings — only report on data present in the scan results
- If a category has no issues, still include it with a positive note
- The attacker narrative should be vivid but not fearmongering — informative, not alarmist
- Keep the entire response under 3000 tokens

### 2. build_user_prompt(scan_results: dict) -> str
Write a Python function that takes the structured scan results dict and formats it into the user prompt. The function should:
- Serialize each category's raw findings into a readable format
- Include the domain name, scan timestamp, and all raw data
- Instruct the model to respond ONLY with the JSON object, no markdown backticks

### 3. parse_ai_response(response_text: str) -> FullReport
Write a function that:
- Strips any markdown code fences if present
- Parses the JSON
- Validates against the FullReport pydantic model
- Handles malformed responses gracefully with a fallback report

Write the complete, production-ready ai_reporter.py file with all three components.
```

---

## PROMPT 4 — PDF Report Generator

```
Build the complete pdf_generator.py for ThreatLens using Python's reportlab library.

## PDF Design Specifications

### Page Setup
- Letter size (8.5" x 11")
- Margins: 0.75" all sides
- Font: Helvetica family (built into reportlab, no external fonts needed)

### Color Scheme
NAVY = HexColor("#0a0e1a")
DARK_BLUE = HexColor("#111827")  
ACCENT_BLUE = HexColor("#3b82f6")
ACCENT_AMBER = HexColor("#f59e0b")
RED = HexColor("#ef4444")
GREEN = HexColor("#10b981")
YELLOW = HexColor("#eab308")
ORANGE = HexColor("#f97316")
WHITE = HexColor("#ffffff")
LIGHT_GRAY = HexColor("#e2e8f0")
MID_GRAY = HexColor("#94a3b8")

### Grade Colors
A = GREEN, B = ACCENT_BLUE, C = YELLOW, D = ORANGE, F = RED

### Page 1: Cover Page
- Full navy background
- "THREATLENS" text logo at top (large, white, spaced tracking)
- "SECURITY ASSESSMENT REPORT" subtitle
- Horizontal divider line (accent blue)
- Large letter grade in a circle (colored by grade), centered
- "Overall Score: 73/100" below the grade
- Domain name: large, white
- "Scan Date: April 9, 2026"
- Bottom: "This report was generated by ThreatLens — AI-powered security analysis"

### Page 2: Executive Summary
- Section header: "EXECUTIVE SUMMARY" with blue left border
- Executive summary text (body paragraphs)
- Then: "ATTACKER'S PERSPECTIVE" header with amber left border
- Attacker narrative in a slightly indented, styled block
- Page number in footer

### Pages 3+: Category Breakdowns
- For each category:
  - Category header with grade badge (colored circle with letter)
  - Category summary paragraph
  - Findings table:
    - Each finding is a mini-section with:
      - Severity badge (colored rectangle with text: CRITICAL, HIGH, MEDIUM, LOW, INFO)
      - Finding title (bold)
      - Explanation paragraph
      - Impact paragraph (italic)
      - "How to Fix:" followed by numbered remediation steps
      - Difficulty badge (EASY = green pill, MEDIUM = yellow pill, HARD = red pill)
    - Horizontal line between findings
  - Page breaks between categories if needed (check remaining space)

### Final Page: Action Items Checklist
- "PRIORITIZED ACTION PLAN" header
- Numbered table with columns: Priority #, Action, Category, Difficulty, Time Estimate
- Each row alternates background color (white / very light blue)
- Below table: "Questions? Share this report with your IT consultant or managed service provider."
- ThreatLens branding footer

### Implementation Requirements
- Function signature: generate_pdf(report: FullReport, domain: str, scan_date: str, grade: str, score: int) -> bytes
- Return the PDF as bytes (BytesIO) so the FastAPI endpoint can stream it
- Handle long text wrapping properly (use Platypus Paragraph objects, not canvas.drawString)
- Add page numbers to every page except the cover
- Handle edge cases: very long domain names, many findings, empty categories
- Use reportlab.platypus for layout (SimpleDocTemplate + Flowables) for pages 2+
- Use reportlab.pdfgen.canvas for the cover page (custom drawing)
- Combine both approaches using canvas callbacks in the doc template

Build the complete, production-ready file. No TODOs, no placeholders.
```

---

## PROMPT 5 — Docker, README & Polish

```
Finalize the ThreatLens project with deployment configuration and documentation.

## 1. docker-compose.yml
- backend service:
  - Build from ./backend
  - Port 8000:8000
  - Environment: OPENAI_API_KEY, SHODAN_API_KEY (optional)
  - Health check: curl /api/health
- frontend service:
  - Build from ./frontend
  - Port 3000:3000
  - Depends on backend
  - Environment: NEXT_PUBLIC_API_URL=http://backend:8000

## 2. Backend Dockerfile
- Python 3.12-slim base
- Install system deps for dnspython
- pip install requirements.txt
- Run with uvicorn, host 0.0.0.0, port 8000

## 3. Frontend Dockerfile
- Node 20-alpine base
- npm install, npm run build, npm start
- Multi-stage build for smaller image

## 4. README.md
Write a compelling, well-structured README with:

### Hero Section
- Project name + tagline: "See your business through a hacker's eyes"
- One-paragraph description
- Screenshot placeholder: [Screenshot of results dashboard]
- Badges: Python, Next.js, FastAPI, OpenAI, Docker

### What It Does
- Bullet list of the 7 passive recon checks
- Emphasize: 100% passive, no active scanning, no legal gray areas
- "Results in under 60 seconds"

### Why It Matters
- Stats: 43% of cyberattacks target small businesses, 60% go out of business within 6 months of a breach
- "Small businesses deserve enterprise-grade security visibility"

### How It Works
- Architecture diagram (text-based/mermaid)
- Flow: Domain Input → Parallel Recon → AI Analysis → Report Generation

### Quick Start
- Prerequisites: Docker, OpenAI API key
- 3 commands to run:
```bash
git clone https://github.com/yourusername/threatlens.git
cd threatlens
echo "OPENAI_API_KEY=your-key-here" > .env
docker-compose up --build
```
- Open http://localhost:3000

### Tech Stack section (table)

### Built For
"This project was built for the OpenAI x Handshake Codex Creator Challenge (2026)"

### Future Roadmap
- Scheduled re-scans with email alerts
- Multi-domain monitoring dashboard
- Compliance mapping (SOC 2, HIPAA, PCI-DSS)
- Browser extension for instant checks
- API for MSP/IT consultant integration

### License: MIT

## 5. .env.example
OPENAI_API_KEY=sk-your-key-here
SHODAN_API_KEY=optional-shodan-key

## 6. .gitignore
Standard Python + Node.js gitignore + .env

Build all files completely.
```

---

## PROMPT 6 (BONUS) — Demo Mode & Fallbacks

```
Add a "demo mode" to ThreatLens so it works perfectly in a live presentation even without API keys or network access.

## Requirements

### Backend Changes
1. Add a DEMO_MODE=true environment variable option
2. When DEMO_MODE is true and domain is "demo.threatlens.io":
   - Skip all real API calls
   - Return realistic pre-built scan results for a fictional company
   - Include a mix of findings: 2 critical, 3 high, 4 medium, 2 low, 3 info
   - Make the demo data tell a compelling story: missing DMARC, expired SSL cert on a subdomain, exposed WordPress admin panel, no HSTS, open FTP port
   - Still call the OpenAI API for the report (if key available), OR return a pre-written report if no key
3. Add artificial delays (0.5-2 seconds per module) so the scanning animation looks realistic in demos

### Frontend Changes
1. On the landing page, add a subtle link below the input: "Try a demo scan →"
2. Clicking it auto-fills "demo.threatlens.io" and triggers the scan
3. The scanning page should show the same progressive animation

### Pre-built Demo Report
Write a complete, realistic AI-generated report for "demo.threatlens.io" that:
- Scores a C (72/100)
- Has a compelling attacker narrative
- Shows a variety of finding severities
- Includes actionable, realistic remediation steps
- Can be used as the fallback when no OpenAI API key is set

Store this as a JSON fixture file: backend/app/fixtures/demo_report.json

Build all changes completely.
```

---

## 🎯 Tips for Running These Prompts

1. **Run them in order.** Each builds on the previous output.
2. **Use Codex in "full repo" mode** if available — give it the whole project context.
3. **After each prompt**, review the output and fix any import path mismatches before moving on.
4. **Test locally** after Prompts 1-2 before moving to 3+. The scan flow should work end-to-end with at least DNS + SSL checks before you layer on the AI report.
5. **For the 3-minute pitch**: demo `demo.threatlens.io` first (reliable), then live-scan a real domain (impressive). Always have the demo as backup.

---

*Built for the OpenAI × Handshake Codex Creator Challenge 2026*
*Prompt suite authored for maximum Codex compatibility*
