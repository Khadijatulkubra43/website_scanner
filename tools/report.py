"""
HTML Report Generator for Web Security Scanner
"""

import json
import datetime
from typing import List, Dict
from scanner import Vulnerability, ScanResult


class ReportGenerator:
    """Generates professional HTML reports from scan results."""

    SEVERITY_COLORS = {
        "Critical": "#dc3545",
        "High": "#fd7e14",
        "Medium": "#ffc107",
        "Low": "#28a745",
    }

    SEVERITY_BG = {
        "Critical": "#f8d7da",
        "High": "#fff3cd",
        "Medium": "#fff3cd",
        "Low": "#d4edda",
    }

    @staticmethod
    def generate_html(result: ScanResult) -> str:
        """Generate a complete HTML report."""

        vulns = result.vulnerabilities

        critical = sum(1 for v in vulns if v.severity == "Critical")
        high = sum(1 for v in vulns if v.severity == "High")
        medium = sum(1 for v in vulns if v.severity == "Medium")
        low = sum(1 for v in vulns if v.severity == "Low")

        vuln_rows = ""

        for i, v in enumerate(vulns, 1):
            color = ReportGenerator.SEVERITY_COLORS.get(v.severity, "#6c757d")
            bg = ReportGenerator.SEVERITY_BG.get(v.severity, "#f8f9fa")

            vuln_rows += f"""
            <tr style="background-color: {bg};">
                <td>{i}</td>
                <td>
                    <span class="badge" style="background-color: {color}; color: white;">
                        {v.type}
                    </span>
                </td>
                <td style="max-width: 350px; word-break: break-all;">
                    {v.url}
                </td>
                <td><code>{v.parameter}</code></td>
                <td>
                    <span class="severity-{v.severity.lower()}">
                        {v.severity}
                    </span>
                </td>
                <td style="max-width: 200px;">
                    {v.description[:120]}
                </td>
            </tr>
            """

        # Detailed vulnerability section
        details_section = ""

        for i, v in enumerate(vulns, 1):
            color = ReportGenerator.SEVERITY_COLORS.get(v.severity, "#6c757d")

            details_section += f"""
            <div class="vuln-card" style="border-left: 5px solid {color};">
                <h3>
                    #{i} {v.type}
                    <span class="sev-badge" style="background: {color};">
                        {v.severity}
                    </span>
                </h3>

                <table class="vuln-details">
                    <tr>
                        <th>URL</th>
                        <td><code>{v.url}</code></td>
                    </tr>

                    <tr>
                        <th>Parameter</th>
                        <td><code>{v.parameter}</code></td>
                    </tr>

                    <tr>
                        <th>Payload</th>
                        <td><code>{v.payload}</code></td>
                    </tr>

                    <tr>
                        <th>Description</th>
                        <td>{v.description}</td>
                    </tr>

                    <tr>
                        <th>Evidence</th>
                        <td><pre>{v.evidence}</pre></td>
                    </tr>

                    <tr>
                        <th>Remediation</th>
                        <td>{v.remediation}</td>
                    </tr>
                </table>
            </div>
            """

        # Severity chart
        max_count = max(critical, high, medium, low, 1)

        chart_bars = ""

        for label, count, color in [
            ("Critical", critical, "#dc3545"),
            ("High", high, "#fd7e14"),
            ("Medium", medium, "#ffc107"),
            ("Low", low, "#28a745"),
        ]:
            pct = (count / max_count) * 100 if max_count > 0 else 0

            chart_bars += f"""
            <div class="chart-row">
                <div class="chart-label">{label}</div>

                <div class="chart-bar-bg">
                    <div
                        class="chart-bar"
                        style="width: {pct}%; background: {color};"
                    ></div>
                </div>

                <div class="chart-count">{count}</div>
            </div>
            """

        html = f"""
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report — {result.target_url}</title>

    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
                         Roboto, Oxygen, Ubuntu, sans-serif;

            background: #0f0f1a;
            color: #e0e0e0;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        .header {{
            background: linear-gradient(
                135deg,
                #1a1a2e 0%,
                #16213e 100%
            );

            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid #2a2a4a;
        }}

        .header h1 {{
            font-size: 2em;
            color: #00d4ff;
            margin-bottom: 10px;
        }}

        .header .subtitle {{
            color: #8892b0;
            font-size: 1.1em;
        }}

        .header .meta {{
            margin-top: 15px;
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
        }}

        .header .meta-item {{
            color: #8892b0;
        }}

        .header .meta-item strong {{
            color: #ccd6f6;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: #1a1a2e;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid #2a2a4a;
        }}

        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #00d4ff;
        }}

        .stat-card .label {{
            color: #8892b0;
            margin-top: 5px;
            font-size: 0.9em;
        }}

        .danger {{
            color: #dc3545 !important;
        }}

        .warning {{
            color: #fd7e14 !important;
        }}

        .safe {{
            color: #28a745 !important;
        }}

        h2 {{
            color: #00d4ff;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #2a2a4a;
        }}

        .chart-container {{
            background: #1a1a2e;
            padding: 25px;
            border-radius: 10px;
            border: 1px solid #2a2a4a;
            margin-bottom: 30px;
        }}

        .chart-row {{
            display: flex;
            align-items: center;
            margin-bottom: 12px;
            gap: 15px;
        }}

        .chart-label {{
            width: 80px;
            font-size: 0.9em;
            color: #ccd6f6;
        }}

        .chart-bar-bg {{
            flex: 1;
            height: 24px;
            background: #2a2a4a;
            border-radius: 12px;
            overflow: hidden;
        }}

        .chart-bar {{
            height: 100%;
            border-radius: 12px;
            transition: width 0.5s;
            min-width: 4px;
        }}

        .chart-count {{
            width: 40px;
            text-align: right;
            font-weight: bold;
            color: #64ffda;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: #1a1a2e;
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 30px;
        }}

        th {{
            background: #16213e;
            color: #64ffda;
            padding: 14px 16px;
            text-align: left;
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        td {{
            padding: 12px 16px;
            border-bottom: 1px solid #2a2a4a;
            font-size: 0.9em;
        }}

        tr:hover td {{
            background: rgba(0, 212, 255, 0.05);
        }}

        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
        }}

        .severity-critical {{
            color: #dc3545;
            font-weight: 600;
        }}

        .severity-high {{
            color: #fd7e14;
            font-weight: 600;
        }}

        .severity-medium {{
            color: #ffc107;
            font-weight: 600;
        }}

        .severity-low {{
            color: #28a745;
            font-weight: 600;
        }}

        code {{
            background: #2a2a4a;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.9em;
            color: #f8f8f2;
        }}

        pre {{
            background: #2a2a4a;
            padding: 10px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.85em;
            color: #f8f8f2;
            max-height: 100px;
            overflow-y: auto;
        }}

        .vuln-card {{
            background: #1a1a2e;
            padding: 25px;
            border-radius: 10px;
            border: 1px solid #2a2a4a;
            margin-bottom: 20px;
        }}

        .vuln-card h3 {{
            color: #ccd6f6;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .sev-badge {{
            display: inline-block;
            padding: 3px 12px;
            border-radius: 12px;
            color: white;
            font-size: 0.7em;
            font-weight: 600;
        }}

        .vuln-details {{
            width: 100%;
            background: transparent;
        }}

        .vuln-details th {{
            width: 140px;
            background: transparent;
            color: #64ffda;
            text-transform: none;
            letter-spacing: 0;
            font-size: 0.85em;
            vertical-align: top;
        }}

        .vuln-details td {{
            color: #ccd6f6;
        }}

        .footer {{
            text-align: center;
            padding: 30px;
            color: #8892b0;
            font-size: 0.85em;
        }}

        .no-vulns {{
            text-align: center;
            padding: 60px;
            background: #1a1a2e;
            border-radius: 10px;
            border: 1px solid #28a745;
        }}

        .no-vulns h2 {{
            color: #28a745;
            border: none;
        }}

        .no-vulns p {{
            color: #8892b0;
            font-size: 1.1em;
        }}

        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}

            .header .meta {{
                flex-direction: column;
                gap: 8px;
            }}
        }}
    </style>
</head>

<body>

    <div class="container">

        <div class="header">
            <h1>🔍 Web Security Scan Report</h1>

            <div class="subtitle">
                Automated vulnerability assessment —
                SQL Injection, XSS & CSRF Detection
            </div>

            <div class="meta">
                <div class="meta-item">
                    <strong>Target:</strong> {result.target_url}
                </div>

                <div class="meta-item">
                    <strong>Scan Date:</strong> {result.scan_date}
                </div>

                <div class="meta-item">
                    <strong>Duration:</strong>
                    {result.scan_duration_seconds:.2f}s
                </div>

                <div class="meta-item">
                    <strong>Scanner:</strong>
                    Full Web Security Scanner v1.0
                </div>
            </div>
        </div>

        <div class="stats-grid">

            <div class="stat-card">
                <div class="number">{result.total_urls_scanned}</div>
                <div class="label">URLs Crawled</div>
            </div>

            <div class="stat-card">
                <div class="number">{result.total_forms_found}</div>
                <div class="label">Forms Analyzed</div>
            </div>

            <div class="stat-card">
                <div class="number danger">{critical}</div>
                <div class="label">Critical</div>
            </div>

            <div class="stat-card">
                <div class="number warning">{high}</div>
                <div class="label">High</div>
            </div>

            <div class="stat-card">
                <div class="number warning">{medium}</div>
                <div class="label">Medium</div>
            </div>

            <div class="stat-card">
                <div class="number safe">{low}</div>
                <div class="label">Low</div>
            </div>

        </div>

        <h2>📊 Severity Breakdown</h2>

        <div class="chart-container">
            {
                chart_bars
                if vulns
                else '<p style="color:#28a745;text-align:center;font-size:1.2em;">✓ No vulnerabilities found — clean scan!</p>'
            }
        </div>
"""

        if vulns:
            html += f"""
        <h2>📋 Vulnerability Summary</h2>

        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Parameter</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
            </thead>

            <tbody>
                {vuln_rows}
            </tbody>
        </table>

        <h2>🔬 Detailed Findings</h2>

        {details_section}
"""
        else:
            html += """
        <div class="no-vulns">
            <h2>✅ No Vulnerabilities Found</h2>

            <p>
                The scan completed successfully with no security issues detected.
            </p>
        </div>
"""

        html += f"""

        <h2>📝 Remediation Summary</h2>

        <div class="vuln-card" style="border-left: 5px solid #00d4ff;">

            <h3>General Security Recommendations</h3>

            <table class="vuln-details">

                <tr>
                    <th>SQL Injection</th>
                    <td>
                        Use parameterized queries (prepared statements),
                        ORM frameworks, input validation,
                        and proper error handling.
                        Implement WAF rules.
                    </td>
                </tr>

                <tr>
                    <th>XSS</th>
                    <td>
                        Apply contextual output encoding
                        (HTML entity, JavaScript, CSS encoding).
                        Use Content-Security-Policy headers.
                        Validate and sanitize all inputs.
                    </td>
                </tr>

                <tr>
                    <th>CSRF</th>
                    <td>
                        Implement anti-CSRF tokens for all
                        state-changing requests.
                        Use SameSite cookies.
                        Validate Origin/Referer headers.
                    </td>
                </tr>

                <tr>
                    <th>General</th>
                    <td>
                        Keep software updated.
                        Use HTTPS everywhere.
                        Implement proper authentication
                        and authorization.
                        Regular security assessments.
                    </td>
                </tr>

            </table>
        </div>

        <div class="footer">
            <p>
                Generated by Full Web Security Scanner —
                {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}
            </p>

            <p>
                Authorized security testing only.
                This report is confidential.
            </p>
        </div>

    </div>

</body>
</html>
"""

        return html

    @staticmethod
    def save_report(result: ScanResult, filename: str = None) -> str:
        """Generate and save HTML report to file."""

        if filename is None:
            safe_url = (
                result.target_url
                .replace("https://", "")
                .replace("http://", "")
                .replace("/", "_")
            )

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

            filename = f"scan_report_{safe_url}_{timestamp}.html"

        html = ReportGenerator.generate_html(result)

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"\n[✓] Report saved: {filename}")

        return filename

    @staticmethod
    def save_json(result: ScanResult, filename: str = None) -> str:
        """Save results as JSON for programmatic consumption."""

        if filename is None:
            safe_url = (
                result.target_url
                .replace("https://", "")
                .replace("http://", "")
                .replace("/", "_")
            )

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

            filename = f"scan_report_{safe_url}_{timestamp}.json"

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)

        print(f"[✓] JSON report saved: {filename}")

        return filename
