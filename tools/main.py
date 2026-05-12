#!/usr/bin/env python3
"""
Full Web Security Scanner — Main Entry Point
A simplified Burp Suite-style pentesting tool with GUI dashboard.

Usage:
    python main.py                  # Launch GUI
    python main.py --cli <url>      # CLI mode (headless scan)
    python main.py --help           # Show help
"""

import sys
import argparse
from scanner import WebScanner
from report import ReportGenerator


def print_banner():
    """Print tool banner."""
    banner = """
╔══════════════════════════════════════════════════╗
║         🔍  FULL WEB SECURITY SCANNER           ║
║     SQL Injection · XSS · CSRF · Crawler        ║
║         Simplified Burp Suite for Pentesters     ║
╚══════════════════════════════════════════════════╝
    """
    print(banner)


def cli_mode(args):
    """Run in CLI (headless) mode."""
    print_banner()
    
    scanner = WebScanner(
        target_url=args.url,
        max_depth=args.depth,
        threads=args.threads,
    )
    
    result = scanner.scan()
    
    # Generate reports
    html_file = ReportGenerator.save_report(result)
    json_file = ReportGenerator.save_json(result)
    
    # Print summary
    print(f"\n{'='*60}")
    print("  SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  Target:      {result.target_url}")
    print(f"  URLs found:  {result.total_urls_scanned}")
    print(f"  Forms found: {result.total_forms_found}")
    print(f"  Vulnerabilities: {len(result.vulnerabilities)}")
    print(f"  Duration:    {result.scan_duration_seconds:.2f}s")
    print(f"  HTML Report: {html_file}")
    print(f"  JSON Report: {json_file}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Full Web Security Scanner — Pentesting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                       # Launch GUI dashboard
  python main.py --cli https://example.com    # CLI scan
  python main.py --cli https://site.com --depth 3 --threads 10
        """
    )
    
    parser.add_argument("--cli", metavar="URL", help="Run in CLI mode (headless scan)")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--threads", type=int, default=5, help="Thread count (default: 5)")
    parser.add_argument("--no-gui", action="store_true", help="Force CLI mode even without URL")
    
    args = parser.parse_args()
    
    if args.cli:
        cli_mode(args)
    else:
        # Launch GUI
        try:
            from gui import ScannerGUI
            app = ScannerGUI()
            app.run()
        except ImportError as e:
            print(f"[!] GUI dependencies missing: {e}")
            print("[!] Run with '--cli <url>' for headless mode")
            print("[!] Or install tkinter: sudo apt install python3-tk")
            sys.exit(1)


if __name__ == "__main__":
    main()
