import asyncio
import aiohttp
import argparse
import sys
import json
import random
import re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

console = Console()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Edge/122.0.2365.66"
]

def extract_secrets(text, patterns):
    extracted = {}
    for pattern in patterns:
        try:
            matches = re.findall(pattern, text)
            if matches:
                flattened = [m if isinstance(m, str) else "".join(m) for m in matches]
                extracted[pattern] = list(set(flattened))
        except Exception:
            pass
    return extracted

async def check_credentials(session, url, username, password, semaphore, success_str=None, failure_str=None, delay=0.0, user_key="username", pass_key="password", base_headers=None, rotate_ua=False, smart_pause=False, lockout_str=None, pause_duration=15.0, pause_lock=None, extract_patterns=None, verbose=False, proxy=None):
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
            
        payload = {user_key: username, pass_key: password}
        headers = dict(base_headers) if base_headers else {}
        
        if rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
            
        request_kwargs = {"data": payload, "headers": headers, "ssl": False}
        if proxy:
            request_kwargs["proxy"] = proxy
        
        if verbose:
            console.print(f"[dim][DEBUG] POST {url} | Payload: {payload} | Headers: {headers}[/dim]")

        try:
            async with session.post(url, **request_kwargs) as response:
                text = await response.text()
                
                is_rate_limited = (response.status == 429) or (lockout_str and lockout_str in text)
                if smart_pause and is_rate_limited:
                    async with pause_lock:
                        console.print(f"\n[bold yellow][!] Rate-limit or lockout detected (Status: {response.status}). Pausing execution for {pause_duration}s cooling period...[/bold yellow]")
                        await asyncio.sleep(pause_duration)
                
                if verbose:
                    console.print(f"[dim][DEBUG] Response Status: {response.status} | Body Snippet: {text[:150]}...[/dim]")

                if failure_str and failure_str in text:
                    is_success = False
                elif success_str:
                    is_success = (success_str in text)
                else:
                    is_success = (response.status == 200)
                    
                secrets = extract_secrets(text, extract_patterns) if (is_success and extract_patterns) else {}
                return (username, password, is_success, text, secrets)
        except Exception as e:
            if verbose:
                console.print(f"[bold red][DEBUG] Exception on {username}:{password} -> {e}[/bold red]")
            return (username, password, False, str(e), {})

async def crawl_endpoint(session, base_url, path, semaphore, delay=0.0, base_headers=None, rotate_ua=False, extract_patterns=None, verbose=False, proxy=None):
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
            
        target_url = urljoin(base_url, path)
        headers = dict(base_headers) if base_headers else {}
        
        if rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
            
        request_kwargs = {"headers": headers, "ssl": False}
        if proxy:
            request_kwargs["proxy"] = proxy
            
        if verbose:
            console.print(f"[dim][DEBUG] GET {target_url} | Headers: {headers}[/dim]")

        try:
            async with session.get(target_url, **request_kwargs) as response:
                text = await response.text()
                
                if verbose:
                    console.print(f"[dim][DEBUG] Crawl Status: {response.status} for {path}[/dim]")

                secrets = extract_secrets(text, extract_patterns) if extract_patterns else {}
                return (path, response.status, text, secrets)
        except Exception as e:
            if verbose:
                console.print(f"[bold red][DEBUG] Crawl Exception on {path} -> {e}[/bold red]")
            return (path, 0, str(e), {})

async def fuzz_request(session, method, url_template, body_template, payload, semaphore, delay=0.0, base_headers=None, rotate_ua=False, smart_pause=False, lockout_str=None, pause_duration=15.0, pause_lock=None, extract_patterns=None, verbose=False, proxy=None):
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
            
        target_url = url_template.replace("§§", payload)
        body = body_template.replace("§§", payload) if body_template else None
        
        headers = dict(base_headers) if base_headers else {}
        if rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
            
        request_kwargs = {"headers": headers, "ssl": False}
        if proxy:
            request_kwargs["proxy"] = proxy
            
        if body is not None:
            request_kwargs["data"] = body
            
        if verbose:
            console.print(f"[dim][DEBUG] {method.upper()} {target_url} | Body: {body} | Headers: {headers}[/dim]")

        try:
            async with session.request(method.upper(), target_url, **request_kwargs) as response:
                text = await response.text()
                
                is_rate_limited = (response.status == 429) or (lockout_str and lockout_str in text)
                if smart_pause and is_rate_limited:
                    async with pause_lock:
                        console.print(f"\n[bold yellow][!] Rate-limit or lockout detected (Status: {response.status}). Pausing execution for {pause_duration}s cooling period...[/bold yellow]")
                        await asyncio.sleep(pause_duration)

                secrets = extract_secrets(text, extract_patterns) if extract_patterns else {}
                return (payload, response.status, len(text), text, secrets)
        except Exception as e:
            if verbose:
                console.print(f"[bold red][DEBUG] Fuzz Exception on payload {payload} -> {e}[/bold red]")
            return (payload, 0, 0, str(e), {})

async def main():
    parser = argparse.ArgumentParser(description="Async Terminal Analyzer / Login Auditor & Burp-Style Intruder Fuzzer")
    parser.add_argument("--intruder", action="store_true", help="Enable Burp-style Intruder fuzzing mode")
    parser.add_argument("--method", default="GET", help="HTTP method for intruder mode (GET, POST, PUT, etc.)")
    parser.add_argument("--fuzz-url", default="http://127.0.0.1:8080/search?q=§§", help="Target URL with §§ insertion point")
    parser.add_argument("--fuzz-body", default=None, help="POST/PUT body template with §§ insertion point")
    parser.add_argument("--payloads", default="payloads.txt", help="Path to payloads wordlist file for intruder mode")
    
    # Original Login Audit arguments
    parser.add_argument("--url", default="http://127.0.0.1:8080/login", help="Target Login URL")
    parser.add_argument("--proxy", default=None, help="HTTP Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Max concurrent requests")
    parser.add_argument("-d", "--delay", type=float, default=0.0, help="Delay in seconds between requests")
    parser.add_argument("-u", "--users", default="usernames.txt", help="Path to usernames file")
    parser.add_argument("-p", "--passwords", default="passwords.txt", help="Path to passwords file")
    parser.add_argument("--user-key", default="username", help="JSON key name for username field (default: username)")
    parser.add_argument("--pass-key", default="password", help="JSON key name for password field (default: password)")
    parser.add_argument("--header", action="append", default=[], help="Custom HTTP header in 'Key: Value' format (can be used multiple times)")
    parser.add_argument("--extract-regex", action="append", default=[], help="Regex pattern to harvest secrets/data from responses (can be used multiple times)")
    parser.add_argument("--success-str", default=None, help="Substring in response body indicating success")
    parser.add_argument("--failure-str", default=None, help="Substring in response body indicating failure")
    parser.add_argument("--rotate-ua", action="store_true", help="Randomly rotate User-Agent header per request")
    parser.add_argument("--smart-pause", action="store_true", help="Automatically pause and back off on HTTP 429 or lockout strings")
    parser.add_argument("--lockout-str", default=None, help="Substring in response body indicating account lockout or rate-limit")
    parser.add_argument("--pause-duration", type=float, default=15.0, help="Cooling pause duration in seconds when rate-limited (default: 15.0)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug output for requests and responses")
    parser.add_argument("--crawl", action="store_true", help="Crawl protected endpoints after successful login")
    parser.add_argument("--paths", default="paths.txt", help="Path to endpoints wordlist file")
    parser.add_argument("-o", "--output", default="results.json", help="Path to output JSON results file")
    args = parser.parse_args()

    custom_headers = {}
    for h in args.header:
        if ":" in h:
            key, val = h.split(":", 1)
            custom_headers[key.strip()] = val.strip()

    connector = aiohttp.TCPConnector(ssl=False)
    cookie_jar = aiohttp.CookieJar(unsafe=True)
    semaphore = asyncio.Semaphore(args.concurrency)
    pause_lock = asyncio.Lock()

    # --- INTRUDER MODE ---
    if args.intruder:
        try:
            with open(args.payloads, "r") as f:
                payloads = [line.strip() for line in f if line.strip()]
        except FileNotFoundError as e:
            console.print(f"[bold red][!] Payloads wordlist file missing: {e}[/bold red]")
            sys.exit(1)

        console.print(f"[bold cyan][*] Starting Burp Intruder mode against {args.fuzz_url}[/bold cyan] [dim](Payloads: {len(payloads)}, Concurrency: {args.concurrency})[/dim]")
        
        async with aiohttp.ClientSession(connector=connector, cookie_jar=cookie_jar) as session:
            tasks = [
                fuzz_request(
                    session, args.method, args.fuzz_url, args.fuzz_body, payload, semaphore,
                    delay=args.delay, base_headers=custom_headers, rotate_ua=args.rotate_ua,
                    smart_pause=args.smart_pause, lockout_str=args.lockout_str,
                    pause_duration=args.pause_duration, pause_lock=pause_lock,
                    extract_patterns=args.extract_regex, verbose=args.verbose, proxy=args.proxy
                )
                for payload in payloads
            ]

            fuzz_results = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task_progress = progress.add_task("[cyan]Fuzzing targets...", total=len(tasks))
                
                for coro in asyncio.as_completed(tasks):
                    res = await coro
                    fuzz_results.append(res)
                    progress.update(task_progress, advance=1)
                    payload, status, length, _, _ = res
                    status_color = "green" if status == 200 else ("yellow" if status == 403 or status == 401 else "red")
                    console.print(f"[{status_color}][{status}] Payload: {payload} (Length: {length})[/{status_color}]")

            if fuzz_results:
                ftable = Table(title="[bold blue]Burp Intruder Results[/bold blue]")
                ftable.add_column("Payload", style="cyan", no_wrap=True)
                ftable.add_column("Status", style="green")
                ftable.add_column("Length", style="magenta")
                ftable.add_column("Response Snippet", style="dim")
                ftable.add_column("Extracted Secrets", style="yellow")
                
                results_json_data = []
                for payload, status, length, resp, secrets in fuzz_results:
                    sc_color = "green" if status == 200 else "red"
                    sec_str = json.dumps(secrets) if secrets else "None"
                    ftable.add_row(payload, f"[{sc_color}]{status}[/{sc_color}]", str(length), resp[:100].strip(), sec_str)
                    results_json_data.append({
                        "payload": payload,
                        "status_code": status,
                        "response_length": length,
                        "response_snippet": resp[:200],
                        "extracted_secrets": secrets
                    })
                console.print(ftable)

                output_data = {
                    "mode": "intruder",
                    "fuzz_url": args.fuzz_url,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "results": results_json_data
                }
                try:
                    with open(args.output, "w") as out_f:
                        json.dump(output_data, out_f, indent=4)
                    console.print(f"[bold green][*] Intruder results successfully saved to {args.output}[/bold green]")
                except Exception as e:
                    console.print(f"[bold red][!] Failed to save results: {e}[/bold red]")
        return

    # --- STANDARD LOGIN AUDIT & CRAWLER MODE ---
    try:
        with open(args.users, "r") as f:
            users = [line.strip() for line in f if line.strip()]
        with open(args.passwords, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError as e:
        console.print(f"[bold red][!] Wordlist file missing: {e}[/bold red]")
        sys.exit(1)

    total_combinations = len(users) * len(passwords)
    console.print(f"[bold cyan][*] Starting async audit against {args.url}[/bold cyan] [dim](Keys: {args.user_key}/{args.pass_key}, Regex Patterns: {len(args.extract_regex)}, Concurrency: {args.concurrency}, Total: {total_combinations})[/dim]")
    
    successful_findings = []
    crawl_results = []
    
    async with aiohttp.ClientSession(connector=connector, cookie_jar=cookie_jar) as session:
        tasks = [
            check_credentials(
                session, args.url, user, pwd, semaphore, 
                success_str=args.success_str, 
                failure_str=args.failure_str, 
                delay=args.delay, 
                user_key=args.user_key,
                pass_key=args.pass_key,
                base_headers=custom_headers,
                rotate_ua=args.rotate_ua,
                smart_pause=args.smart_pause,
                lockout_str=args.lockout_str,
                pause_duration=args.pause_duration,
                pause_lock=pause_lock,
                extract_patterns=args.extract_regex,
                verbose=args.verbose,
                proxy=args.proxy
            )
            for user in users for pwd in passwords
        ]
        
        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task_progress = progress.add_task("[cyan]Testing credentials...", total=len(tasks))
            
            for coro in asyncio.as_completed(tasks):
                res = await coro
                results.append(res)
                progress.update(task_progress, advance=1)
                user, pwd, success, _, _ = res
                if success:
                    console.print(f"[bold green][+] SUCCESS: {user}:{pwd}[/bold green]")
        
        login_successful = False
        for user, pwd, success, resp, secrets in results:
            if success:
                successful_findings.append({
                    "username": user,
                    "password": pwd,
                    "response_snippet": resp[:200],
                    "extracted_secrets": secrets
                })
                login_successful = True
        
        if args.crawl and login_successful:
            console.print("[bold yellow][*] Valid credentials acquired. Starting post-auth endpoint crawl...[/bold yellow]")
            try:
                with open(args.paths, "r") as pf:
                    paths = [line.strip() for line in pf if line.strip()]
                
                parsed_url = urlparse(args.url)
                base_root = f"{parsed_url.scheme}://{parsed_url.netloc}/"
                
                crawl_tasks = [
                    crawl_endpoint(session, base_root, path, semaphore, delay=args.delay, base_headers=custom_headers, rotate_ua=args.rotate_ua, extract_patterns=args.extract_regex, verbose=args.verbose, proxy=args.proxy)
                    for path in paths
                ]
                c_results = await asyncio.gather(*crawl_tasks)
                
                for path, status, resp, secrets in c_results:
                    status_color = "green" if status == 200 else ("yellow" if status == 403 else "red")
                    console.print(f"[{status_color}][{status}] Endpoint: {path}[/{status_color}]")
                    crawl_results.append({
                        "path": path,
                        "status_code": status,
                        "response_snippet": resp[:200],
                        "extracted_secrets": secrets
                    })
            except FileNotFoundError:
                console.print(f"[bold red][!] Paths wordlist file ({args.paths}) not found. Skipping crawl.[/bold red]")

        if successful_findings:
            table = Table(title="[bold green]Successful Credential Findings[/bold green]")
            table.add_column("Username", style="cyan", no_wrap=True)
            table.add_column("Password", style="magenta")
            table.add_column("Response Snippet", style="dim")
            table.add_column("Extracted Secrets", style="yellow")
            for f in successful_findings:
                sec_str = json.dumps(f["extracted_secrets"]) if f["extracted_secrets"] else "None"
                table.add_row(f["username"], f["password"], f["response_snippet"].strip(), sec_str)
            console.print(table)

        if crawl_results:
            ctable = Table(title="[bold blue]Post-Auth Crawler Results[/bold blue]")
            ctable.add_column("Path", style="cyan")
            ctable.add_column("Status Code", style="green")
            ctable.add_column("Response Snippet", style="dim")
            ctable.add_column("Extracted Secrets", style="yellow")
            for c in crawl_results:
                sc_color = "green" if c["status_code"] == 200 else "red"
                sec_str = json.dumps(c["extracted_secrets"]) if c["extracted_secrets"] else "None"
                ctable.add_row(c["path"], f"[{sc_color}]{c['status_code']}[/{sc_color}]", c["response_snippet"].strip(), sec_str)
            console.print(ctable)

        output_data = {
            "mode": "audit",
            "target": args.url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "successful_logins": successful_findings,
            "crawl_results": crawl_results
        }
        
        try:
            with open(args.output, "w") as out_f:
                json.dump(output_data, out_f, indent=4)
            console.print(f"[bold green][*] Results successfully saved to {args.output}[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Failed to save results: {e}[/bold red]")

if __name__ == "__main__":
    asyncio.run(main())
