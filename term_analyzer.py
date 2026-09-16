import asyncio
import aiohttp
import argparse
import sys
import json
import random
from datetime import datetime, timezone
from urllib.parse import urljoin
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

console = Console()

# Built-in pool of modern browser user agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Edge/122.0.2365.66"
]

async def check_credentials(session, url, username, password, semaphore, success_str=None, failure_str=None, delay=0.0, rotate_ua=False, proxy=None):
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
            
        payload = {"username": username, "password": password}
        request_kwargs = {"data": payload, "ssl": False}
        
        if rotate_ua:
            request_kwargs["headers"] = {"User-Agent": random.choice(USER_AGENTS)}
            
        if proxy:
            request_kwargs["proxy"] = proxy
        
        try:
            async with session.post(url, **request_kwargs) as response:
                text = await response.text()
                
                if failure_str and failure_str in text:
                    is_success = False
                elif success_str:
                    is_success = (success_str in text)
                else:
                    is_success = (response.status == 200)
                    
                return (username, password, is_success, text)
        except Exception as e:
            return (username, password, False, str(e))

async def crawl_endpoint(session, base_url, path, semaphore, delay=0.0, rotate_ua=False, proxy=None):
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
            
        target_url = urljoin(base_url, path)
        request_kwargs = {"ssl": False}
        
        if rotate_ua:
            request_kwargs["headers"] = {"User-Agent": random.choice(USER_AGENTS)}
            
        if proxy:
            request_kwargs["proxy"] = proxy
            
        try:
            async with session.get(target_url, **request_kwargs) as response:
                text = await response.text()
                return (path, response.status, text)
        except Exception as e:
            return (path, 0, str(e))

async def main():
    parser = argparse.ArgumentParser(description="Async Terminal Analyzer / Login Auditor & Crawler")
    parser.add_argument("--url", default="http://127.0.0.1:8080/login", help="Target Login URL")
    parser.add_argument("--proxy", default=None, help="HTTP Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Max concurrent requests")
    parser.add_argument("-d", "--delay", type=float, default=0.0, help="Delay in seconds between requests")
    parser.add_argument("-u", "--users", default="usernames.txt", help="Path to usernames file")
    parser.add_argument("-p", "--passwords", default="passwords.txt", help="Path to passwords file")
    parser.add_argument("--success-str", default=None, help="Substring in response body indicating success")
    parser.add_argument("--failure-str", default=None, help="Substring in response body indicating failure")
    parser.add_argument("--rotate-ua", action="store_true", help="Randomly rotate User-Agent header per request")
    parser.add_argument("--crawl", action="store_true", help="Crawl protected endpoints after successful login")
    parser.add_argument("--paths", default="paths.txt", help="Path to endpoints wordlist file")
    parser.add_argument("-o", "--output", default="results.json", help="Path to output JSON results file")
    args = parser.parse_args()

    try:
        with open(args.users, "r") as f:
            users = [line.strip() for line in f if line.strip()]
        with open(args.passwords, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError as e:
        console.print(f"[bold red][!] Wordlist file missing: {e}[/bold red]")
        sys.exit(1)

    total_combinations = len(users) * len(passwords)
    console.print(f"[bold cyan][*] Starting async audit against {args.url}[/bold cyan] [dim](Concurrency: {args.concurrency}, Delay: {args.delay}s, Rotate UA: {args.rotate_ua}, Total: {total_combinations})[/dim]")
    
    semaphore = asyncio.Semaphore(args.concurrency)
    connector = aiohttp.TCPConnector(ssl=False)
    cookie_jar = aiohttp.CookieJar(unsafe=True)
    
    successful_findings = []
    crawl_results = []
    
    async with aiohttp.ClientSession(connector=connector, cookie_jar=cookie_jar) as session:
        tasks = [
            check_credentials(
                session, args.url, user, pwd, semaphore, 
                success_str=args.success_str, 
                failure_str=args.failure_str, 
                delay=args.delay, 
                rotate_ua=args.rotate_ua,
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
                user, pwd, success, _ = res
                if success:
                    console.print(f"[bold green][+] SUCCESS: {user}:{pwd}[/bold green]")
        
        login_successful = False
        for user, pwd, success, resp in results:
            if success:
                successful_findings.append({
                    "username": user,
                    "password": pwd,
                    "response_snippet": resp[:200]
                })
                login_successful = True
        
        if args.crawl and login_successful:
            console.print("[bold yellow][*] Valid credentials acquired. Starting post-auth endpoint crawl...[/bold yellow]")
            try:
                with open(args.paths, "r") as pf:
                    paths = [line.strip() for line in pf if line.strip()]
                
                base_root = args.url.rsplit('/', 1)[0] + '/'
                
                crawl_tasks = [
                    crawl_endpoint(session, base_root, path, semaphore, delay=args.delay, rotate_ua=args.rotate_ua, proxy=args.proxy)
                    for path in paths
                ]
                c_results = await asyncio.gather(*crawl_tasks)
                
                for path, status, resp in c_results:
                    status_color = "green" if status == 200 else ("yellow" if status == 403 else "red")
                    console.print(f"[{status_color}][{status}] Endpoint: {path}[/{status_color}]")
                    crawl_results.append({
                        "path": path,
                        "status_code": status,
                        "response_snippet": resp[:200]
                    })
            except FileNotFoundError:
                console.print(f"[bold red][!] Paths wordlist file ({args.paths}) not found. Skipping crawl.[/bold red]")

        if successful_findings:
            table = Table(title="[bold green]Successful Credential Findings[/bold green]")
            table.add_column("Username", style="cyan", no_wrap=True)
            table.add_column("Password", style="magenta")
            table.add_column("Response Snippet", style="dim")
            for f in successful_findings:
                table.add_row(f["username"], f["password"], f["response_snippet"].strip())
            console.print(table)

        if crawl_results:
            ctable = Table(title="[bold blue]Post-Auth Crawler Results[/bold blue]")
            ctable.add_column("Path", style="cyan")
            ctable.add_column("Status Code", style="green")
            ctable.add_column("Response Snippet", style="dim")
            for c in crawl_results:
                sc_color = "green" if c["status_code"] == 200 else "red"
                ctable.add_row(c["path"], f"[{sc_color}]{c['status_code']}[/{sc_color}]", c["response_snippet"].strip())
            console.print(ctable)

        output_data = {
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
