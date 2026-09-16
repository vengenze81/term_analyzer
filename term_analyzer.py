import asyncio
import aiohttp
import argparse
import sys
import json
from datetime import datetime, timezone
from urllib.parse import urljoin

async def check_credentials(session, url, username, password, semaphore, proxy=None):
    async with semaphore:
        payload = {"username": username, "password": password}
        request_kwargs = {"data": payload, "ssl": False}
        if proxy:
            request_kwargs["proxy"] = proxy
        
        try:
            async with session.post(url, **request_kwargs) as response:
                text = await response.text()
                if response.status == 200:
                    return (username, password, True, text)
                return (username, password, False, text)
        except Exception as e:
            return (username, password, False, str(e))

async def crawl_endpoint(session, base_url, path, semaphore, proxy=None):
    async with semaphore:
        target_url = urljoin(base_url, path)
        request_kwargs = {"ssl": False}
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
    parser.add_argument("-u", "--users", default="usernames.txt", help="Path to usernames file")
    parser.add_argument("-p", "--passwords", default="passwords.txt", help="Path to passwords file")
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
        print(f"[!] Wordlist file missing: {e}")
        sys.exit(1)

    print(f"[*] Starting async audit against {args.url} (Concurrency: {args.concurrency})")
    
    semaphore = asyncio.Semaphore(args.concurrency)
    connector = aiohttp.TCPConnector(ssl=False)
    
    successful_findings = []
    crawl_results = []
    
    async with aiohttp.ClientSession(connector=connector) as session:
        # Phase 1: Credential Auditing
        tasks = [
            check_credentials(session, args.url, user, pwd, semaphore, proxy=args.proxy)
            for user in users for pwd in passwords
        ]
        results = await asyncio.gather(*tasks)
        
        login_successful = False
        for user, pwd, success, resp in results:
            if success:
                print(f"[+] SUCCESS: {user}:{pwd}")
                successful_findings.append({
                    "username": user,
                    "password": pwd,
                    "response_snippet": resp[:200]
                })
                login_successful = True
        
        # Phase 2: Post-Auth Endpoint Crawling (if enabled and login succeeded)
        if args.crawl and login_successful:
            print("[*] Valid credentials acquired. Starting post-auth endpoint crawl...")
            try:
                with open(args.paths, "r") as pf:
                    paths = [line.strip() for line in pf if line.strip()]
                
                # Derive base URL root (e.g., http://127.0.0.1:8080/ from http://127.0.0.1:8080/login)
                base_root = args.url.rsplit('/', 1)[0] + '/'
                
                crawl_tasks = [
                    crawl_endpoint(session, base_root, path, semaphore, proxy=args.proxy)
                    for path in paths
                ]
                c_results = await asyncio.gather(*crawl_tasks)
                
                for path, status, resp in c_results:
                    print(f"[{status}] Endpoint: {path}")
                    crawl_results.append({
                        "path": path,
                        "status_code": status,
                        "response_snippet": resp[:200]
                    })
            except FileNotFoundError:
                print(f"[!] Paths wordlist file ({args.paths}) not found. Skipping crawl.")

        # Export all findings to JSON
        output_data = {
            "target": args.url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "successful_logins": successful_findings,
            "crawl_results": crawl_results
        }
        
        try:
            with open(args.output, "w") as out_f:
                json.dump(output_data, out_f, indent=4)
            print(f"[*] Results successfully saved to {args.output}")
        except Exception as e:
            print(f"[!] Failed to save results: {e}")

if __name__ == "__main__":
    asyncio.run(main())
