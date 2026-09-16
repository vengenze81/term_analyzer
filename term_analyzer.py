import asyncio
import aiohttp
import argparse
import sys

async def check_credentials(session, url, username, password, proxy=None):
    payload = {"username": username, "password": password}
    request_kwargs = {
        "data": payload,
        "ssl": False
    }
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

async def main():
    parser = argparse.ArgumentParser(description="Async Terminal Analyzer / Login Auditor")
    parser.add_argument("--url", default="http://127.0.0.1:8080/login", help="Target URL")
    parser.add_argument("--proxy", default=None, help="HTTP Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-u", "--users", default="usernames.txt", help="Path to usernames file")
    parser.add_argument("-p", "--passwords", default="passwords.txt", help="Path to passwords file")
    args = parser.parse_args()

    try:
        with open(args.users, "r") as f:
            users = [line.strip() for line in f if line.strip()]
        with open(args.passwords, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError as e:
        print(f"[!] Wordlist file missing: {e}")
        sys.exit(1)

    print(f"[*] Starting async scan against {args.url} (Proxy: {args.proxy})")
    
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            check_credentials(session, args.url, user, pwd, proxy=args.proxy)
            for user in users for pwd in passwords
        ]
        results = await asyncio.gather(*tasks)
        
        for user, pwd, success, resp in results:
            if success:
                print(f"[+] SUCCESS: {user}:{pwd}")

if __name__ == "__main__":
    asyncio.run(main())
