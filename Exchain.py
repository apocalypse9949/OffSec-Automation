exploit_chain = {
    "CVE-2017-0144": ["smb_exploit", "mimikatz_dump"],
    "CVE-2021-41773": ["apache_rce", "local_priv_esc"],
    "CVE-2020-14145": ["ssh_user_enum", "ssh_root_priv_esc"]
}

def execute_exploit_chain(cve):
    if cve in exploit_chain:
        for exploit in exploit_chain[cve]:
            print(f"[+] Executing {exploit}...")
            
            time.sleep(2)
            print(f"[✔] {exploit} executed successfully.")
    else:
        print("[-] No known exploit chain.")

execute_exploit_chain("CVE-2017-0144")
