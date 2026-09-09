import nmap

def scan_target(target):
    nm = nmap.PortScanner()
    print(f"[*] Lancement du scan TCP Connect sur {target}...")
    nm.scan(hosts=target, arguments='-sT -F')
    
    for host in nm.all_hosts():
        print(f"\nCible : {host} ({nm[host].hostname()})")
        print(f"État : {nm[host].state()}")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                state = nm[host][proto][port]['state']
                name = nm[host][proto][port]['name']
                print(f"  Port {port}/TCP \t [{state}] \t Service: {name}")

if __name__ == "__main__":
    scan_target("scanme.nmap.org")