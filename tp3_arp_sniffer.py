import scapy.all as scapy
from collections import defaultdict
from rich.console import Console
from rich.table import Table

console = Console()

def create_dummy_pcap(filename="traffic_sample.pcap"):
    """Génère un fichier PCAP de démonstration avec une attaque ARP Spoofing."""
    packets = [
        scapy.Ether(src="00:11:22:33:44:55")/scapy.ARP(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55"),
        scapy.Ether(src="66:77:88:99:AA:BB")/scapy.ARP(op=2, psrc="192.168.1.50", hwsrc="66:77:88:99:AA:BB"),
        # Attaque : La même IP (192.168.1.1) émet avec une adresse MAC différente
        scapy.Ether(src="DE:AD:BE:EF:00:01")/scapy.ARP(op=2, psrc="192.168.1.1", hwsrc="DE:AD:BE:EF:00:01"),
    ]
    scapy.wrpcap(filename, packets)

def analyze_pcap(filename="traffic_sample.pcap"):
    """Analyse le fichier PCAP et repère les conflits d'adresses MAC/IP (ARP Poisoning)."""
    packets = scapy.rdpcap(filename)
    ip_mac_mapping = defaultdict(set)
    alerts = []

    for pkt in packets:
        if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:  # is-at (réponse ARP)
            ip = pkt[scapy.ARP].psrc
            mac = pkt[scapy.ARP].hwsrc
            
            if ip in ip_mac_mapping and mac not in ip_mac_mapping[ip]:
                alerts.append((ip, list(ip_mac_mapping[ip])[0], mac))
            
            ip_mac_mapping[ip].add(mac)

    return ip_mac_mapping, alerts

if __name__ == "__main__":
    console.print("[bold cyan]=== TP3 : Détection ARP Poisoning & Sniffing ===[/bold cyan]\n")
    
    # 1. Génération du fichier de capture
    pcap_file = "traffic_sample.pcap"
    create_dummy_pcap(pcap_file)
    console.print(f"[dim]Fichier de capture généré : {pcap_file}[/dim]")

    # 2. Analyse forensique du trafic
    mappings, alerts = analyze_pcap(pcap_file)

    # Affichage de la table ARP apprise
    table = Table(title="Table d'associations IP / MAC détectées")
    table.add_column("Adresse IP", style="cyan")
    table.add_column("Adresse(s) MAC associées", style="magenta")
    
    for ip, macs in mappings.items():
        table.add_row(ip, ", ".join(macs))
    console.print(table)

    # Affichage des alertes de sécurité
    if alerts:
        console.print("\n[bold red]⚠ ALERTE SÉCURITÉ : ANOMALIE ARP DÉTECTÉE ![/bold red]")
        for ip, old_mac, new_mac in alerts:
            console.print(f"[bold red]→ Usurpation détectée pour {ip} :[/bold red] MAC légitime [green]{old_mac}[/green] remplacée par [red]{new_mac}[/red]")
    else:
        console.print("\n[green]✓ Aucun comportement suspect détecté dans la capture.[/green]")