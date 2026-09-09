import requests
from rich.console import Console
from rich.table import Table

console = Console()

# IP cibles pour la démonstration d'analyse de réputation
TARGET_IPS = [
    "8.8.8.8",         # Google DNS (Légitime)
    "1.1.1.1",         # Cloudflare DNS (Légitime)
    "185.220.101.5"    # Noeud de sortie Tor (Potentiellement suspect)
]

def check_ip_reputation(ip: str) -> dict:
    """Interroge l'API publique de détection IP (ip-api.com)."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,org,hosting"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        pass
    return {"status": "fail"}

if __name__ == "__main__":
    console.print("[bold cyan]=== TP9 : Threat Intelligence & Enrichment API ===[/bold cyan]\n")

    table = Table(title="Analyse de Réputation IP & Threat Intelligence")
    table.add_column("Adresse IP", style="cyan")
    table.add_column("Pays", style="magenta")
    table.add_column("Organisation", style="yellow")
    table.add_column("Hébergeur / Proxy", style="bold")

    for ip in TARGET_IPS:
        data = check_ip_reputation(ip)
        if data.get("status") == "success":
            country = data.get("country", "Inconnu")
            org = data.get("org", "N/A")
            is_hosting = "[bold red]OUI (Datacenter/Tor)[/bold red]" if data.get("hosting") else "[green]NON (Résidentiel/DNS)[/green]"
            table.add_row(ip, country, org, is_hosting)
        else:
            table.add_row(ip, "Erreur API", "N/A", "[dim]N/A[/dim]")

    console.print(table)