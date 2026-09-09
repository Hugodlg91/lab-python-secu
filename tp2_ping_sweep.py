import socket
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table

console = Console()

# Liste d'hôtes / IP cibles à tester
TARGET_HOSTS = [
    "127.0.0.1",
    "8.8.8.8",
    "1.1.1.1",
    "scanme.nmap.org",
    "192.168.1.254"
]

def check_host(host: str) -> tuple[str, bool, str]:
    """Vérifie la joignabilité d'un hôte sur le port 80/443 (Socket TCP)."""
    for port in [80, 443, 22]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return host, True, f"Port {port} ouvert"
        except Exception as e:
            pass
    return host, False, "Injoignable"

if __name__ == "__main__":
    console.print("[bold cyan]=== TP2 : Ping Sweep & Découverte Réseau ===[/bold cyan]\n")
    
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check_host, TARGET_HOSTS))
        
    table = Table(title="Résultats de la découverte d'hôtes")
    table.add_column("Cible / IP", style="cyan")
    table.add_column("Statut", style="bold")
    table.add_column("Détail", style="dim")
    
    for host, active, detail in results:
        status = "[bold green]ACTIF[/bold green]" if active else "[bold red]INACTIF[/bold red]"
        table.add_row(host, status, detail)
        
    console.print(table)