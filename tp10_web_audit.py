import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

console = Console()

TARGET_URL = "https://httpbin.org/forms/post"

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy"
]

def audit_web_page(url: str):
    """Analyse les en-têtes HTTP de sécurité et extrait les formulaires HTML."""
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        # 1. Vérification des en-têtes
        header_results = {}
        for h in SECURITY_HEADERS:
            header_results[h] = headers.get(h, "ABSENT")
            
        # 2. Parsing du HTML pour trouver les formulaires
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        return header_results, len(forms)
    except Exception as e:
        return None, 0

if __name__ == "__main__":
    console.print("[bold cyan]=== TP10 : Audit Web & Audit d'En-têtes HTTP ===[/bold cyan]\n")
    console.print(f"Cible : [yellow]{TARGET_URL}[/yellow]\n")

    headers_audit, form_count = audit_web_page(TARGET_URL)

    if headers_audit:
        # Affichage du rapport sur les en-têtes
        table = Table(title="Analyse des En-têtes de Sécurité HTTP")
        table.add_column("En-tête de Sécurité", style="cyan")
        table.add_column("Statut / Valeur", style="bold")

        for h, val in headers_audit.items():
            if val == "ABSENT":
                status = "[bold red]ABSENT (Incomplet)[/bold red]"
            else:
                status = f"[bold green]{val}[/bold green]"
            table.add_row(h, status)

        console.print(table)
        console.print(f"\n[bold]Formulaires HTML détectés sur la page :[/bold] [magenta]{form_count}[/magenta]")
    else:
        console.print("[bold red]Erreur de connexion à la cible web.[/bold red]")