import hashlib
from cryptography.fernet import Fernet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Épreuve 1 : Hash MD5 d'une clé d'accès
STAGE1_HASH = "827ccb0eea8a706c4c34a16891f84e7b"  # Correspond à "12345"
DICTIONARY = ["admin", "root", "12345", "password", "itis2026"]

# Épreuve 2 : Fichier secret chiffré
FERNET_KEY = Fernet.generate_key()
cipher_suite = Fernet(FERNET_KEY)
SECRET_FLAG = b"FLAG{ITIS_PYTHON_SECURITY_MASTER_2026}"
ENCRYPTED_MESSAGE = cipher_suite.encrypt(SECRET_FLAG)

def solve_stage_1():
    """Étape 1 : Brute-force local du hash MD5."""
    for word in DICTIONARY:
        if hashlib.md5(word.encode()).hexdigest() == STAGE1_HASH:
            return word
    return None

def solve_stage_2(key):
    """Étape 2 : Déchiffrement du drapeau final."""
    try:
        suite = Fernet(key)
        decrypted = suite.decrypt(ENCRYPTED_MESSAGE)
        return decrypted.decode('utf-8')
    except Exception:
        return None

if __name__ == "__main__":
    console.print("[bold cyan]=== TP11 : CTF Final - Challenge d'Automation ===[/bold cyan]\n")

    # Résolution Étape 1
    found_key = solve_stage_1()
    
    # Résolution Étape 2
    flag = solve_stage_2(FERNET_KEY)

    table = Table(title="Progression du Challenge CTF")
    table.add_column("Étape", style="cyan")
    table.add_column("Moteur / Notions", style="magenta")
    table.add_column("Statut", style="bold")

    if found_key:
        table.add_row("Étape 1", "Cassage Hash MD5", f"[bold green]RÉUSSI (Clé: {found_key})[/bold green]")
    else:
        table.add_row("Étape 1", "Cassage Hash MD5", "[bold red]ÉCHEC[/bold red]")

    if flag:
        table.add_row("Étape 2", "Déchiffrement Fernet AES", "[bold green]RÉUSSI[/bold green]")
    else:
        table.add_row("Étape 2", "Déchiffrement Fernet AES", "[bold red]ÉCHEC[/bold red]")

    console.print(table)

    if flag:
        console.print("\n", Panel(f"[bold green]FÉLICITATIONS ! FLAG : {flag}[/bold green]", title="Victoire CTF"))