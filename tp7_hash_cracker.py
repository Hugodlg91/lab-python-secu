import hashlib
import time
from rich.console import Console
from rich.table import Table

console = Console()

# Le hash MD5 cible correspond exactement au mot "cyber2026"
TARGET_WORD = "cyber2026"
TARGET_HASH = hashlib.md5(TARGET_WORD.encode('utf-8')).hexdigest()

# Dictionnaire de démonstration
WORDLIST = [
    "admin",
    "123456",
    "password",
    "itis2026",
    "cyber2026",  # Mot de passe recherché
    "administrator"
]

def crack_hash(target_hash: str, wordlist: list[str]) -> tuple[str | None, int]:
    """Tente de trouver le mot de passe en clair correspondant au hash MD5."""
    attempts = 0
    for word in wordlist:
        attempts += 1
        candidate_hash = hashlib.md5(word.encode('utf-8')).hexdigest()
        
        if candidate_hash == target_hash:
            return word, attempts
            
    return None, attempts

if __name__ == "__main__":
    console.print("[bold cyan]=== TP7 : Cassage d'Empreintes Cryptographiques (MD5) ===[/bold cyan]\n")
    console.print(f"Hash cible recherché : [yellow]{TARGET_HASH}[/yellow]\n")

    start_time = time.time()
    found_word, total_attempts = crack_hash(TARGET_HASH, WORDLIST)
    duration = time.time() - start_time

    table = Table(title="Statistiques de l'attaque Hash-Cracking")
    table.add_column("Algorithme", style="magenta")
    table.add_column("Mots testés", style="cyan")
    table.add_column("Temps d'exécution", style="dim")
    table.add_column("Résultat", style="bold")

    status = "[bold green]CASSÉ[/bold green]" if found_word else "[bold red]NON TROUVÉ[/bold red]"
    table.add_row("MD5", str(total_attempts), f"{duration:.4f}s", status)

    console.print(table)

    if found_word:
        console.print(f"\n[bold green]✓ Correspondance trouvée ![/bold green]")
        console.print(f"Mot de passe en clair : [black on green]{found_word}[/black on green]")
    else:
        console.print("\n[bold red]✕ Échec : Aucun mot correspondant dans le dictionnaire.[/bold red]")