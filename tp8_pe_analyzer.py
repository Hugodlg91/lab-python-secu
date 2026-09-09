import hashlib
import pefile
from rich.console import Console
from rich.table import Table

console = Console()

def create_mock_pe_file(filename="sample_malware.exe"):
    """Génère un faux binaire PE pour la démonstration."""
    # En-tête DOS minimal + Signature PE
    dos_header = b'MZ' + b'\x90' * 58 + b'\x80\x00\x00\x00'
    pe_header = b'\x00' * 64 + b'PE\x00\x00' + b'\x4c\x01' + b'\x03\x00' + b'\x00' * 16
    optional_header = b'\x0b\x01' + b'\x00' * 222
    sections = b'.text\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x60'
    
    with open(filename, "wb") as f:
        f.write(dos_header + pe_header + optional_header + sections + b"\x90" * 512)

def analyze_pe(filename):
    """Calcule les hashs et extrait la structure basique du fichier PE."""
    with open(filename, "rb") as f:
        content = f.read()
        md5_hash = hashlib.md5(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()

    pe = pefile.PE(filename)
    
    sections_info = []
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        size = section.SizeOfRawData
        sections_info.append((name, hex(section.VirtualAddress), size))

    return md5_hash, sha256_hash, sections_info

if __name__ == "__main__":
    console.print("[bold cyan]=== TP8 : Analyse Forensics de Fichier Binaire (PE) ===[/bold cyan]\n")

    file_path = "sample_malware.exe"
    create_mock_pe_file(file_path)
    console.print(f"[dim]Fichier binaire de démonstration généré : {file_path}[/dim]\n")

    md5_h, sha256_h, sections = analyze_pe(file_path)

    # Affichage des hashs
    console.print(f"[bold]MD5    :[/bold] [yellow]{md5_h}[/yellow]")
    console.print(f"[bold]SHA256 :[/bold] [yellow]{sha256_h}[/yellow]\n")

    # Table des sections
    table = Table(title="Sections PE détectées")
    table.add_column("Nom Section", style="magenta")
    table.add_column("Adresse Virtuelle", style="cyan")
    table.add_column("Taille (Octets)", style="green")

    for name, addr, size in sections:
        table.add_row(name, addr, str(size))

    console.print(table)