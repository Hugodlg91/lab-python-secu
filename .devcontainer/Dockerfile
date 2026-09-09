FROM mcr.microsoft.com/devcontainers/python:3.10-bullseye

# Installation des outils système (nmap, netcat, etc.)
RUN apt-get update && apt-get install -y \
    nmap \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# Installation des paquets Python nécessaires au cours
RUN pip install --no-cache-dir \
    python-nmap \
    requests \
    cryptography \
    pefile \
    rich \
    python-dotenv \
    beautifulsoup4
