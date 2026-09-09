FROM mcr.microsoft.com/devcontainers/python:3.10-bullseye

RUN apt-get update && apt-get install -y \
    nmap \
    netcat \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    python-nmap \
    requests \
    cryptography \
    pefile \
    rich \
    python-dotenv \
    beautifulsoup4