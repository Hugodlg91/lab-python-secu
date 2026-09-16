FROM mcr.microsoft.com/devcontainers/python:3.10-bullseye

RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       nmap \
       netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    python-nmap \
    requests \
    cryptography \
    pefile \
    rich \
    python-dotenv \
    beautifulsoup4