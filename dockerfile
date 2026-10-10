FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    nmap \
    enum4linux \
    smbclient \
    snmp snmp-mibs-downloader \
    ldap-utils \
    nfs-common \
    nikto \
    whatweb \
    dirb \
    hydra \
    john \
    hashcat \
    tcpdump \
    aircrack-ng \
    dnsutils \
    whois \
    git \
    sslscan \
    && rm -rf /var/lib/apt/lists/*

# theHarvester (qua pip để có bản mới)
RUN pip3 install --break-system-packages theHarvester \
    python-whois dnspython requests beautifulsoup4 \
    PyYAML jinja2 colorama \
    fastapi uvicorn websockets \
    scapy

# Cài searchsploit
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

WORKDIR /app
COPY . /app

RUN mkdir -p /app/output /app/plugins

EXPOSE 8000

# Chạy dashboard mặc định
CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8000"]