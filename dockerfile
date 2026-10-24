FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
# Đảm bảo Python tìm thấy các module trong thư mục /app
ENV PYTHONPATH=/app

# ============================================================
# PHẦN 1: CÀI ĐẶT CÁC GÓI PHỤ THUỘC VÀ PYTHON 3.12 TỪ SOURCE
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    wget \
    curl \
    llvm \
    libncurses5-dev \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libffi-dev \
    liblzma-dev \
    python3-openssl \
    git \
    default-jre \
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
    sslscan \
    seclists \
    theharvester \
    afl++ \
    lynis \
    metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

# Tải và biên dịch Python 3.12.8 từ source
RUN wget https://www.python.org/ftp/python/3.12.8/Python-3.12.8.tgz \
    && tar -xvf Python-3.12.8.tgz \
    && cd Python-3.12.8 \
    && ./configure --enable-optimizations --with-ensurepip=install \
    && make -j$(nproc) \
    && make altinstall \
    && cd .. \
    && rm -rf Python-3.12.8 Python-3.12.8.tgz

# Cài đặt pip và nâng cấp lên bản mới nhất cho Python 3.12
RUN python3.12 -m ensurepip --upgrade \
    && python3.12 -m pip install --upgrade pip

# ============================================================
# PHẦN 1b: CÀI HELM TỪ BINARY
# ============================================================
RUN curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# ============================================================
# PHẦN 2: THƯ VIỆN PYTHON CƠ BẢN & SỬA LỖI PYDANTIC
# ============================================================
RUN python3.12 -m pip install \
    "pydantic>=2.13.0" \
    "fastapi>=0.128.1" "uvicorn[standard]" websockets \
    "PyYAML>=6.0" \
    email-validator \
    python-whois dnspython requests beautifulsoup4 \
    jinja2 colorama \
    pyjwt "passlib[bcrypt]" python-multipart \
    scapy \
    anthropic openai \
    APScheduler Ray \
    networkx==3.4.2 pyvis \
    elasticsearch splunk-sdk elasticsearch-dsl \
    paramiko pymetasploit3 \
    vt-py shodan censys \
    scikit-learn \
    boto3 kubernetes \
    cloudscraper wafw00f

# ============================================================
# PHẦN 3: CÁC MODULE CHUYÊN BIỆT (BỎ QUA DEPENDENCY NẾU CẦN)
# ============================================================
RUN python3.12 -m pip install --no-deps pwncat-cs
RUN python3.12 -m pip install --no-deps atomic-operator
RUN python3.12 -m pip install boofuzz
RUN python3.12 -m pip install c7n
RUN python3.12 -m pip install slither-analyzer
RUN python3.12 -m pip install --no-deps mythril || echo "[!] Mythril bỏ qua"
RUN python3.12 -m pip install checkov
RUN python3.12 -m pip install prowler || echo "[!] Prowler bỏ qua"

# ============================================================
# PHẦN 4: THƯ VIỆN CHO CÁC MODULE NÂNG CAO MỚI
# ============================================================
RUN python3.12 -m pip install pyspark
RUN python3.12 -m pip install sigma-cli pySigma
RUN python3.12 -m pip install sliver-py || echo "[!] Sliver bỏ qua"

# ============================================================
# PHẦN 5: CÀI CÁC TOOL BINARY
# ============================================================
# Trivy - cài qua apt của Kali
RUN apt-get update && apt-get install -y --no-install-recommends trivy && rm -rf /var/lib/apt/lists/*

# kube-bench - tải file .deb từ phiên bản cụ thể và cài đặt
RUN curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.9.3/kube-bench_0.9.3_linux_amd64.deb -o /tmp/kube-bench.deb \
    && dpkg -i /tmp/kube-bench.deb \
    && rm /tmp/kube-bench.deb

# tfsec - tải binary trực tiếp từ GitHub (phiên bản mới nhất)
RUN curl -L https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64 \
    -o /usr/local/bin/tfsec \
    && chmod +x /usr/local/bin/tfsec

# kube-hunter - cài qua pip
RUN python3.12 -m pip install kube-hunter \
    || echo "[!] kube-hunter không cài được - bỏ qua"

# ============================================================
# PHẦN 6: SEARCHSPLOIT & CẤU HÌNH APP
# ============================================================
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

WORKDIR /app
COPY . /app

RUN mkdir -p /app/output /app/plugins /app/compliance_evidence

EXPOSE 8000

CMD ["python3.12", "-m", "uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8000"]