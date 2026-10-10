# 1. Cài thêm dependencies
pip install scapy
sudo apt install hydra john hashcat aircrack-ng tcpdump
# Prowler / ScoutSuite (tùy chọn):
pip install prowler scoutsuite

# 2. Scan chain tự động: M03 → M04 → M05 → M11
python main.py scan example.com \
    --modules m04_enumeration,m05_vuln_analysis,m11_web_hacking \
    --chain

# 3. Chỉ Hydra trên các service đã phát hiện
python main.py scan 192.168.1.10 \
    --modules m03_scanning,m06_system_hacking \
    --chain

# 4. Sniffing 30s trên eth0
python main.py scan example.com \
    --modules m08_sniffing

# 5. WiFi scan 60s
python main.py scan example.com \
    --modules m13_wireless

# 6. Cloud audit AWS
python main.py scan aws-account \
    --modules m16_cloud