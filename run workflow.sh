# 1. Docker all-in-one
docker compose up -d --build

# 2. Mở dashboard
open http://localhost:8000

# 3. Chạy từ CLI với profile
python main.py scan 192.168.1.10 --profile stealth --chain

# 4. Xem MITRE techniques
cat output/ceh_*.json | python -c "
import json,sys
d = json.load(sys.stdin)
for tid, info in d.get('_mitre_attack', {}).items():
    print(f'{tid:12} {info[\"name\"]}')
"

# 5. Sinh báo cáo LLM
export ANTHROPIC_API_KEY=sk-ant-...
python main.py report output/ceh_192.168.1.10_*.json --provider anthropic

# 6. Viết plugin riêng
cp plugins/example_plugin.py plugins/my_custom_check.py
# Sửa logic, sau đó:
python main.py scan example.com --modules my_custom_check