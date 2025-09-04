#!/bin/bash
# Quick setup and run for PortScanX

# 1️⃣ Update & install dependencies
sudo apt update
sudo apt install -y nmap ncat python3-pip jq

# 2️⃣ Install python-nmap
pip3 install --upgrade python-nmap

# 3️⃣ Create project folder if it doesn't exist
mkdir -p PortScanX
cd PortScanX

# 4️⃣ Download PortScanX script from GitHub (replace URL with your repo link)
curl -O https://github.com/Atharva1807/PortScanX/blob/main/scanner.py

# 5️⃣ Run PortScanX (admin role, verbose output, JSON results)
python3 portscanx.py 127.0.0.1 --start 20 --end 1024 --timeout 5 --json results --verbose <<EOF
admin
EOF

# 6️⃣ Show JSON results nicely
latest=$(ls -t results_*.json | head -1)
echo -e "\n✅ Latest results file: $latest"
cat $latest | jq
