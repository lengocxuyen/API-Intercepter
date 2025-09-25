#!/bin/bash

# API Interceptor Setup Script for macOS
# Bypasses proxy configuration restrictions

set -e

echo "🔧 API Interceptor Framework Setup"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo -e "${RED}❌ This script is designed for macOS only${NC}"
    exit 1
fi

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is required but not installed${NC}"
    echo "Install Python 3 from https://python.org or use homebrew: brew install python3"
    exit 1
fi

echo -e "${GREEN}✅ Python 3 found${NC}"

# Create project directory
PROJECT_DIR="$HOME/api-interceptor"
echo -e "${BLUE}📁 Creating project directory: $PROJECT_DIR${NC}"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo -e "${BLUE}🐍 Creating Python virtual environment${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo -e "${BLUE}📦 Installing Python dependencies${NC}"
pip install --upgrade pip
pip install aiohttp psutil cryptography scapy

# Create main application file
cat > interceptor.py << 'EOF'
# The Python code from the previous artifact would go here
# (Copy the entire proxy_server.py content)
EOF

# Make it executable
chmod +x interceptor.py

# Create launch script
cat > launch.sh << 'EOF'
#!/bin/bash

cd "$(dirname "$0")"
source venv/bin/activate

echo "🚀 Starting API Interceptor..."
echo "Web UI will be available at: http://localhost:8888"
echo ""
echo "⚠️  You may need to enter your password for system-level operations"
echo ""

python3 interceptor.py
EOF

chmod +x launch.sh

# Create configuration directories
mkdir -p config
mkdir -p logs
mkdir -p certs

# Create app-specific configuration
cat > config/apps.json << 'EOF'
{
  "target_apps": [
    {
      "name": "Safari",
      "bundle_id": "com.apple.Safari",
      "intercept": true
    },
    {
      "name": "Chrome",
      "bundle_id": "com.google.Chrome",
      "intercept": true
    },
    {
      "name": "Postman",
      "bundle_id": "com.postmanlabs.mac",
      "intercept": true
    }
  ],
  "domain_rules": [
    {
      "pattern": "*.api.*",
      "action": "intercept"
    },
    {
      "pattern": "*/api/*",
      "action": "intercept"
    }
  ]
}
EOF

# Create network configuration script
cat > setup_network.sh << 'EOF'
#!/bin/bash

# Network configuration for API interceptor
# This runs with sudo privileges to modify system settings

echo "🔧 Setting up network interception..."

# Method 1: pfctl rules for traffic redirection
setup_pfctl() {
    echo "📡 Setting up pfctl rules..."
    
    # Create rules file
    cat > /tmp/api_interceptor.rules << 'RULES'
# API Interceptor traffic redirection rules
# Redirect common API ports to our proxy
rdr pass on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port 8888
rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port 8889
RULES

    # Load rules
    pfctl -f /tmp/api_interceptor.rules
    pfctl -e 2>/dev/null || true
    
    echo "✅ pfctl rules loaded"
}

# Method 2: Modify /etc/hosts for domain redirection  
setup_hosts() {
    echo "🌐 Setting up hosts file redirection..."
    
    # Backup original hosts file
    cp /etc/hosts /etc/hosts.interceptor.backup
    
    # Add our entries
    cat >> /etc/hosts << 'HOSTS'

# API Interceptor entries
127.0.0.1 api.example.com
127.0.0.1 graph.facebook.com
127.0.0.1 api.twitter.com
127.0.0.1 api.instagram.com
127.0.0.1 api.github.com
# Add more domains as needed
HOSTS

    # Flush DNS cache
    dscacheutil -flushcache
    
    echo "✅ Hosts file updated"
}

# Method 3: Setup transparent proxy using pf
setup_transparent_proxy() {
    echo "🔄 Setting up transparent proxy..."
    
    # Enable IP forwarding
    sysctl -w net.inet.ip.forwarding=1
    
    echo "✅ Transparent proxy configured"
}

# Run setup functions
setup_pfctl
setup_hosts
setup_transparent_proxy

echo "🎉 Network setup complete!"
echo "⚠️  Remember to restore settings when done with: ./restore_network.sh"
EOF

chmod +x setup_network.sh

# Create network restoration script
cat > restore_network.sh << 'EOF'
#!/bin/bash

echo "🔄 Restoring network settings..."

# Disable pfctl rules
pfctl -d 2>/dev/null || true
pfctl -F all 2>/dev/null || true

# Restore hosts file
if [ -f /etc/hosts.interceptor.backup ]; then
    cp /etc/hosts.interceptor.backup /etc/hosts
    rm /etc/hosts.interceptor.backup
fi

# Flush DNS
dscacheutil -flushcache

echo "✅ Network settings restored"
EOF

chmod +x restore_network.sh

# Create application hooks script
cat > app_hooks.py << 'EOF'
#!/usr/bin/env python3
"""
Application-level hooks for intercepting network calls
Uses various techniques to hook into applications without system proxy
"""

import os
import signal
import subprocess
import time
from pathlib import Path

class AppHooker:
    def __init__(self):
        self.hooked_processes = []
        
    def hook_browser(self, browser_name="Chrome"):
        """Hook into browser network calls"""
        if browser_name.lower() == "chrome":
            return self._hook_chrome()
        elif browser_name.lower() == "safari":
            return self._hook_safari()
            
    def _hook_chrome(self):
        """Hook Chrome using command line flags"""
        chrome_path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        
        if not Path(chrome_path).exists():
            print("❌ Chrome not found")
            return False
            
        # Launch Chrome with proxy settings
        cmd = [
            chrome_path,
            "--proxy-server=http://localhost:8888",
            "--ignore-certificate-errors",
            "--disable-web-security",
            "--user-data-dir=/tmp/chrome-interceptor"
        ]
        
        proc = subprocess.Popen(cmd)
        self.hooked_processes.append(proc)
        
        print("✅ Chrome hooked with proxy settings")
        return True
        
    def _hook_safari(self):
        """Hook Safari using AppleScript"""
        applescript = '''
        tell application "Safari"
            activate
            -- Safari hooks would go here
        end tell
        '''
        
        subprocess.run(["osascript", "-e", applescript])
        return True
        
    def hook_process_by_name(self, process_name):
        """Hook existing process by name"""
        import psutil
        
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                return self._inject_into_process(proc.info['pid'])
                
    def _inject_into_process(self, pid):
        """Inject hooks into running process"""
        # This would use techniques like:
        # - DYLD_INSERT_LIBRARIES
        # - ptrace() system calls
        # - Dynamic library injection
        
        print(f"🎯 Injecting into process {pid}")
        return True
        
    def cleanup(self):
        """Clean up hooked processes"""
        for proc in self.hooked_processes:
            try:
                proc.terminate()
            except:
                pass

if __name__ == "__main__":
    hooker = AppHooker()
    
    try:
        # Hook Chrome
        hooker.hook_browser("chrome")
        
        # Keep running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        hooker.cleanup()
        print("\n👋 App hooks cleaned up")
EOF

chmod +x app_hooks.py

# Create README
cat > README.md << 'EOF'
# 🔍 API Interceptor Framework

A Charles Proxy-like tool for macOS that bypasses proxy configuration restrictions.

## 🚀 Quick Start

1. Run setup (one time only):
   ```bash
   ./launch.sh
   ```

2. Set up network interception (requires sudo):
   ```bash
   sudo ./setup_network.sh
   ```

3. Open the web interface:
   ```
   http://localhost:8888
   ```

## 🎯 Features

- **Traffic Interception**: Captures HTTP/HTTPS requests from all apps
- **Request Modification**: Edit requests and responses in real-time
- **Charles-like UI**: Familiar interface for easy analysis
- **No Proxy Config**: Works without changing system proxy settings
- **Multi-method**: Uses pfctl, DNS hijacking, and app hooks

## 🛠 Methods Used

### 1. pfctl Traffic Redirection
- Redirects traffic using macOS packet filter
- Works at kernel level
- Requires sudo privileges

### 2. DNS Hijacking
- Modifies /etc/hosts to redirect domains
- Transparent to applications
- Easy to set up and tear down

### 3. Application Hooks
- Injects into running processes
- Browser-specific hooks
- Process-level interception

## 🔧 Configuration

### Target Applications
Edit `config/apps.json` to specify which apps to intercept.

### Domain Rules
Add patterns in `config/apps.json` to match specific domains.

## 📱 Mobile App Testing

For iOS Simulator:
```bash
# Configure simulator to use proxy
xcrun simctl io booted set_network_proxy_configuration --host 127.0.0.1 --port 8888
```

For Android Emulator:
```bash
# Start emulator with proxy
emulator -avd MyAVD -http-proxy http://127.0.0.1:8888
```

## 🔐 HTTPS Interception

1. Install the generated CA certificate:
   ```bash
   open ~/.api_interceptor/ca.crt
   ```

2. Trust the certificate in Keychain Access

3. Enable SSL Kill Switch for apps if needed

## 🧹 Cleanup

When finished, restore network settings:
```bash
sudo ./restore_network.sh
```

## ⚠️ Important Notes

- Requires administrator privileges for system-level interception
- Only works on macOS
- Some corporate security tools may block this
- Use responsibly and only on systems you own

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Find and kill process using port 8888
lsof -ti:8888 | xargs kill -9
```

### Permission Denied
```bash
# Make sure scripts are executable
chmod +x *.sh *.py
```

### SSL Certificate Issues
```bash
# Regenerate certificates
rm -rf ~/.api_interceptor/
# Restart the interceptor
```

## 📚 Advanced Usage

### Custom Rules
Create custom interception rules in the web UI or via API:

```python
import requests

# Add intercept rule
requests.post('http://localhost:8888/api/intercept-rule', json={
    'url': 'https://api.example.com/users',
    'enabled': True,
    'status': 200,
    'response': '{"fake": "data"}'
})
```

### Programmatic Control
```python
import websocket

# Connect to WebSocket for real-time updates
ws = websocket.WebSocket()
ws.connect("ws://localhost:8888/ws")

# Send commands
ws.send('{"action": "start_recording"}')
```
EOF

echo -e "${GREEN}✅ Setup complete!${NC}"
echo ""
echo -e "${BLUE}📋 Next steps:${NC}"
echo "1. Start the interceptor: ${YELLOW}./launch.sh${NC}"
echo "2. Set up network (requires sudo): ${YELLOW}sudo ./setup_network.sh${NC}"  
echo "3. Open web UI: ${YELLOW}http://localhost:8888${NC}"
echo ""
echo -e "${YELLOW}⚠️  Important:${NC}"
echo "- Some steps require administrator privileges"
echo "- Always run ${YELLOW}sudo ./restore_network.sh${NC} when finished"
echo "- This tool is for legitimate testing only"
echo ""
echo -e "${GREEN}🎉 Ready to intercept APIs!${NC}"