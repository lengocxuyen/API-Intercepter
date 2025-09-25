# 🔍 Hướng Dẫn Sử Dụng API Interceptor

## 🎯 Tổng Quan

Framework này giúp bạn intercept tất cả HTTP/HTTPS requests trên macOS mà không cần thay đổi proxy settings trong System Preferences. Đặc biệt hữu ích khi máy công ty bị khóa cấu hình.

## 🚀 Cài Đặt Nhanh

### Bước 1: Download và Setup
```bash
# Tải về và chạy script setup
curl -O https://your-repo.com/setup.sh
chmod +x setup.sh
./setup.sh
```

### Bước 2: Khởi động Interceptor
```bash
cd ~/api-interceptor
./launch.sh
```

### Bước 3: Cấu hình Network (cần sudo)
```bash
sudo ./setup_network.sh
```

### Bước 4: Mở Web UI
Truy cập: http://localhost:8888

## 🎮 Sử Dụng Web Interface

### Dashboard Chính
- **Start Recording**: Bắt đầu ghi lại requests
- **Stop**: Dừng ghi lại  
- **Clear**: Xóa tất cả requests đã ghi

### Panel Requests (Trái)
- Hiển thị danh sách tất cả requests
- Click vào request để xem chi tiết
- Màu vàng = request bị intercept

### Panel Chi Tiết (Phải)
1. **Overview**: Thông tin tổng quan
2. **Request**: Headers và body của request
3. **Response**: Headers và body của response  
4. **Intercept**: Cấu hình intercept rules

## 🎯 Các Phương Pháp Intercept

### 1. pfctl Traffic Redirection
```bash
# Tự động redirect traffic qua proxy
# Hoạt động ở kernel level
sudo pfctl -f /tmp/api_interceptor.rules
sudo pfctl -e
```

### 2. DNS Hijacking
```bash
# Redirect domains qua /etc/hosts
echo "127.0.0.1 api.example.com" >> /etc/hosts
sudo dscacheutil -flushcache
```

### 3. Application Hooks
```bash
# Hook vào browser hoặc app cụ thể
python3 app_hooks.py --target chrome
```

## 🔧 Cấu Hình Chi Tiết

### Target Applications
Chỉnh sửa `config/apps.json`:
```json
{
  "target_apps": [
    {
      "name": "MyApp",
      "bundle_id": "com.company.myapp", 
      "intercept": true
    }
  ],
  "domain_rules": [
    {
      "pattern": "*.api.*",
      "action": "intercept"
    }
  ]
}
```

### Intercept Rules
Tạo rules để modify responses:
```json
{
  "url": "https://api.example.com/users",
  "enabled": true,
  "status": 200,
  "response": "{\"fake\": \"data\"}"
}
```

## 📱 Testing Mobile Apps

### iOS Simulator
```bash
# Cấu hình proxy cho simulator
xcrun simctl io booted set_network_proxy_configuration \
  --host 127.0.0.1 --port 8888
```

### Android Emulator  
```bash
# Chạy emulator với proxy
emulator -avd MyAVD -http-proxy http://127.0.0.1:8888
```

### Physical Devices
1. Connect device to same WiFi
2. Set manual proxy: `<your-mac-ip>:8888`

## 🔐 HTTPS Interception Setup

### Bước 1: Generate CA Certificate
```bash
# Framework tự động tạo CA cert
ls ~/.api_interceptor/
# ca.crt  ca.key
```

### Bước 2: Install CA Certificate
```bash
# Mở certificate để install
open ~/.api_interceptor/ca.crt

# Hoặc import vào Keychain
security add-trusted-cert -d -r trustRoot \
  -k ~/Library/Keychains/login.keychain \
  ~/.api_interceptor/ca.crt
```

### Bước 3: Trust Certificate
1. Mở **Keychain Access**
2. Tìm "API Interceptor Root CA"
3. Double-click → Trust → Always Trust

### Cho iOS Device
```bash
# Copy cert to device qua AirDrop hoặc email
# Settings → General → About → Certificate Trust Settings
# Enable trust cho "API Interceptor Root CA"
```

## 🎨 UI Features Chi Tiết

### Request List Features
- **Method Tags**: Màu sắc khác nhau cho GET/POST/PUT/DELETE
- **Status Codes**: Hiển thị response status
- **Timestamps**: Thời gian chính xác của request
- **Search/Filter**: Lọc requests theo URL, method, status

### Detail Panel Features
- **JSON Prettify**: Tự động format JSON responses
- **Headers Inspection**: Xem tất cả request/response headers  
- **Raw View**: Xem raw HTTP data
- **Edit Mode**: Chỉnh sửa request/response trước khi forward

### Intercept Controls
- **Breakpoints**: Tạm dừng request để chỉnh sửa
- **Auto-Continue**: Tự động continue sau khi modify
- **Rule Templates**: Lưu intercept rules để tái sử dụng

## 🔧 Advanced Configuration

### Custom Proxy Chains
```python
# config/proxy_chain.json
{
  "upstream_proxies": [
    {
      "host": "corporate-proxy.company.com",
      "port": 8080,
      "auth": {
        "username": "user",
        "password": "pass"
      }
    }
  ]
}
```

### Request Filtering
```python
# config/filters.json
{
  "include_patterns": [
    "*/api/*",
    "*.json",
    "*graphql*"
  ],
  "exclude_patterns": [
    "*.css",
    "*.js",
    "*.png",
    "*.jpg"
  ]
}
```

### Custom Response Templates
```python
# config/templates.json
{
  "error_responses": {
    "404": {
      "status": 404,
      "body": "{\"error\": \"Not found\", \"code\": 404}"
    },
    "500": {
      "status": 500, 
      "body": "{\"error\": \"Server error\", \"code\": 500}"
    }
  }
}
```

## 🛠 Command Line Usage

### Start/Stop Service
```bash
# Start interceptor daemon
./interceptor.py --daemon --port 8888

# Stop daemon
./interceptor.py --stop

# Status check
./interceptor.py --status
```

### Export/Import Sessions
```bash
# Export captured requests
./interceptor.py --export session.json

# Import previous session
./interceptor.py --import session.json

# Export specific format
./interceptor.py --export --format har session.har
```

### Batch Operations
```bash
# Apply intercept rules from file
./interceptor.py --rules rules.json

# Batch modify responses
./interceptor.py --batch-modify modifications.json
```

## 🎯 Common Use Cases

### 1. API Development Testing
```bash
# Intercept và modify API responses để test error handling
# Rules: api.myservice.com/users → 500 error
# Rules: api.myservice.com/login → fake success token
```

### 2. Mobile App Debug
```bash
# Test app behavior với different API responses
# Simulate network failures, slow responses, malformed data
```

### 3. Security Testing  
```bash
# Intercept authentication flows
# Test injection vulnerabilities
# Analyze encrypted communications
```

### 4. Performance Analysis
```bash
# Monitor API call patterns
# Identify slow endpoints
# Track request/response sizes
```

## 🚨 Troubleshooting

### Port Conflicts
```bash
# Tìm process đang dùng port 8888
lsof -ti:8888 | xargs kill -9

# Đổi port khác
./launch.sh --port 9999
```

### SSL Certificate Issues
```bash
# Xóa và tạo lại certificates
rm -rf ~/.api_interceptor/
./interceptor.py --regenerate-certs

# Check certificate validity
openssl x509 -in ~/.api_interceptor/ca.crt -text -noout
```

### Permission Problems
```bash
# Cấp quyền cho scripts
chmod +x *.sh *.py

# Check pfctl permissions
sudo pfctl -s rules

# Reset network settings
sudo ./restore_network.sh
```

### DNS Cache Issues
```bash
# Clear DNS cache
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# Check hosts file
cat /etc/hosts | grep "# API Interceptor"
```

### App-Specific Issues
```bash
# Chrome: Clear browsing data and restart
# Safari: Clear cache in Develop menu
# iOS Simulator: Reset content and settings
# Android Emulator: Wipe data and restart
```

## 🔍 Debugging Tips

### Verbose Logging
```bash
# Enable debug logging
./interceptor.py --debug --log-level DEBUG

# Watch logs in real-time
tail -f logs/interceptor.log
```

### Network Interface Monitoring
```bash
# Monitor network interfaces
sudo tcpdump -i lo0 port 8888

# Check routing table
netstat -rn | grep 127.0.0.1
```

### Process Monitoring
```bash
# Watch for new network connections
sudo lsof -i -P | grep LISTEN

# Monitor specific app network activity
sudo lsof -p $(pgrep -f "Google Chrome") | grep TCP
```

## 🎛 API Reference

### WebSocket Events
```javascript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:8888/ws');

// Event types
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  switch(data.type) {
    case 'new_request':
      // New HTTP request captured
      break;
    case 'intercepted_request':  
      // Request matched intercept rule
      break;
    case 'status_change':
      // Recording status changed
      break;
  }
};
```

### REST API Endpoints
```bash
# Start/stop recording
POST /api/start
POST /api/stop

# Manage requests
GET /api/requests
POST /api/clear
DELETE /api/requests/{id}

# Intercept rules
POST /api/intercept-rule
GET /api/intercept-rules
PUT /api/intercept-rules/{id}
DELETE /api/intercept-rules/{id}

# Export data
GET /api/export?format=json|har|curl
```

### Python API
```python
from api_interceptor import InterceptorClient

client = InterceptorClient('http://localhost:8888')

# Start recording
client.start_recording()

# Add intercept rule
client.add_rule(
    url='https://api.example.com/users',
    response={'fake': 'data'},
    status=200
)

# Get captured requests
requests = client.get_requests()
```

## 📊 Performance Tuning

### Memory Usage
```bash
# Limit stored requests
./interceptor.py --max-requests 1000

# Enable request cleanup
./interceptor.py --cleanup-interval 300
```

### Network Performance  
```bash
# Adjust buffer sizes
./interceptor.py --buffer-size 8192

# Enable compression
./interceptor.py --compress-responses
```

### CPU Usage
```bash
# Reduce logging overhead
./interceptor.py --log-level ERROR

# Disable packet inspection
./interceptor.py --no-packet-inspection
```

## 🔒 Security Considerations

### Certificate Management
- Store CA private key securely
- Rotate certificates regularly
- Never share CA private key

### Network Security
- Use only on trusted networks
- Firewall rules to block external access
- Monitor for unauthorized connections

### Data Privacy
- Clear captured data regularly  
- Encrypt sensitive request/response data
- Comply with company data policies

## 📚 Additional Resources

### Documentation
- [mitmproxy docs](https://docs.mitmproxy.org/) - Similar tool reference
- [pfctl man page](https://www.openbsd.org/faq/pf/) - Packet filter docs
- [macOS networking](https://developer.apple.com/network/) - Apple networking guides

### Community
- GitHub Issues: Report bugs and feature requests
- Discussions: Share tips and configurations
- Wiki: Community-maintained guides

## 🎉 Success Examples

### E-commerce App Testing
```json
{
  "url": "https://api.shop.com/products",
  "modifications": [
    {"scenario": "empty_cart", "response": {"items": []}},
    {"scenario": "sale_prices", "response": {"items": [{"price": 0.99}]}},
    {"scenario": "out_of_stock", "response": {"error": "Out of stock"}}
  ]
}
```

### Authentication Flow Testing  
```json
{
  "url": "https://auth.service.com/login",
  "test_cases": [
    {"invalid_token": {"status": 401, "body": {"error": "Invalid token"}}},
    {"expired_session": {"status": 403, "body": {"error": "Session expired"}}},
    {"rate_limited": {"status": 429, "body": {"error": "Too many requests"}}}
  ]
}
```

Với framework này, bạn có thể intercept và modify tất cả API calls trên macOS mà không cần thay đổi proxy settings hệ thống! 🎯