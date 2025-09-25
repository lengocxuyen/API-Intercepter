#!/usr/bin/env python3
"""
macOS API Interceptor Framework
Bypasses proxy settings restrictions using multiple techniques
"""

import asyncio
import json
import logging
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp
from aiohttp import web, WSMsgType
from aiohttp.web_ws import WebSocketResponse
import psutil


class TrafficInterceptor:
    """Core traffic interception engine"""
    
    def __init__(self):
        self.is_running = False
        self.intercepted_requests = []
        self.intercept_rules = {}
        self.websocket_clients = set()
        self.app = None
        
    async def save_intercept_rule(self, request):
        """Save intercept rule for specific URL"""
        data = await request.json()
        url = data.get('url')
        rule = {
            'enabled': data.get('enabled', False),
            'status': data.get('status', 200),
            'response': data.get('response', '{}')
        }
        
        self.intercept_rules[url] = rule
        
        return web.json_response({'status': 'saved'})

    async def setup_traffic_capture(self):
        """Setup various traffic capture methods for macOS"""
        # Method 1: pfctl rules (requires sudo)
        await self.setup_pfctl_redirect()
        
        # Method 2: DNS hijacking via /etc/hosts
        await self.setup_dns_hijacking()
        
        # Method 3: Application-level hooks
        await self.setup_app_hooks()

    async def setup_pfctl_redirect(self):
        """Setup pfctl packet filtering rules"""
        try:
            # Create pfctl rule to redirect traffic
            pfctl_rules = """
# API Interceptor rules
rdr pass on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port 8888
rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port 8888
            """.strip()
            
            # Write rules to temporary file
            rules_file = Path("/tmp/api_interceptor.rules")
            rules_file.write_text(pfctl_rules)
            
            # Load rules (requires sudo)
            subprocess.run([
                'sudo', 'pfctl', '-f', str(rules_file)
            ], check=True, capture_output=True)
            
            print("✅ pfctl rules loaded successfully")
            
        except subprocess.CalledProcessError as e:
            print(f"⚠️  pfctl setup failed: {e}")
        except Exception as e:
            print(f"⚠️  pfctl error: {e}")

    async def setup_dns_hijacking(self):
        """Modify /etc/hosts to redirect domains"""
        try:
            # Backup original hosts file
            subprocess.run([
                'sudo', 'cp', '/etc/hosts', '/etc/hosts.backup'
            ], check=True)
            
            # Common API domains to intercept
            domains = [
                'api.example.com',
                'graph.facebook.com',
                'api.twitter.com',
                'api.instagram.com',
                'api.linkedin.com',
                'api.github.com'
            ]
            
            # Add redirects to hosts file
            hosts_entries = "\n# API Interceptor entries\n"
            for domain in domains:
                hosts_entries += f"127.0.0.1 {domain}\n"
            
            with open('/etc/hosts', 'a') as f:
                f.write(hosts_entries)
                
            # Flush DNS cache
            subprocess.run(['sudo', 'dscacheutil', '-flushcache'], check=True)
            
            print("✅ DNS hijacking setup complete")
            
        except Exception as e:
            print(f"⚠️  DNS hijacking failed: {e}")

    async def setup_app_hooks(self):
        """Setup application-level network hooks"""
        # This would involve more complex implementation
        # Using techniques like:
        # - DYLD_INSERT_LIBRARIES for dynamic library injection
        # - Process monitoring and syscall interception
        # - Network namespace manipulation
        
        print("🔧 App-level hooks initialized")


class NetworkSniffer:
    """Network packet sniffer for traffic analysis"""
    
    def __init__(self, interceptor: TrafficInterceptor):
        self.interceptor = interceptor
        self.running = False
        
    def start_sniffing(self):
        """Start packet sniffing"""
        if not self.check_privileges():
            print("❌ Need root privileges for packet sniffing")
            return False
            
        self.running = True
        threading.Thread(target=self._sniff_packets, daemon=True).start()
        return True
        
    def check_privileges(self):
        """Check if running with sufficient privileges"""
        return psutil.Process().username() == 'root'
        
    def _sniff_packets(self):
        """Packet sniffing loop"""
        try:
            import scapy.all as scapy
            
            def packet_handler(packet):
                if not self.running:
                    return
                    
                # Process HTTP packets
                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                    
                    # Look for HTTP requests
                    if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
                        self._process_http_packet(packet, payload)
            
            # Start sniffing
            scapy.sniff(
                filter="tcp port 80 or tcp port 443",
                prn=packet_handler,
                store=0
            )
            
        except ImportError:
            print("⚠️  scapy not installed. Install with: pip install scapy")
        except Exception as e:
            print(f"⚠️  Packet sniffing error: {e}")
            
    def _process_http_packet(self, packet, payload):
        """Process captured HTTP packet"""
        lines = payload.split('\n')
        if not lines:
            return
            
        # Parse request line
        request_line = lines[0].split()
        if len(request_line) < 3:
            return
            
        method = request_line[0]
        path = request_line[1]
        
        # Parse headers
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Extract body
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        # Create request record
        request_record = {
            'id': int(time.time() * 1000),
            'method': method,
            'url': f"http://{headers.get('Host', 'unknown')}{path}",
            'timestamp': datetime.now().isoformat(),
            'headers': headers,
            'body': body,
            'source': 'packet_capture'
        }
        
        # Add to interceptor
        self.interceptor.intercepted_requests.insert(0, request_record)


class ProcessMonitor:
    """Monitor processes for network activity"""
    
    def __init__(self, interceptor: TrafficInterceptor):
        self.interceptor = interceptor
        self.running = False
        
    def start_monitoring(self):
        """Start process monitoring"""
        self.running = True
        threading.Thread(target=self._monitor_processes, daemon=True).start()
        
    def _monitor_processes(self):
        """Monitor processes for network connections"""
        while self.running:
            try:
                # Get all network connections
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.status == psutil.CONN_ESTABLISHED:
                        self._analyze_connection(conn)
                        
            except Exception as e:
                print(f"Process monitoring error: {e}")
                
            time.sleep(1)
            
    def _analyze_connection(self, conn):
        """Analyze network connection"""
        try:
            if conn.pid:
                process = psutil.Process(conn.pid)
                
                # Log interesting connections
                if conn.raddr and conn.raddr.port in [80, 443]:
                    print(f"📡 {process.name()} -> {conn.raddr.ip}:{conn.raddr.port}")
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


class CertificateManager:
    """Manage SSL certificates for HTTPS interception"""
    
    def __init__(self):
        self.ca_cert = None
        self.ca_key = None
        
    def setup_ca(self):
        """Setup Certificate Authority"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            
            # Generate private key for CA
            self.ca_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create CA certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "API Interceptor CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "API Interceptor Root CA"),
            ])
            
            self.ca_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                self.ca_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                ]),
                critical=False,
            ).sign(self.ca_key, hashes.SHA256())
            
            # Save CA cert and key
            self._save_ca_files()
            
            print("✅ CA certificate generated")
            
        except ImportError:
            print("⚠️  cryptography not installed. Install with: pip install cryptography")
            
    def _save_ca_files(self):
        """Save CA certificate and key to files"""
        ca_dir = Path.home() / ".api_interceptor"
        ca_dir.mkdir(exist_ok=True)
        
        # Save certificate
        cert_file = ca_dir / "ca.crt"
        with open(cert_file, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
            
        # Save private key
        key_file = ca_dir / "ca.key"
        with open(key_file, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        print(f"📁 CA files saved to {ca_dir}")
        print(f"💡 Import {cert_file} to your system's trusted certificates")


async def main():
    """Main application entry point"""
    print("🔧 Starting API Interceptor Framework...")
    
    # Initialize components
    interceptor = TrafficInterceptor()
    sniffer = NetworkSniffer(interceptor)
    monitor = ProcessMonitor(interceptor)
    cert_manager = CertificateManager()
    
    # Setup SSL certificates
    cert_manager.setup_ca()
    
    # Start network monitoring
    if sniffer.start_sniffing():
        print("📡 Packet sniffing started")
    
    monitor.start_monitoring()
    print("👀 Process monitoring started")
    
    # Start web server
    runner = await interceptor.start_server()
    
    try:
        # Keep running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    # Check dependencies
    required_packages = ['aiohttp', 'psutil']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print(f"Install with: pip install {' '.join(missing_packages)}")
        sys.exit(1)
    
    # Run the application
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        sys.exit(1) start_server(self, port=8888):
        """Start the proxy server and web UI"""
        self.app = web.Application()
        
        # Web UI routes
        self.app.router.add_get('/', self.serve_ui)
        self.app.router.add_get('/ws', self.websocket_handler)
        
        # API routes
        self.app.router.add_post('/api/start', self.start_interception)
        self.app.router.add_post('/api/stop', self.stop_interception)
        self.app.router.add_post('/api/clear', self.clear_requests)
        self.app.router.add_post('/api/intercept-rule', self.save_intercept_rule)
        
        # Proxy routes - handle all HTTP/HTTPS traffic
        self.app.router.add_route('*', '/{path:.*}', self.proxy_handler)
        
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        site = web.TCPSite(runner, 'localhost', port)
        await site.start()
        
        print(f"🚀 API Interceptor running at http://localhost:{port}")
        print("📱 Configure apps to use proxy: localhost:8888")
        
        return runner

    async def serve_ui(self, request):
        """Serve the web UI"""
        ui_content = """<!-- The HTML content from the previous artifact would go here -->"""
        return web.Response(text=ui_content, content_type='text/html')

    async def websocket_handler(self, request):
        """Handle WebSocket connections for real-time updates"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        self.websocket_clients.add(ws)
        
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    await self.handle_ws_message(ws, data)
                elif msg.type == WSMsgType.ERROR:
                    print(f'WebSocket error: {ws.exception()}')
        finally:
            self.websocket_clients.discard(ws)
            
        return ws

    async def handle_ws_message(self, ws, data):
        """Handle WebSocket messages from UI"""
        action = data.get('action')
        
        if action == 'start_recording':
            await self.start_interception(None)
        elif action == 'stop_recording':
            await self.stop_interception(None)
        elif action == 'clear_requests':
            await self.clear_requests(None)

    async def broadcast_to_clients(self, message):
        """Broadcast message to all connected WebSocket clients"""
        if not self.websocket_clients:
            return
            
        disconnected = set()
        for ws in self.websocket_clients:
            try:
                await ws.send_str(json.dumps(message))
            except ConnectionResetError:
                disconnected.add(ws)
                
        self.websocket_clients -= disconnected

    async def proxy_handler(self, request):
        """Main proxy handler for intercepting HTTP/HTTPS requests"""
        if not self.is_running:
            return web.Response(text="Proxy not running", status=503)
            
        # Extract request details
        method = request.method
        url = str(request.url)
        headers = dict(request.headers)
        
        # Remove proxy-specific headers
        headers.pop('Host', None)
        headers.pop('Proxy-Connection', None)
        
        # Read request body
        body = None
        if request.can_read_body:
            body = await request.read()
            
        # Create request record
        request_record = {
            'id': int(time.time() * 1000),
            'method': method,
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'headers': headers,
            'body': body.decode('utf-8', errors='ignore') if body else None,
            'intercepted': False
        }
        
        # Check for intercept rules
        if url in self.intercept_rules and self.intercept_rules[url].get('enabled'):
            return await self.handle_intercepted_request(request_record)
            
        # Forward request to actual server
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    ssl=False,  # For debugging, disable SSL verification
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    response_body = await resp.read()
                    response_headers = dict(resp.headers)
                    
                    # Complete request record
                    request_record.update({
                        'status': resp.status,
                        'response_headers': response_headers,
                        'response_body': response_body.decode('utf-8', errors='ignore')
                    })
                    
                    # Store and broadcast request
                    self.intercepted_requests.insert(0, request_record)
                    await self.broadcast_to_clients({
                        'type': 'new_request',
                        'request': request_record
                    })
                    
                    # Return response
                    return web.Response(
                        body=response_body,
                        status=resp.status,
                        headers=response_headers
                    )
                    
        except Exception as e:
            error_response = {
                'error': str(e),
                'message': f'Failed to proxy request to {url}'
            }
            
            request_record.update({
                'status': 500,
                'response_body': json.dumps(error_response),
                'error': True
            })
            
            self.intercepted_requests.insert(0, request_record)
            await self.broadcast_to_clients({
                'type': 'new_request',
                'request': request_record
            })
            
            return web.json_response(error_response, status=500)

    async def handle_intercepted_request(self, request_record):
        """Handle requests that match intercept rules"""
        request_record['intercepted'] = True
        rule = self.intercept_rules[request_record['url']]
        
        # Use custom response from rule
        custom_response = rule.get('response', '{}')
        custom_status = rule.get('status', 200)
        
        request_record.update({
            'status': custom_status,
            'response_body': custom_response,
            'modified': True
        })
        
        self.intercepted_requests.insert(0, request_record)
        await self.broadcast_to_clients({
            'type': 'intercepted_request',
            'request': request_record
        })
        
        return web.Response(
            text=custom_response,
            status=custom_status,
            headers={'Content-Type': 'application/json'}
        )

    async def start_interception(self, request):
        """Start traffic interception"""
        self.is_running = True
        
        # Start traffic capture methods
        await self.setup_traffic_capture()
        
        await self.broadcast_to_clients({
            'type': 'status_change',
            'status': 'recording'
        })
        
        if request:
            return web.json_response({'status': 'started'})

    async def stop_interception(self, request):
        """Stop traffic interception"""
        self.is_running = False
        
        await self.broadcast_to_clients({
            'type': 'status_change',
            'status': 'stopped'
        })
        
        if request:
            return web.json_response({'status': 'stopped'})

    async def clear_requests(self, request):
        """Clear all intercepted requests"""
        self.intercepted_requests.clear()
        
        await self.broadcast_to_clients({
            'type': 'requests_cleared'
        })
        
        if request:
            return web.json_response({'status': 'cleared'})

    async def