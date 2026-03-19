"""
Packet analyzer for extracting meaningful events from raw packets.
Includes DDoS detection, auto-ban capabilities, and vulnerability exploitation detection.
"""
from datetime import datetime, timedelta
from collections import defaultdict
import subprocess
import platform
import re
import base64
import math

from detection.vuln_detector import VulnerabilityExploitDetector


class PacketAnalyzer:
    """
    Analyzes packets to detect patterns and generate events.
    Includes DDoS detection with configurable thresholds.
    """

    # DDoS Detection Thresholds
    DDOS_PACKET_THRESHOLD = 500  # packets per window
    DDOS_TIME_WINDOW = 10  # seconds
    DDOS_SYN_FLOOD_THRESHOLD = 200  # SYN packets per window
    DDOS_AUTO_BAN_ENABLED = True
    DDOS_BAN_DURATION = 3600  # seconds (1 hour)

    # Default whitelisted IPs - NEVER ban these
    DEFAULT_WHITELIST_IPS = {
        '127.0.0.1',          # Localhost
        '10.0.0.1',         # Internal gateway
        '10.0.0.15',        # Bastion itself
        '192.168.1.1',        # Internal network
        '192.168.1.100',      # Bastion eth1
    }

    def __init__(self):
        # Track connection attempts for port scan detection
        self.connection_tracker = defaultdict(lambda: {'ports': set(), 'first_seen': None})
        # Track failed connections
        self.syn_tracker = defaultdict(list)
        # DNS query tracker
        self.dns_queries = defaultdict(list)
        # DDoS detection: track packet rates per IP
        self.packet_rate_tracker = defaultdict(lambda: {'count': 0, 'first_seen': None, 'syn_count': 0})
        # Banned IPs cache (to avoid DB lookups on every packet)
        self.banned_ips_cache = set()
        # Custom whitelist cache (loaded from database)
        self.custom_whitelist_cache = set()
        # Callback for auto-ban (set by run.py)
        self.on_auto_ban = None
        # Vulnerability exploitation detector
        self.vuln_detector = VulnerabilityExploitDetector()
        # C2 beaconing tracker: {ip: [timestamp1, timestamp2, ...]}
        self.beacon_tracker = defaultdict(list)
        # HTTP exfiltration tracker: {ip: {'bytes': 0, 'requests': 0, 'first_seen': None}}
        self.exfil_tracker = defaultdict(lambda: {'bytes': 0, 'requests': 0, 'first_seen': None})
        # Fuzzing tracker: {ip: {'count': 0, 'first_seen': None, 'payloads': set()}}
        self.fuzzing_tracker = defaultdict(lambda: {'count': 0, 'first_seen': None, 'payloads': set()})

    def load_whitelist_from_db(self, whitelist_ips):
        """Load custom whitelist IPs from database."""
        self.custom_whitelist_cache = set(whitelist_ips)

    def is_whitelisted(self, ip):
        """Check if IP is whitelisted (default or custom)."""
        return ip in self.DEFAULT_WHITELIST_IPS or ip in self.custom_whitelist_cache

    def add_to_whitelist_cache(self, ip):
        """Add IP to custom whitelist cache."""
        self.custom_whitelist_cache.add(ip)

    def remove_from_whitelist_cache(self, ip):
        """Remove IP from custom whitelist cache."""
        self.custom_whitelist_cache.discard(ip)

    def analyze(self, packet_data):
        """
        Analyze a packet and return any detected events.

        Args:
            packet_data: Dict with packet information from sniffer

        Returns:
            List of event dicts
        """
        events = []
        src_ip = packet_data.get('src_ip')

        # Skip analysis if IP is already banned (cached)
        if src_ip in self.banned_ips_cache:
            return events

        # Check for DDoS / high packet rate
        ddos_event = self._detect_ddos(packet_data)
        if ddos_event:
            events.append(ddos_event)

        # Check for port scanning
        scan_event = self._detect_port_scan(packet_data)
        if scan_event:
            events.append(scan_event)

        # Check for suspicious DNS
        dns_event = self._detect_suspicious_dns(packet_data)
        if dns_event:
            events.append(dns_event)

        # Check for common attack patterns
        attack_event = self._detect_attack_patterns(packet_data)
        if attack_event:
            events.append(attack_event)

        # Check for DNS exfiltration (enhanced)
        dns_exfil_event = self._detect_dns_exfiltration(packet_data)
        if dns_exfil_event:
            events.append(dns_exfil_event)

        # Check for HTTP exfiltration
        http_exfil_event = self._detect_http_exfiltration(packet_data)
        if http_exfil_event:
            events.append(http_exfil_event)

        # Check for C2 beaconing
        beacon_event = self._detect_c2_beaconing(packet_data)
        if beacon_event:
            events.append(beacon_event)

        # Check for fuzzing on uptime API
        fuzz_event = self._detect_fuzzing(packet_data)
        if fuzz_event:
            events.append(fuzz_event)

        # Check for vulnerability exploitation attempts
        vuln_events = self.vuln_detector.analyze(packet_data)
        if vuln_events:
            events.extend(vuln_events)
            # Auto-ban on critical exploits if callback is set
            for event in vuln_events:
                if event.get('severity', 0) >= 4 and self.on_auto_ban:
                    exploit_type = event.get('details', {}).get('exploit', 'unknown')
                    reason = f"Exploit detected: {exploit_type}"
                    self.on_auto_ban(src_ip, 'exploit', reason)
                    self.banned_ips_cache.add(src_ip)

        return events

    def _detect_ddos(self, packet_data):
        """Detect potential DDoS attacks based on packet rate."""
        src_ip = packet_data.get('src_ip')
        if not src_ip:
            return None

        # Skip whitelisted IPs
        if self.is_whitelisted(src_ip):
            return None

        # Skip known CDN/DNS resolver IPs (high volume but legitimate)
        if src_ip.startswith(self.WHITELISTED_CDN_PREFIXES):
            return None

        now = packet_data.get('timestamp', datetime.utcnow())
        flags = packet_data.get('flags', '')
        tracker = self.packet_rate_tracker[src_ip]

        # Initialize or reset window
        if tracker['first_seen'] is None:
            tracker['first_seen'] = now
            tracker['count'] = 1
            tracker['syn_count'] = 1 if 'SYN' in str(flags) and 'ACK' not in str(flags) else 0
            return None

        # Check if we're still in the time window
        elapsed = (now - tracker['first_seen']).total_seconds()

        if elapsed <= self.DDOS_TIME_WINDOW:
            tracker['count'] += 1
            if 'SYN' in str(flags) and 'ACK' not in str(flags):
                tracker['syn_count'] += 1

            # Debug logging for high packet rates
            if tracker['count'] % 25 == 0:
                print(f"[DDOS] {src_ip}: {tracker['count']} pkts, {tracker['syn_count']} SYN in {elapsed:.1f}s")

            # Check thresholds
            is_ddos = False
            ddos_type = None
            reason = None

            if tracker['count'] >= self.DDOS_PACKET_THRESHOLD:
                is_ddos = True
                ddos_type = 'packet_flood'
                reason = f"High packet rate: {tracker['count']} packets in {elapsed:.1f}s"

            elif tracker['syn_count'] >= self.DDOS_SYN_FLOOD_THRESHOLD:
                is_ddos = True
                ddos_type = 'syn_flood'
                reason = f"SYN flood detected: {tracker['syn_count']} SYN packets in {elapsed:.1f}s"

            if is_ddos:
                # Reset tracker
                self.packet_rate_tracker[src_ip] = {'count': 0, 'first_seen': None, 'syn_count': 0}

                # Trigger auto-ban if enabled
                if self.DDOS_AUTO_BAN_ENABLED and self.on_auto_ban:
                    self.on_auto_ban(src_ip, ddos_type, reason)
                    self.banned_ips_cache.add(src_ip)

                return {
                    'timestamp': now,
                    'event_type': f'ddos_{ddos_type}',
                    'src_ip': src_ip,
                    'dst_ip': packet_data.get('dst_ip'),
                    'severity': 4,  # Critical
                    'details': {
                        'ddos_type': ddos_type,
                        'packet_count': tracker['count'],
                        'syn_count': tracker['syn_count'],
                        'time_window': elapsed,
                        'reason': reason,
                        'auto_banned': self.DDOS_AUTO_BAN_ENABLED
                    },
                    'log_source': 'packet'
                }
        else:
            # Reset window
            tracker['first_seen'] = now
            tracker['count'] = 1
            tracker['syn_count'] = 1 if 'SYN' in str(flags) and 'ACK' not in str(flags) else 0

        return None

    def add_to_ban_cache(self, ip):
        """Add IP to banned cache."""
        self.banned_ips_cache.add(ip)

    def remove_from_ban_cache(self, ip):
        """Remove IP from banned cache."""
        self.banned_ips_cache.discard(ip)

    def load_banned_ips(self, ip_list):
        """Load list of banned IPs into cache."""
        self.banned_ips_cache = set(ip_list)

    def _detect_port_scan(self, packet_data):
        """Detect potential port scanning activity."""
        src_ip = packet_data.get('src_ip')
        dst_port = packet_data.get('dst_port')
        flags = packet_data.get('flags', '')

        if not src_ip or not dst_port:
            return None

        # Track SYN packets (potential scan)
        if 'SYN' in str(flags) and 'ACK' not in str(flags):
            tracker = self.connection_tracker[src_ip]

            if tracker['first_seen'] is None:
                tracker['first_seen'] = packet_data['timestamp']

            tracker['ports'].add(dst_port)

            # Check if this looks like a scan (many ports in short time)
            time_window = timedelta(seconds=60)
            if (packet_data['timestamp'] - tracker['first_seen']) <= time_window:
                if len(tracker['ports']) >= 10:  # Threshold for scan detection
                    event = {
                        'timestamp': packet_data['timestamp'],
                        'event_type': 'port_scan',
                        'src_ip': src_ip,
                        'dst_ip': packet_data.get('dst_ip'),
                        'severity': 3,  # High
                        'details': {
                            'ports_scanned': len(tracker['ports']),
                            'ports': list(tracker['ports'])[:20]  # First 20 ports
                        },
                        'log_source': 'packet'
                    }
                    # Reset tracker
                    self.connection_tracker[src_ip] = {'ports': set(), 'first_seen': None}
                    return event

        return None

    def _detect_suspicious_dns(self, packet_data):
        """Detect suspicious DNS queries."""
        dns_data = packet_data.get('dns_data')
        if not dns_data or dns_data.get('type') != 'query':
            return None

        query = dns_data.get('query', '')
        src_ip = packet_data.get('src_ip')

        # Skip reverse DNS lookups and SRV records
        if query.endswith('.in-addr.arpa.') or query.endswith('.ip6.arpa.'):
            return None
        if any(label.startswith('_') for label in query.split('.')):
            return None

        suspicious = False
        reason = None

        # Check for very long domain names (possible DNS tunneling)
        if len(query) > 100:
            suspicious = True
            reason = 'Unusually long domain name (possible DNS tunneling)'

        # Check for many subdomains (possible DNS tunneling)
        if query.count('.') > 5:
            suspicious = True
            reason = 'Many subdomains (possible DNS tunneling)'

        # Check for suspicious TLDs or patterns
        suspicious_patterns = ['.onion', '.bit', 'dnscat', 'tunnel']
        for pattern in suspicious_patterns:
            if pattern in query.lower():
                suspicious = True
                reason = f'Suspicious pattern in DNS query: {pattern}'
                break

        if suspicious:
            return {
                'timestamp': packet_data['timestamp'],
                'event_type': 'suspicious_dns',
                'src_ip': src_ip,
                'dst_ip': packet_data.get('dst_ip'),
                'severity': 2,  # Medium
                'details': {
                    'query': query,
                    'reason': reason
                },
                'log_source': 'packet'
            }

        return None

    def _detect_attack_patterns(self, packet_data):
        """Detect common attack patterns in packet payload."""
        payload = packet_data.get('payload_preview')
        if not payload:
            return None

        try:
            # Convert hex back to bytes for analysis
            payload_bytes = bytes.fromhex(payload)
            payload_str = payload_bytes.decode('utf-8', errors='ignore').lower()
        except Exception:
            return None

        attack_patterns = {
            'sql_injection': ['union select', "' or '1'='1", '; drop table', '/**/'],
            'xss': ['<script>', 'javascript:', 'onerror=', 'onload='],
            'path_traversal': ['../..', '..\\..', '/etc/passwd', 'c:\\windows'],
            'command_injection': ['; cat ', '| cat ', '`cat ', '$(cat '],
        }

        for attack_type, patterns in attack_patterns.items():
            for pattern in patterns:
                if pattern in payload_str:
                    return {
                        'timestamp': packet_data['timestamp'],
                        'event_type': f'attack_{attack_type}',
                        'src_ip': packet_data.get('src_ip'),
                        'dst_ip': packet_data.get('dst_ip'),
                        'src_port': packet_data.get('src_port'),
                        'dst_port': packet_data.get('dst_port'),
                        'severity': 4,  # Critical
                        'details': {
                            'attack_type': attack_type,
                            'pattern_matched': pattern,
                            'payload_sample': payload_str[:100]
                        },
                        'log_source': 'packet'
                    }

        return None

    # Known legitimate domains to skip in DNS exfiltration detection
    LEGITIMATE_DNS_DOMAINS = {
        'google.com', 'google.fr', 'googleapis.com', 'gstatic.com', 'googlevideo.com',
        'github.com', 'githubusercontent.com', 'githubassets.com',
        'discord.com', 'discord.gg', 'discordapp.com',
        'microsoft.com', 'microsoftonline.com', '[C2_DOMAIN]',
        'windows.net', 'azure.com', 'office.com', 'live.com',
        'twitter.com', 'x.com', 'twimg.com',
        'cloudflare.com', 'cloudflare-dns.com',
        'amazonaws.com', 'aws.amazon.com',
        'reddit.com', 'redd.it', 'redditstatic.com',
        'youtube.com', 'ytimg.com', 'yt3.ggpht.com',
        'facebook.com', 'fbcdn.net',
        'ubuntu.com', 'canonical.com',
        'debian.org', 'pypi.org', 'python.org', 'npmjs.org',
    }

    def _detect_dns_exfiltration(self, packet_data):
        """
        Detect DNS-based data exfiltration.
        Looks for encoded/long subdomains, high entropy labels, and known exfil patterns.
        Query rate alone is NOT sufficient - must be combined with another indicator.
        """
        dns_data = packet_data.get('dns_data')
        if not dns_data or dns_data.get('type') != 'query':
            return None

        query = dns_data.get('query', '').rstrip('.')
        src_ip = packet_data.get('src_ip')
        if not query:
            return None

        labels = query.split('.')
        if len(labels) < 2:
            return None

        # Skip DNS SRV / service discovery records (e.g. _kerberos._tcp.DOMAIN)
        if any(label.startswith('_') for label in labels):
            return None

        # Skip reverse DNS lookups (in-addr.arpa)
        if query.endswith('.in-addr.arpa') or query.endswith('.ip6.arpa'):
            return None

        # Skip known legitimate domains
        base_domain = '.'.join(labels[-2:]).lower()
        if base_domain in self.LEGITIMATE_DNS_DOMAINS:
            return None

        # Check subdomain part (everything except last 2 labels = domain + TLD)
        subdomain_part = '.'.join(labels[:-2]) if len(labels) > 2 else ''

        reasons = []

        # High entropy subdomain (base64/hex encoded data)
        if subdomain_part and len(subdomain_part) > 30:
            entropy = self._calc_entropy(subdomain_part.replace('.', ''))
            if entropy > 4.0:
                reasons.append(f'High entropy subdomain ({entropy:.1f} bits)')

        # Hex-encoded subdomain labels
        for label in labels[:-2]:
            if len(label) > 10 and all(c in '0123456789abcdef' for c in label.lower()):
                reasons.append(f'Hex-encoded label: {label[:20]}...')
                break

        # Base64-like subdomain labels
        for label in labels[:-2]:
            if len(label) > 15 and re.match(r'^[A-Za-z0-9+/=]+$', label):
                reasons.append(f'Base64-like label: {label[:20]}...')
                break

        # Known exfiltration domain patterns
        exfil_keywords = ['exfil', 'exfiltration', 'passwd', 'leak', 'dump', 'steal', 'c2', 'beacon']
        for kw in exfil_keywords:
            if kw in query.lower():
                reasons.append(f'Exfiltration keyword in domain: {kw}')
                break

        # Track DNS query rate (but NOT as a standalone reason)
        now = packet_data.get('timestamp', datetime.utcnow())
        self.dns_queries[src_ip].append(now)
        cutoff = now - timedelta(seconds=60)
        self.dns_queries[src_ip] = [t for t in self.dns_queries[src_ip] if t > cutoff]
        high_rate = len(self.dns_queries[src_ip]) > 100  # raised threshold

        # Only flag high rate if there's ALSO another suspicious indicator
        if high_rate and reasons:
            reasons.append(f'High DNS query rate: {len(self.dns_queries[src_ip])} queries/min')

        if reasons:
            return {
                'timestamp': packet_data['timestamp'],
                'event_type': 'dns_exfiltration',
                'src_ip': src_ip,
                'dst_ip': packet_data.get('dst_ip'),
                'severity': 3,
                'details': {
                    'query': query,
                    'reasons': reasons,
                    'subdomain_length': len(subdomain_part),
                },
                'log_source': 'packet'
            }

        return None

    def _calc_entropy(self, data):
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0
        freq = defaultdict(int)
        for c in data:
            freq[c] += 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _detect_http_exfiltration(self, packet_data):
        """
        Detect HTTP-based data exfiltration.
        Looks for suspicious outbound POST/GET with encoded data in params or body.
        """
        payload_hex = packet_data.get('payload_preview')
        if not payload_hex:
            return None

        dst_port = packet_data.get('dst_port')
        src_ip = packet_data.get('src_ip')

        # Only check outbound HTTP (from internal to external)
        if dst_port not in (80, 443, 8080, 8443):
            return None

        try:
            payload = bytes.fromhex(payload_hex).decode('utf-8', errors='ignore')
        except Exception:
            return None

        reasons = []

        # Large POST body with potential encoded data
        if payload.startswith('POST '):
            # Check for base64 or hex encoded body content
            if 'Content-Length:' in payload:
                cl_match = re.search(r'Content-Length:\s*(\d+)', payload)
                if cl_match and int(cl_match.group(1)) > 5000:
                    reasons.append(f'Large POST body: {cl_match.group(1)} bytes')

        # Suspicious URL parameters (long encoded values)
        param_match = re.search(r'[?&](fwd|data|d|payload|cmd|q|file|content)=([^\s&]{50,})', payload, re.IGNORECASE)
        if param_match:
            reasons.append(f'Suspicious URL param: {param_match.group(1)}= (len={len(param_match.group(2))})')

        # Cookie exfiltration (unusually large cookies with encoded data)
        cookie_match = re.search(r'Cookie:\s*(.{200,})', payload)
        if cookie_match:
            cookie_val = cookie_match.group(1)
            if self._calc_entropy(cookie_val[:100]) > 4.0:
                reasons.append('High-entropy cookie (potential data exfiltration)')

        # Track volume from same IP
        if reasons:
            return {
                'timestamp': packet_data['timestamp'],
                'event_type': 'http_exfiltration',
                'src_ip': src_ip,
                'dst_ip': packet_data.get('dst_ip'),
                'dst_port': dst_port,
                'severity': 3,
                'details': {
                    'reasons': reasons,
                    'payload_sample': payload[:150],
                },
                'log_source': 'packet'
            }

        return None

    # Known CDN / legitimate service IP prefixes to exclude from C2 detection
    WHITELISTED_CDN_PREFIXES = (
        # Cloudflare
        '104.16.', '104.17.', '104.18.', '104.19.', '104.20.',
        '104.21.', '104.22.', '104.23.', '104.24.', '104.25.',
        '104.26.', '104.27.', '104.28.', '104.29.', '104.30.', '104.31.',
        '172.64.', '172.65.', '172.66.', '172.67.',
        '162.159.', '198.41.',
        # Akamai
        '2.16.', '2.17.', '2.18.', '2.19.', '2.20.',
        '2.21.', '2.22.', '2.23.',
        '23.0.', '23.1.', '23.2.', '23.3.', '23.4.', '23.5.',
        '23.6.', '23.7.', '23.8.', '23.9.',
        '23.32.', '23.33.', '23.34.', '23.35.', '23.36.',
        '23.37.', '23.38.', '23.39.',
        '23.40.', '23.41.', '23.42.', '23.43.', '23.44.',
        '23.45.', '23.46.', '23.47.',
        '23.48.', '23.49.', '23.50.', '23.51.', '23.52.',
        '23.53.', '23.54.', '23.55.',
        '23.56.', '23.57.', '23.58.', '23.59.', '23.60.',
        '23.61.', '23.62.', '23.63.',
        '23.192.', '23.193.', '23.194.', '23.195.', '23.196.',
        '23.197.', '23.198.', '23.199.',
        '23.200.', '23.201.', '23.202.', '23.203.', '23.204.',
        '23.205.', '23.206.', '23.207.',
        '23.208.', '23.209.', '23.210.', '23.211.', '23.212.',
        '23.213.', '23.214.', '23.215.',
        # Fastly
        '151.101.',
        '199.232.',
        # Google / GCP
        '142.250.', '142.251.',
        '172.217.', '172.253.',
        '216.58.',
        '74.125.',
        '64.233.',
        '34.107.', '34.117.', '34.120.', '34.149.',
        '35.186.', '35.190.', '35.191.', '35.201.',
        # GitHub
        '140.82.112.', '140.82.113.', '140.82.114.', '140.82.121.',
        '185.199.108.', '185.199.109.', '185.199.110.', '185.199.111.',
        # Amazon CloudFront / AWS
        '13.224.', '13.225.', '13.226.', '13.227.',
        '13.32.', '13.33.', '13.35.',
        '18.64.', '18.154.', '18.160.', '18.164.', '18.172.',
        '18.238.', '18.239.',
        '54.230.', '54.239.',
        '99.84.', '99.86.',
        '143.204.',
        '205.251.',
        # Microsoft / Azure CDN
        '13.107.', '204.79.',
        '52.96.', '52.97.', '52.98.', '52.99.',
        '40.126.',
        # Discord CDN/API
        '162.159.128.', '162.159.129.', '162.159.130.',
        '162.159.133.', '162.159.134.', '162.159.135.',
        '162.159.136.', '162.159.137.',
        # Let's Encrypt / OCSP
        '149.137.',
    )

    def _detect_c2_beaconing(self, packet_data):
        """
        Detect C2 beaconing patterns: regular interval connections to external IPs.
        Looks for periodic outbound connections with consistent timing.
        Excludes known CDN/cloud service IPs to reduce false positives.
        """
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        dst_port = packet_data.get('dst_port')
        flags = packet_data.get('flags', '')

        # Only track outbound SYN (new connections) from internal IPs
        if not src_ip or not dst_ip:
            return None
        if 'SYN' not in str(flags) or 'ACK' in str(flags):
            return None
        # Only from internal IPs to external
        if not (src_ip.startswith('10.') or src_ip.startswith('192.168.')):
            return None
        if dst_ip.startswith('10.') or dst_ip.startswith('192.168.') or dst_ip.startswith('127.'):
            return None

        # Skip known CDN / legitimate service IPs
        if dst_ip.startswith(self.WHITELISTED_CDN_PREFIXES):
            return None

        now = packet_data.get('timestamp', datetime.utcnow())
        key = f"{src_ip}->{dst_ip}:{dst_port}"
        self.beacon_tracker[key].append(now)

        # Keep last 10 minutes
        cutoff = now - timedelta(minutes=10)
        self.beacon_tracker[key] = [t for t in self.beacon_tracker[key] if t > cutoff]

        timestamps = self.beacon_tracker[key]
        if len(timestamps) < 5:
            return None

        # Calculate intervals between connections
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append((timestamps[i] - timestamps[i - 1]).total_seconds())

        if not intervals:
            return None

        avg_interval = sum(intervals) / len(intervals)
        # Check for regularity (low variance = beaconing)
        if avg_interval > 0:
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            std_dev = variance ** 0.5
            # Coefficient of variation < 0.3 means very regular timing
            cv = std_dev / avg_interval if avg_interval > 0 else 999

            if cv < 0.3 and len(timestamps) >= 5:
                self.beacon_tracker[key] = []  # Reset to avoid repeated alerts
                return {
                    'timestamp': now,
                    'event_type': 'c2_beaconing',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'severity': 4,
                    'details': {
                        'beacon_count': len(timestamps),
                        'avg_interval_sec': round(avg_interval, 1),
                        'regularity_cv': round(cv, 3),
                        'destination': f'{dst_ip}:{dst_port}',
                        'description': f'Regular beaconing detected: {len(timestamps)} connections, avg interval {avg_interval:.0f}s (CV={cv:.2f})'
                    },
                    'log_source': 'packet'
                }

        return None

    def _detect_fuzzing(self, packet_data):
        """
        Detect fuzzing attempts on services (especially uptime API on port 5001).
        Looks for rapid varied requests from same IP.
        """
        payload_hex = packet_data.get('payload_preview')
        dst_port = packet_data.get('dst_port')
        src_ip = packet_data.get('src_ip')

        if not payload_hex or not src_ip:
            return None

        # Monitor uptime API (5001) and web services
        monitored_ports = {5001, 80, 8080, 8042}
        if dst_port not in monitored_ports:
            return None

        try:
            payload = bytes.fromhex(payload_hex).decode('utf-8', errors='ignore')
        except Exception:
            return None

        # Only track HTTP requests
        if not any(payload.startswith(m) for m in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ']):
            return None

        now = packet_data.get('timestamp', datetime.utcnow())
        key = f"fuzz:{src_ip}:{dst_port}"
        tracker = self.fuzzing_tracker[key]

        if tracker['first_seen'] is None:
            tracker['first_seen'] = now

        tracker['count'] += 1
        # Track unique payload signatures (first 50 chars of request line)
        tracker['payloads'].add(payload[:50])

        elapsed = (now - tracker['first_seen']).total_seconds()

        # Detection: many varied requests in short time
        if elapsed > 0 and elapsed <= 60:
            rate = tracker['count'] / elapsed
            unique_ratio = len(tracker['payloads']) / tracker['count'] if tracker['count'] > 0 else 0

            # High request rate + high variety = fuzzing
            if tracker['count'] >= 30 and unique_ratio > 0.5:
                event = {
                    'timestamp': now,
                    'event_type': 'fuzzing_detected',
                    'src_ip': src_ip,
                    'dst_ip': packet_data.get('dst_ip'),
                    'dst_port': dst_port,
                    'severity': 3,
                    'details': {
                        'request_count': tracker['count'],
                        'unique_payloads': len(tracker['payloads']),
                        'rate_per_sec': round(rate, 1),
                        'unique_ratio': round(unique_ratio, 2),
                        'time_window': round(elapsed, 1),
                        'target_port': dst_port,
                        'description': f'Fuzzing detected: {tracker["count"]} requests ({len(tracker["payloads"])} unique) in {elapsed:.0f}s on port {dst_port}'
                    },
                    'log_source': 'packet'
                }
                # Reset tracker
                self.fuzzing_tracker[key] = {'count': 0, 'first_seen': None, 'payloads': set()}
                return event
        elif elapsed > 60:
            # Reset window
            self.fuzzing_tracker[key] = {'count': 0, 'first_seen': now, 'payloads': set()}

        return None

    def cleanup_old_data(self, max_age_seconds=300):
        """Clean up old tracking data to prevent memory growth."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=max_age_seconds)

        # Clean connection tracker
        to_remove = []
        for ip, data in self.connection_tracker.items():
            if data['first_seen'] and data['first_seen'] < cutoff:
                to_remove.append(ip)
        for ip in to_remove:
            del self.connection_tracker[ip]

        # Clean beacon tracker
        for key in list(self.beacon_tracker.keys()):
            self.beacon_tracker[key] = [t for t in self.beacon_tracker[key] if t > cutoff]
            if not self.beacon_tracker[key]:
                del self.beacon_tracker[key]

        # Clean fuzzing tracker
        for key in list(self.fuzzing_tracker.keys()):
            data = self.fuzzing_tracker[key]
            if data['first_seen'] and data['first_seen'] < cutoff:
                del self.fuzzing_tracker[key]

        # Clean exfil tracker
        for key in list(self.exfil_tracker.keys()):
            data = self.exfil_tracker[key]
            if data['first_seen'] and data['first_seen'] < cutoff:
                del self.exfil_tracker[key]

        # Clean vulnerability detector tracking data
        self.vuln_detector.cleanup_old_data(max_age_seconds)
