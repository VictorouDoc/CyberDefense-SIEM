"""
Vulnerability Exploitation Detection Module.
Detects exploitation attempts against discovered network services.

Targeted Services (from network scan):
- Samba (storage - 192.168.1.30:139/445)
- Orthanc DICOM (192.168.1.71:4242/8042)
- Redis (192.168.1.106:6379)
- Apache / EHR (192.168.1.102:80)
- Mail servers (SMTP/POP3)
- SSH / OpenSSH
- Nginx
"""

import re
from datetime import datetime
from collections import defaultdict


class VulnerabilityExploitDetector:
    """
    Detects vulnerability exploitation attempts in network traffic.
    """

    # Critical hospital infrastructure
    PROTECTED_HOSTS = {
        '192.168.1.30': 'storage',
        '192.168.1.71': 'orthanc',
        '192.168.1.102': 'ehr',
        '192.168.1.106': 'redis',
        '192.168.1.111': 'mail',
    }

    def __init__(self):
        # Track exploitation attempts per source IP
        self.exploit_tracker = defaultdict(lambda: {'attempts': 0, 'types': set()})
        # Track brute force attempts
        self.auth_tracker = defaultdict(lambda: {'failures': 0, 'first_seen': None})
        # Callback for auto-ban
        self.on_exploit_detected = None

    def analyze(self, packet_data):
        """
        Analyze packet for vulnerability exploitation attempts.
        Returns list of detection events.
        """
        events = []
        dst_port = packet_data.get('dst_port')
        src_port = packet_data.get('src_port')

        # SMB/Samba exploitation (ports 139, 445)
        if dst_port in (139, 445):
            event = self._detect_smb_exploit(packet_data)
            if event:
                events.append(event)

        # Redis exploitation (port 6379)
        if dst_port == 6379:
            event = self._detect_redis_exploit(packet_data)
            if event:
                events.append(event)

        # DICOM/Orthanc exploitation (ports 4242, 8042)
        if dst_port in (4242, 8042):
            event = self._detect_dicom_exploit(packet_data)
            if event:
                events.append(event)

        # HTTP exploitation (ports 80, 443, 8080)
        if dst_port in (80, 443, 8080, 8042):
            event = self._detect_http_exploit(packet_data)
            if event:
                events.append(event)

        # SSH exploitation (port 22)
        if dst_port == 22:
            event = self._detect_ssh_exploit(packet_data)
            if event:
                events.append(event)

        # SMTP exploitation (port 25)
        if dst_port == 25:
            event = self._detect_smtp_exploit(packet_data)
            if event:
                events.append(event)

        # POP3 exploitation (port 110)
        if dst_port == 110:
            event = self._detect_pop3_exploit(packet_data)
            if event:
                events.append(event)

        return events

    def _get_payload_str(self, packet_data):
        """Extract payload as string from packet data."""
        payload = packet_data.get('payload_preview')
        if not payload:
            return ''
        try:
            payload_bytes = bytes.fromhex(payload)
            return payload_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return ''

    def _extract_real_ip(self, packet_data):
        """
        Extract real client IP from HTTP headers (X-Forwarded-For, X-Real-IP).
        Falls back to packet src_ip if no forwarding header found.
        """
        payload = self._get_payload_str(packet_data)
        if not payload:
            return packet_data.get('src_ip')

        # Try X-Forwarded-For first (can contain multiple IPs, first is the client)
        xff_match = re.search(r'X-Forwarded-For:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', payload, re.IGNORECASE)
        if xff_match:
            return xff_match.group(1)

        # Try X-Real-IP
        xri_match = re.search(r'X-Real-IP:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', payload, re.IGNORECASE)
        if xri_match:
            return xri_match.group(1)

        return packet_data.get('src_ip')

    def _create_event(self, packet_data, event_type, severity, details):
        """Create a standardized detection event."""
        return {
            'timestamp': packet_data.get('timestamp', datetime.utcnow()),
            'event_type': event_type,
            'src_ip': packet_data.get('src_ip'),
            'dst_ip': packet_data.get('dst_ip'),
            'src_port': packet_data.get('src_port'),
            'dst_port': packet_data.get('dst_port'),
            'severity': severity,
            'details': details,
            'log_source': 'vuln_detection'
        }

    # ==================== SMB/SAMBA EXPLOITATION ====================

    def _detect_smb_exploit(self, packet_data):
        """
        Detect SMB/Samba exploitation attempts.
        - EternalBlue (MS17-010)
        - SMB relay attacks
        - Null session enumeration
        - SambaCry (CVE-2017-7494)
        """
        payload = self._get_payload_str(packet_data)
        payload_lower = payload.lower()

        # EternalBlue signatures
        eternalblue_patterns = [
            b'\x00\x00\x00\x31\xff\x53\x4d\x42',  # SMB Trans2
            'trans2_open',
            'trans2_session_setup',
            '\x00\x00\x00\x2f\xfe\x53\x4d\x42',  # SMB2 exploit
        ]

        for pattern in eternalblue_patterns:
            if isinstance(pattern, bytes):
                try:
                    if pattern in bytes.fromhex(packet_data.get('payload_preview', '')):
                        return self._create_event(packet_data, 'exploit_eternalblue', 4, {
                            'exploit': 'EternalBlue (MS17-010)',
                            'cve': 'CVE-2017-0144',
                            'target_service': 'SMB',
                            'description': 'Potential EternalBlue exploitation attempt detected'
                        })
                except Exception:
                    pass
            elif pattern in payload_lower:
                return self._create_event(packet_data, 'exploit_eternalblue', 4, {
                    'exploit': 'EternalBlue (MS17-010)',
                    'cve': 'CVE-2017-0144',
                    'target_service': 'SMB',
                    'description': 'Potential EternalBlue exploitation attempt detected'
                })

        # SambaCry detection (CVE-2017-7494)
        sambacry_patterns = [
            '/tmp/',
            'is_known_pipename',
            '\\\\pipe\\',
            '.so',  # Shared object loading
        ]
        matches = sum(1 for p in sambacry_patterns if p in payload)
        if matches >= 2:
            return self._create_event(packet_data, 'exploit_sambacry', 4, {
                'exploit': 'SambaCry',
                'cve': 'CVE-2017-7494',
                'target_service': 'Samba',
                'description': 'Potential SambaCry RCE exploitation attempt'
            })

        # SMB null session enumeration
        if '\x00\x00\x00\x00' in payload and 'ipc$' in payload_lower:
            return self._create_event(packet_data, 'smb_null_session', 3, {
                'attack': 'SMB Null Session',
                'target_service': 'SMB',
                'description': 'SMB null session enumeration attempt'
            })

        # SMB brute force / password spray
        smb_auth_patterns = ['ntlmssp', 'session setup', 'negprot']
        if any(p in payload_lower for p in smb_auth_patterns):
            src_ip = packet_data.get('src_ip')
            self.auth_tracker[f"smb:{src_ip}"]['failures'] += 1
            if self.auth_tracker[f"smb:{src_ip}"]['failures'] >= 5:
                self.auth_tracker[f"smb:{src_ip}"]['failures'] = 0
                return self._create_event(packet_data, 'smb_bruteforce', 3, {
                    'attack': 'SMB Brute Force',
                    'target_service': 'SMB',
                    'description': 'Multiple SMB authentication attempts detected'
                })

        return None

    # ==================== REDIS EXPLOITATION ====================

    def _detect_redis_exploit(self, packet_data):
        """
        Detect Redis exploitation attempts.
        - Unauthenticated access
        - Redis RCE via SLAVEOF/CONFIG
        - Lua script injection
        """
        payload = self._get_payload_str(packet_data)
        payload_upper = payload.upper()

        # Redis RCE patterns
        rce_patterns = [
            ('CONFIG SET', 'Redis CONFIG SET RCE attempt'),
            ('SLAVEOF', 'Redis SLAVEOF replication attack'),
            ('MODULE LOAD', 'Redis malicious module loading'),
            ('DEBUG SEGFAULT', 'Redis debug crash attempt'),
            ('SCRIPT LOAD', 'Redis Lua script injection'),
            ('EVAL ', 'Redis Lua eval execution'),
            ('FLUSHALL', 'Redis data destruction attempt'),
            ('SHUTDOWN', 'Redis shutdown attempt'),
        ]

        for pattern, description in rce_patterns:
            if pattern in payload_upper:
                severity = 4 if pattern in ('CONFIG SET', 'SLAVEOF', 'MODULE LOAD', 'EVAL ') else 3
                return self._create_event(packet_data, 'exploit_redis', severity, {
                    'exploit': 'Redis RCE',
                    'pattern': pattern,
                    'target_service': 'Redis',
                    'description': description
                })

        # Detect SSH key injection via Redis
        if 'AUTHORIZED_KEYS' in payload_upper or '.SSH' in payload_upper:
            return self._create_event(packet_data, 'exploit_redis_ssh', 4, {
                'exploit': 'Redis SSH Key Injection',
                'target_service': 'Redis',
                'description': 'Attempt to write SSH keys via Redis'
            })

        # Detect crontab injection via Redis
        if 'CRON' in payload_upper or '/VAR/SPOOL' in payload_upper:
            return self._create_event(packet_data, 'exploit_redis_cron', 4, {
                'exploit': 'Redis Crontab Injection',
                'target_service': 'Redis',
                'description': 'Attempt to write crontab via Redis'
            })

        # Detect webshell injection via Redis
        webshell_patterns = ['<?PHP', 'SYSTEM(', 'EXEC(', 'SHELL_EXEC', 'PASSTHRU']
        if any(p in payload_upper for p in webshell_patterns):
            return self._create_event(packet_data, 'exploit_redis_webshell', 4, {
                'exploit': 'Redis Webshell Injection',
                'target_service': 'Redis',
                'description': 'Attempt to inject webshell via Redis'
            })

        return None

    # ==================== DICOM/ORTHANC EXPLOITATION ====================

    def _detect_dicom_exploit(self, packet_data):
        """
        Detect DICOM/Orthanc exploitation attempts.
        - DICOM injection attacks
        - Orthanc API abuse
        - Patient data exfiltration
        """
        payload = self._get_payload_str(packet_data)
        payload_lower = payload.lower()
        dst_port = packet_data.get('dst_port')

        # Orthanc REST API abuse (port 8042)
        if dst_port == 8042:
            api_abuse_patterns = [
                ('/tools/execute-script', 'Orthanc script execution'),
                ('/system', 'Orthanc system access'),
                ('/../', 'Path traversal in Orthanc'),
                ('/plugins', 'Orthanc plugin manipulation'),
                ('DELETE ', 'Orthanc data deletion'),
            ]
            for pattern, description in api_abuse_patterns:
                if pattern in payload:
                    return self._create_event(packet_data, 'exploit_orthanc', 4, {
                        'exploit': 'Orthanc API Abuse',
                        'pattern': pattern,
                        'target_service': 'Orthanc DICOM',
                        'description': description
                    })

        # DICOM C-STORE abuse (potential malicious DICOM files)
        if dst_port == 4242:
            # Large number of DICOM requests (data exfiltration)
            src_ip = packet_data.get('src_ip')
            self.exploit_tracker[f"dicom:{src_ip}"]['attempts'] += 1
            if self.exploit_tracker[f"dicom:{src_ip}"]['attempts'] >= 50:
                self.exploit_tracker[f"dicom:{src_ip}"]['attempts'] = 0
                return self._create_event(packet_data, 'dicom_exfiltration', 3, {
                    'attack': 'DICOM Data Exfiltration',
                    'target_service': 'DICOM',
                    'description': 'High volume of DICOM requests - potential data exfiltration'
                })

        # DICOM injection patterns
        if 'patientname' in payload_lower or 'patientid' in payload_lower:
            injection_chars = ["'", '"', ';', '--', '/*', '<script']
            if any(c in payload for c in injection_chars):
                return self._create_event(packet_data, 'dicom_injection', 3, {
                    'attack': 'DICOM Injection',
                    'target_service': 'DICOM',
                    'description': 'Potential injection attack via DICOM fields'
                })

        return None

    # ==================== HTTP/WEB EXPLOITATION ====================

    def _detect_http_exploit(self, packet_data):
        """
        Detect HTTP exploitation attempts.
        - Log4Shell (CVE-2021-44228)
        - Apache exploits
        - Spring4Shell
        - Server-Side Template Injection
        - Remote Code Execution
        """
        payload = self._get_payload_str(packet_data)
        payload_lower = payload.lower()

        # Override src_ip with real IP from HTTP headers for all HTTP detections
        real_ip = self._extract_real_ip(packet_data)
        if real_ip != packet_data.get('src_ip'):
            packet_data = dict(packet_data)
            packet_data['src_ip'] = real_ip

        # Log4Shell detection (CVE-2021-44228)
        log4j_patterns = [
            '${jndi:', '${jndi:ldap:', '${jndi:rmi:',
            '${${lower:j}ndi:', '${${::-j}ndi:',
            '${${env:', '${${sys:', '${${date:',
        ]
        for pattern in log4j_patterns:
            if pattern in payload_lower:
                return self._create_event(packet_data, 'exploit_log4shell', 4, {
                    'exploit': 'Log4Shell',
                    'cve': 'CVE-2021-44228',
                    'target_service': 'HTTP/Java',
                    'pattern': pattern,
                    'description': 'Log4Shell (Log4j RCE) exploitation attempt'
                })

        # Spring4Shell detection (CVE-2022-22965)
        spring_patterns = [
            'class.module.classloader',
            'class.module.classLoader.resources',
            'tomcatwar.jsp',
        ]
        for pattern in spring_patterns:
            if pattern in payload_lower:
                return self._create_event(packet_data, 'exploit_spring4shell', 4, {
                    'exploit': 'Spring4Shell',
                    'cve': 'CVE-2022-22965',
                    'target_service': 'HTTP/Spring',
                    'description': 'Spring4Shell RCE exploitation attempt'
                })

        # Apache Struts RCE (CVE-2017-5638)
        struts_patterns = [
            'content-type.*ognl',
            '#cmd=',
            '#iswin=',
            'processbuilder',
            'runtime.getruntime',
        ]
        for pattern in struts_patterns:
            if re.search(pattern, payload_lower):
                return self._create_event(packet_data, 'exploit_struts', 4, {
                    'exploit': 'Apache Struts RCE',
                    'cve': 'CVE-2017-5638',
                    'target_service': 'HTTP/Struts',
                    'description': 'Apache Struts OGNL injection attempt'
                })

        # Server-Side Template Injection (SSTI)
        # Only check inbound requests to our servers, not outbound traffic
        dst_ip = packet_data.get('dst_ip', '')
        is_inbound = dst_ip.startswith(('10.', '192.168.'))
        if is_inbound:
            ssti_signatures = [
                r'\{\{.*?\d+\s*[\*\+\-]\s*\d+.*?\}\}',   # {{7*7}}, {{7*'7'}}
                r'\{\{.*?config.*?\}\}',                    # {{config}}, {{config.items()}}
                r'\{\{.*?self\.__.*?\}\}',                  # {{self.__init__}}
                r'\{%.*?import.*?%\}',                      # {% import os %}
                r'\{\{.*?__class__.*?\}\}',                 # {{''.__class__}}
                r'\{\{.*?__mro__.*?\}\}',                   # MRO traversal
                r'\{\{.*?__subclasses__.*?\}\}',            # subclass enumeration
                r'\{\{.*?__globals__.*?\}\}',               # globals access
                r'\{\{.*?__builtins__.*?\}\}',              # builtins access
                r'\{\{.*?lipsum.*?\}\}',                    # lipsum trick
                r'\{\{.*?cycler.*?\}\}',                    # cycler trick
                r'\{\{.*?joiner.*?\}\}',                    # joiner trick
                r'\{\{.*?request\.*?\}\}',                  # request object access
            ]
            ssti_keywords = [
                '{{7*7}}', "{{7*'7'}}", '{{config}}', '{{self.', '{%import', '{%set',
                '__class__', '__mro__', '__subclasses__', '__globals__', '__builtins__',
                '${7*7}', '${T(java.lang.', '#{7*7}',
                '#set($', '#foreach(', '#include(',
                '<%=', '%>${',
                'os.popen', 'subprocess', '__import__',
            ]

            # Regex signatures (high confidence, 1 match = detection)
            for pattern in ssti_signatures:
                if re.search(pattern, payload):
                    real_ip = self._extract_real_ip(packet_data)
                    return self._create_event(packet_data, 'attack_ssti', 3, {
                        'attack': 'Server-Side Template Injection',
                        'target_service': 'HTTP',
                        'real_source_ip': real_ip,
                        'pattern_matched': pattern,
                        'payload_sample': payload[:200],
                        'description': f'SSTI exploitation attempt from {real_ip}'
                    })

            # Keyword patterns (need 1+ match)
            ssti_count = sum(1 for p in ssti_keywords if p in payload)
            if ssti_count >= 1:
                real_ip = self._extract_real_ip(packet_data)
                matched = [p for p in ssti_keywords if p in payload]
                return self._create_event(packet_data, 'attack_ssti', 3, {
                    'attack': 'Server-Side Template Injection',
                    'target_service': 'HTTP',
                    'real_source_ip': real_ip,
                    'patterns_matched': matched[:5],
                    'payload_sample': payload[:200],
                    'description': f'SSTI exploitation attempt from {real_ip}'
                })

        # PHP exploitation patterns
        php_rce_patterns = [
            'php://input', 'php://filter', 'data://text',
            'expect://', 'phar://',
            'system(', 'exec(', 'passthru(', 'shell_exec(',
            'eval(base64_decode',
        ]
        for pattern in php_rce_patterns:
            if pattern in payload_lower:
                return self._create_event(packet_data, 'exploit_php_rce', 4, {
                    'exploit': 'PHP RCE',
                    'pattern': pattern,
                    'target_service': 'HTTP/PHP',
                    'description': 'PHP remote code execution attempt'
                })

        # Local/Remote File Inclusion
        lfi_patterns = [
            '/etc/passwd', '/etc/shadow', '/proc/self',
            'c:\\windows\\', 'c:/windows/',
            '....//....//..../',
            'file://', 'dict://', 'gopher://',
        ]
        for pattern in lfi_patterns:
            if pattern in payload_lower:
                return self._create_event(packet_data, 'attack_lfi', 3, {
                    'attack': 'Local/Remote File Inclusion',
                    'pattern': pattern,
                    'target_service': 'HTTP',
                    'description': 'LFI/RFI exploitation attempt'
                })

        # Shellshock (CVE-2014-6271)
        if '() {' in payload and (':;' in payload or '};' in payload):
            return self._create_event(packet_data, 'exploit_shellshock', 4, {
                'exploit': 'Shellshock',
                'cve': 'CVE-2014-6271',
                'target_service': 'HTTP/CGI',
                'description': 'Shellshock (Bash RCE) exploitation attempt'
            })

        # Apache mod_proxy SSRF (CVE-2021-40438)
        if 'unix:' in payload_lower and 'http://' in payload_lower:
            return self._create_event(packet_data, 'exploit_apache_ssrf', 3, {
                'exploit': 'Apache mod_proxy SSRF',
                'cve': 'CVE-2021-40438',
                'target_service': 'HTTP/Apache',
                'description': 'Apache mod_proxy SSRF exploitation attempt'
            })

        return None

    # ==================== SSH EXPLOITATION ====================

    def _detect_ssh_exploit(self, packet_data):
        """
        Detect SSH exploitation attempts.
        - Brute force attacks
        - CVE exploits
        - Weak algorithm attacks
        """
        payload = self._get_payload_str(packet_data)
        src_ip = packet_data.get('src_ip')

        # Track SSH connection attempts for brute force detection
        if 'SSH-' in payload or packet_data.get('flags') == 'SYN':
            tracker_key = f"ssh:{src_ip}"
            if self.auth_tracker[tracker_key]['first_seen'] is None:
                self.auth_tracker[tracker_key]['first_seen'] = packet_data.get('timestamp', datetime.utcnow())
            self.auth_tracker[tracker_key]['failures'] += 1

            # Brute force threshold
            if self.auth_tracker[tracker_key]['failures'] >= 10:
                self.auth_tracker[tracker_key]['failures'] = 0
                return self._create_event(packet_data, 'ssh_bruteforce', 3, {
                    'attack': 'SSH Brute Force',
                    'target_service': 'SSH',
                    'attempts': 10,
                    'description': 'SSH brute force attack detected'
                })

        # Libssh authentication bypass (CVE-2018-10933)
        if 'SSH_MSG_USERAUTH_SUCCESS' in payload:
            return self._create_event(packet_data, 'exploit_libssh_bypass', 4, {
                'exploit': 'Libssh Auth Bypass',
                'cve': 'CVE-2018-10933',
                'target_service': 'SSH',
                'description': 'Libssh authentication bypass attempt'
            })

        # Terrapin attack detection (CVE-2023-48795)
        if 'chacha20' in payload.lower() or 'aes.*gcm' in payload.lower():
            # Additional check for sequence number manipulation would need stateful tracking
            pass

        return None

    # ==================== SMTP EXPLOITATION ====================

    def _detect_smtp_exploit(self, packet_data):
        """
        Detect SMTP exploitation attempts.
        - Open relay abuse
        - Command injection
        - Buffer overflow exploits
        """
        payload = self._get_payload_str(packet_data)
        payload_upper = payload.upper()

        # SMTP command injection
        injection_patterns = [
            ('|', 'Pipe command injection'),
            ('`', 'Backtick command injection'),
            ('$(', 'Command substitution'),
            ('\r\n.', 'SMTP smuggling'),
        ]
        for pattern, description in injection_patterns:
            if pattern in payload and any(cmd in payload_upper for cmd in ['MAIL', 'RCPT', 'DATA']):
                return self._create_event(packet_data, 'smtp_injection', 3, {
                    'attack': 'SMTP Command Injection',
                    'pattern': pattern,
                    'target_service': 'SMTP',
                    'description': description
                })

        # Exim RCE (CVE-2019-15846, CVE-2019-16928)
        exim_patterns = [
            '${run{', '${perl{', '${extract{',
        ]
        for pattern in exim_patterns:
            if pattern in payload:
                return self._create_event(packet_data, 'exploit_exim', 4, {
                    'exploit': 'Exim RCE',
                    'cve': 'CVE-2019-15846',
                    'target_service': 'SMTP/Exim',
                    'description': 'Exim command execution exploitation attempt'
                })

        # Open relay detection
        src_ip = packet_data.get('src_ip')
        if 'RCPT TO:' in payload_upper:
            # Track relay attempts from external IPs
            if not src_ip or not src_ip.startswith(('10.', '192.168.', '172.')):
                self.exploit_tracker[f"smtp_relay:{src_ip}"]['attempts'] += 1
                if self.exploit_tracker[f"smtp_relay:{src_ip}"]['attempts'] >= 5:
                    self.exploit_tracker[f"smtp_relay:{src_ip}"]['attempts'] = 0
                    return self._create_event(packet_data, 'smtp_relay_abuse', 2, {
                        'attack': 'SMTP Open Relay Abuse',
                        'target_service': 'SMTP',
                        'description': 'Potential spam relay abuse detected'
                    })

        return None

    # ==================== POP3 EXPLOITATION ====================

    def _detect_pop3_exploit(self, packet_data):
        """
        Detect POP3 exploitation attempts.
        - Brute force
        - Buffer overflow
        """
        payload = self._get_payload_str(packet_data)
        payload_upper = payload.upper()
        src_ip = packet_data.get('src_ip')

        # POP3 brute force detection
        if 'USER ' in payload_upper or 'PASS ' in payload_upper:
            tracker_key = f"pop3:{src_ip}"
            self.auth_tracker[tracker_key]['failures'] += 1
            if self.auth_tracker[tracker_key]['failures'] >= 10:
                self.auth_tracker[tracker_key]['failures'] = 0
                return self._create_event(packet_data, 'pop3_bruteforce', 3, {
                    'attack': 'POP3 Brute Force',
                    'target_service': 'POP3',
                    'description': 'POP3 brute force attack detected'
                })

        # Buffer overflow detection (very long strings)
        if len(payload) > 1000:
            return self._create_event(packet_data, 'pop3_overflow', 3, {
                'attack': 'POP3 Buffer Overflow',
                'target_service': 'POP3',
                'payload_length': len(payload),
                'description': 'Potential POP3 buffer overflow attempt'
            })

        return None

    def cleanup_old_data(self, max_age_seconds=300):
        """Clean up old tracking data."""
        # Reset counters periodically to prevent false positives
        self.exploit_tracker.clear()
        self.auth_tracker.clear()
