"""
Scapy-based packet sniffer for real-time network traffic capture.
Requires root/admin privileges for raw socket access.
"""
import threading
from queue import Queue
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw


class PacketSniffer:
    """
    Network packet sniffer using Scapy.
    Captures packets and puts them in a thread-safe queue for processing.
    """

    def __init__(self, interface='eth0', bpf_filter='', packet_queue=None):
        """
        Initialize the packet sniffer.

        Args:
            interface: Network interface to sniff on (e.g., 'eth0', 'any')
            bpf_filter: Berkeley Packet Filter string (e.g., 'tcp port 80')
            packet_queue: Thread-safe queue to put captured packets
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_queue = packet_queue or Queue()
        self._running = False
        self._thread = None

    def _packet_callback(self, packet):
        """Process each captured packet."""
        if IP not in packet:
            return

        # Debug: count packets (reduced logging)
        if not hasattr(self, '_pkt_count'):
            self._pkt_count = 0
        self._pkt_count += 1
        if self._pkt_count % 1000 == 0:
            print(f"[SNIFFER] Captured {self._pkt_count} packets")

        data = {
            'timestamp': datetime.utcnow(),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': self._get_protocol(packet),
            'length': len(packet),
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'payload_preview': None
        }

        # Extract TCP info
        if TCP in packet:
            data['src_port'] = packet[TCP].sport
            data['dst_port'] = packet[TCP].dport
            data['flags'] = self._get_tcp_flags(packet[TCP])

        # Extract UDP info
        elif UDP in packet:
            data['src_port'] = packet[UDP].sport
            data['dst_port'] = packet[UDP].dport

        # Extract DNS info
        if DNS in packet:
            data['dns_data'] = self._parse_dns(packet)

        # Extract payload preview
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            data['payload_preview'] = payload[:200].hex()

        self.packet_queue.put(data)

    def _get_protocol(self, packet):
        """Determine the protocol of the packet (transport + application layer)."""
        # Application layer protocol detection by port
        APP_PROTOCOLS = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
            80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'ORACLE',
            3306: 'MYSQL', 3389: 'RDP', 5432: 'POSTGRES', 5900: 'VNC',
            6379: 'REDIS', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
            27017: 'MONGODB'
        }

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            # Check destination port first (more likely to be the service)
            if dport in APP_PROTOCOLS:
                return APP_PROTOCOLS[dport]
            elif sport in APP_PROTOCOLS:
                return APP_PROTOCOLS[sport]
            # Payload-based detection for HTTP
            if Raw in packet:
                payload = bytes(packet[Raw].load[:20])
                if payload.startswith((b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'HTTP/')):
                    return 'HTTP'
                if payload.startswith(b'\x16\x03'):  # TLS handshake
                    return 'TLS'
            return 'TCP'

        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            if dport in APP_PROTOCOLS:
                return APP_PROTOCOLS[dport]
            elif sport in APP_PROTOCOLS:
                return APP_PROTOCOLS[sport]
            if DNS in packet:
                return 'DNS'
            return 'UDP'

        elif ICMP in packet:
            return 'ICMP'

        return f'IP/{packet[IP].proto}'

    def _get_tcp_flags(self, tcp_layer):
        """Extract TCP flags as a string."""
        flags = []
        if tcp_layer.flags.S:
            flags.append('SYN')
        if tcp_layer.flags.A:
            flags.append('ACK')
        if tcp_layer.flags.F:
            flags.append('FIN')
        if tcp_layer.flags.R:
            flags.append('RST')
        if tcp_layer.flags.P:
            flags.append('PSH')
        return ','.join(flags) if flags else None

    def _parse_dns(self, packet):
        """Extract DNS query/response data."""
        dns = packet[DNS]
        data = {'type': 'query' if dns.qr == 0 else 'response'}

        if dns.qd:
            data['query'] = dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)

        return data

    def _sniff_loop(self):
        """Main sniffing loop (runs in separate thread)."""
        try:
            # Handle "any" interface by sniffing on all available interfaces
            if self.interface == 'any':
                iface_list = ['eth0', 'eth1']
                print(f"[SNIFFER] Sniffing on multiple interfaces: {iface_list}")
            else:
                iface_list = self.interface

            sniff(
                iface=iface_list,
                filter=self.bpf_filter,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: not self._running
            )
        except Exception as e:
            print(f"Sniffer error: {e}")
            import traceback
            traceback.print_exc()

    def start(self):
        """Start packet capture in a background thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        print(f"Sniffer started on {self.interface}")

    def stop(self):
        """Stop packet capture."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        print("Sniffer stopped")

    def is_running(self):
        """Check if sniffer is currently running."""
        return self._running
