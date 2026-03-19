from flask import Blueprint, render_template, request, jsonify
from datetime import datetime, timedelta
import threading
from app import db
from app.models import Packet

packets_bp = Blueprint('packets', __name__, template_folder='../templates')

# BPF filters for each protocol type
PROTOCOL_FILTERS = {
    'TCP': 'tcp',
    'UDP': 'udp',
    'ICMP': 'icmp',
    'HTTP': 'tcp port 80',
    'HTTPS': 'tcp port 443',
    'DNS': 'udp port 53',
    'SSH': 'tcp port 22',
    'SMTP': 'tcp port 25',
    'FTP': 'tcp port 21',
    'REDIS': 'tcp port 6379',
    'MYSQL': 'tcp port 3306',
    'POP3': 'tcp port 110',
    'IMAP': 'tcp port 143',
    'RDP': 'tcp port 3389',
    'SMB': 'tcp port 445',
    'ANY': '',
}


@packets_bp.route('/explore')
def explore():
    """Packet explorer - capture and analyze single packets."""
    return render_template('packet_explore.html', protocols=sorted(PROTOCOL_FILTERS.keys()))


@packets_bp.route('/explore/capture', methods=['POST'])
def capture_one():
    """Capture a single packet matching the selected protocol."""
    protocol = request.form.get('protocol', 'ANY')
    bpf_filter = PROTOCOL_FILTERS.get(protocol, '')

    try:
        from scapy.all import sniff as scapy_sniff, IP, TCP, UDP, ICMP, DNS, Raw

        packets = scapy_sniff(
            iface=['eth0', 'eth1'],
            filter=bpf_filter,
            count=1,
            timeout=10
        )

        if not packets:
            return render_template('packet_explore.html',
                                   protocols=sorted(PROTOCOL_FILTERS.keys()),
                                   error=f"No {protocol} packet captured within 10s timeout.")

        pkt = packets[0]
        if IP not in pkt:
            return render_template('packet_explore.html',
                                   protocols=sorted(PROTOCOL_FILTERS.keys()),
                                   error="Captured packet has no IP layer.")

        # Parse ALL packet details
        packet_info = {
            'capture_time': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'requested_protocol': protocol,
            'total_length': len(pkt),
            'summary': pkt.summary(),
            'layers': [],
            'raw_hex': bytes(pkt).hex(),
            'raw_bytes_display': '',
        }

        # --- IP Layer ---
        ip_layer = pkt[IP]
        ip_info = {
            'name': 'IP (Internet Protocol)',
            'fields': {
                'Version': ip_layer.version,
                'IHL (Header Length)': f"{ip_layer.ihl} ({ip_layer.ihl * 4} bytes)",
                'Type of Service (TOS)': hex(ip_layer.tos),
                'Total Length': ip_layer.len,
                'Identification': ip_layer.id,
                'Flags': str(ip_layer.flags),
                'Fragment Offset': ip_layer.frag,
                'TTL': ip_layer.ttl,
                'Protocol Number': ip_layer.proto,
                'Checksum': hex(ip_layer.chksum) if ip_layer.chksum else 'N/A',
                'Source IP': ip_layer.src,
                'Destination IP': ip_layer.dst,
            }
        }
        packet_info['layers'].append(ip_info)

        # --- TCP Layer ---
        if TCP in pkt:
            tcp = pkt[TCP]
            flags = []
            if tcp.flags.S: flags.append('SYN')
            if tcp.flags.A: flags.append('ACK')
            if tcp.flags.F: flags.append('FIN')
            if tcp.flags.R: flags.append('RST')
            if tcp.flags.P: flags.append('PSH')
            if tcp.flags.U: flags.append('URG')

            tcp_info = {
                'name': 'TCP (Transmission Control Protocol)',
                'fields': {
                    'Source Port': tcp.sport,
                    'Destination Port': tcp.dport,
                    'Sequence Number': tcp.seq,
                    'Acknowledgment Number': tcp.ack,
                    'Data Offset': f"{tcp.dataofs} ({tcp.dataofs * 4} bytes)",
                    'Flags': ', '.join(flags) if flags else 'None',
                    'Window Size': tcp.window,
                    'Checksum': hex(tcp.chksum),
                    'Urgent Pointer': tcp.urgptr,
                }
            }
            if tcp.options:
                opts = []
                for opt in tcp.options:
                    if isinstance(opt, tuple):
                        opts.append(f"{opt[0]}={opt[1]}")
                    else:
                        opts.append(str(opt))
                tcp_info['fields']['Options'] = ', '.join(opts)
            packet_info['layers'].append(tcp_info)

        # --- UDP Layer ---
        elif UDP in pkt:
            udp = pkt[UDP]
            udp_info = {
                'name': 'UDP (User Datagram Protocol)',
                'fields': {
                    'Source Port': udp.sport,
                    'Destination Port': udp.dport,
                    'Length': udp.len,
                    'Checksum': hex(udp.chksum) if udp.chksum else 'N/A',
                }
            }
            packet_info['layers'].append(udp_info)

        # --- ICMP Layer ---
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            icmp_types = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}
            icmp_info = {
                'name': 'ICMP (Internet Control Message Protocol)',
                'fields': {
                    'Type': f"{icmp.type} ({icmp_types.get(icmp.type, 'Unknown')})",
                    'Code': icmp.code,
                    'Checksum': hex(icmp.chksum),
                    'ID': icmp.id if hasattr(icmp, 'id') else 'N/A',
                    'Sequence': icmp.seq if hasattr(icmp, 'seq') else 'N/A',
                }
            }
            packet_info['layers'].append(icmp_info)

        # --- DNS Layer ---
        if DNS in pkt:
            dns = pkt[DNS]
            dns_info = {
                'name': 'DNS (Domain Name System)',
                'fields': {
                    'Transaction ID': hex(dns.id),
                    'Type': 'Query' if dns.qr == 0 else 'Response',
                    'Opcode': dns.opcode,
                    'Authoritative': bool(dns.aa),
                    'Truncated': bool(dns.tc),
                    'Recursion Desired': bool(dns.rd),
                    'Recursion Available': bool(dns.ra),
                    'Response Code': dns.rcode,
                    'Questions': dns.qdcount,
                    'Answers': dns.ancount,
                }
            }
            if dns.qd:
                qname = dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                dns_info['fields']['Query Name'] = qname
                dns_info['fields']['Query Type'] = dns.qd.qtype
            packet_info['layers'].append(dns_info)

        # --- Payload / Raw Data ---
        if Raw in pkt:
            raw_data = bytes(pkt[Raw].load)
            payload_text = ''
            try:
                payload_text = raw_data[:500].decode('utf-8', errors='replace')
            except:
                payload_text = raw_data[:500].hex()

            raw_info = {
                'name': f'Payload ({len(raw_data)} bytes)',
                'fields': {
                    'Size': f"{len(raw_data)} bytes",
                    'Preview (text)': payload_text[:500],
                    'Preview (hex)': raw_data[:200].hex(),
                }
            }
            packet_info['layers'].append(raw_info)

        # Hex dump display (Wireshark-style)
        raw_bytes = bytes(pkt)
        hex_lines = []
        for i in range(0, min(len(raw_bytes), 512), 16):
            chunk = raw_bytes[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_lines.append(f'{i:04x}  {hex_part:<48}  {ascii_part}')
        packet_info['hex_dump'] = '\n'.join(hex_lines)

        return render_template('packet_explore.html',
                               protocols=sorted(PROTOCOL_FILTERS.keys()),
                               packet=packet_info)

    except Exception as e:
        return render_template('packet_explore.html',
                               protocols=sorted(PROTOCOL_FILTERS.keys()),
                               error=f"Capture error: {str(e)}")


@packets_bp.route('/')
def list_packets():
    """View captured packets."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    # Filters
    src_ip = request.args.get('src_ip')
    dst_ip = request.args.get('dst_ip')
    protocol = request.args.get('protocol')

    query = Packet.query

    if src_ip:
        query = query.filter(Packet.src_ip == src_ip)
    if dst_ip:
        query = query.filter(Packet.dst_ip == dst_ip)
    if protocol:
        query = query.filter(Packet.protocol == protocol)

    packets = query.order_by(Packet.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('packets.html', packets=packets)


@packets_bp.route('/<int:packet_id>')
def packet_detail(packet_id):
    """View single packet details."""
    packet = Packet.query.get_or_404(packet_id)
    return render_template('packet_detail.html', packet=packet)
