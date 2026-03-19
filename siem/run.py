#!/usr/bin/env python3
"""
SIEM Application Entry Point
Starts the Flask web server and packet sniffer.

Usage:
    python run.py                    # Start without packet capture
    sudo python run.py --capture     # Start with packet capture (requires root)
    sudo python run.py --capture --interface eth0
"""
import os
import sys
import argparse
import threading
from queue import Queue
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Config
from app import create_app, db
from app.models import Packet, Event, Alert, BannedIP, WhitelistIP, AttackChain
from detection.correlator import correlate_event


def create_auto_ban_handler(app):
    """Create auto-ban handler with app context."""
    def auto_ban_handler(ip_address, ban_type, reason):
        """Handle auto-ban from analyzer."""
        with app.app_context():
            from app.routes.firewall import auto_ban_ip
            auto_ban_ip(ip_address, ban_type, reason)
    return auto_ban_handler


def load_banned_ips_to_cache(app, analyzer):
    """Load currently banned IPs into analyzer cache."""
    with app.app_context():
        banned = BannedIP.query.filter_by(is_active=True).all()
        ip_list = [b.ip_address for b in banned]
        analyzer.load_banned_ips(ip_list)
        print(f"[FIREWALL] Loaded {len(ip_list)} banned IPs into cache")


def load_whitelist_to_cache(app, analyzer):
    """Load whitelisted IPs from database into analyzer cache."""
    with app.app_context():
        whitelist = WhitelistIP.query.all()
        ip_list = [w.ip_address for w in whitelist]
        analyzer.load_whitelist_from_db(ip_list)
        print(f"[FIREWALL] Loaded {len(ip_list)} custom whitelisted IPs into cache")


def process_packet_queue(app, packet_queue, analyzer):
    """Background thread to process packets from the queue and store in DB."""
    packet_count = 0
    SAMPLE_RATE = 10  # Only store 1 in N packets to reduce DB load
    with app.app_context():
        batch = []
        batch_size = Config.PACKET_BATCH_SIZE

        while True:
            try:
                packet_data = packet_queue.get(timeout=5)
                packet_count += 1

                # Debug: log every 500 packets (reduced frequency)
                if packet_count % 500 == 0:
                    print(f"[DEBUG] Processed {packet_count} packets, queue size: {packet_queue.qsize()}")

                # Skip if source IP is banned
                src_ip = packet_data.get('src_ip')
                if src_ip in analyzer.banned_ips_cache:
                    # Increment blocked packet count
                    ban = BannedIP.query.filter_by(ip_address=src_ip, is_active=True).first()
                    if ban:
                        ban.packet_count += 1
                        if ban.packet_count % 100 == 0:  # Commit every 100 blocked packets
                            db.session.commit()
                    continue

                # Only store sampled packets to reduce DB load
                # But ALWAYS analyze for security events
                if packet_count % SAMPLE_RATE == 0:
                    packet = Packet(
                        timestamp=packet_data['timestamp'],
                        src_ip=packet_data['src_ip'],
                        dst_ip=packet_data['dst_ip'],
                        src_port=packet_data.get('src_port'),
                        dst_port=packet_data.get('dst_port'),
                        protocol=packet_data['protocol'],
                        length=packet_data['length'],
                        flags=packet_data.get('flags'),
                        payload_preview=packet_data.get('payload_preview')
                    )
                    batch.append(packet)

                # Analyze packet for events
                events = analyzer.analyze(packet_data)
                for event_data in events:
                    event = Event(
                        timestamp=event_data['timestamp'],
                        event_type=event_data['event_type'],
                        src_ip=event_data.get('src_ip'),
                        dst_ip=event_data.get('dst_ip'),
                        src_port=event_data.get('src_port'),
                        dst_port=event_data.get('dst_port'),
                        details=event_data.get('details'),
                        severity=event_data.get('severity', 0),
                        log_source=event_data.get('log_source', 'packet')
                    )
                    db.session.add(event)

                    # Create alert for high-severity events
                    alert_id = None
                    if event_data.get('severity', 0) >= 3:
                        alert = Alert(
                            title=f"{event_data['event_type'].replace('_', ' ').title()} Detected",
                            description=str(event_data.get('details', '')),
                            severity='critical' if event_data['severity'] >= 4 else 'high',
                            source_ip=event_data.get('src_ip'),
                            dest_ip=event_data.get('dst_ip'),
                            rule_name=event_data['event_type'],
                            first_seen=event_data['timestamp'],
                            last_seen=event_data['timestamp']
                        )
                        db.session.add(alert)
                        db.session.flush()  # Get alert.id before commit
                        alert_id = alert.id

                    # Kill chain correlation
                    if event_data.get('severity', 0) >= 2:
                        try:
                            correlate_event(db, AttackChain, event_data, alert_id=alert_id)
                        except Exception as corr_err:
                            print(f"[CORRELATOR] Error: {corr_err}")

                # Batch insert packets
                if len(batch) >= batch_size:
                    db.session.add_all(batch)
                    db.session.commit()
                    batch = []
                    # Cleanup old tracking data
                    analyzer.cleanup_old_data()

            except Exception as e:
                if batch:
                    try:
                        db.session.add_all(batch)
                        db.session.commit()
                        batch = []
                    except:
                        db.session.rollback()


def main():
    parser = argparse.ArgumentParser(description='SIEM Application')
    parser.add_argument('--capture', action='store_true',
                        help='Enable packet capture (requires root)')
    parser.add_argument('--interface', '-i', default=Config.SNIFF_INTERFACE,
                        help=f'Network interface to capture (default: {Config.SNIFF_INTERFACE})')
    parser.add_argument('--filter', '-f', default=Config.SNIFF_FILTER,
                        help='BPF filter for packet capture')
    parser.add_argument('--host', default=Config.HOST,
                        help=f'Web server host (default: {Config.HOST})')
    parser.add_argument('--port', '-p', type=int, default=Config.PORT,
                        help=f'Web server port (default: {Config.PORT})')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Enable debug mode')
    parser.add_argument('--no-debug', action='store_true',
                        help='Disable debug mode')

    args = parser.parse_args()

    # Create Flask app
    app = create_app()

    if args.capture:
        # Check for root privileges
        if os.geteuid() != 0:
            print("ERROR: Packet capture requires root privileges.")
            print("Run with: sudo python run.py --capture")
            sys.exit(1)

        print(f"Starting packet capture on {args.interface}...")

        from capture.sniffer import PacketSniffer
        from capture.analyzer import PacketAnalyzer

        packet_queue = Queue()
        analyzer = PacketAnalyzer()

        # Setup auto-ban handler
        analyzer.on_auto_ban = create_auto_ban_handler(app)

        # Load banned IPs into cache
        load_banned_ips_to_cache(app, analyzer)

        # Load whitelist into cache
        load_whitelist_to_cache(app, analyzer)

        # Start packet sniffer
        sniffer = PacketSniffer(
            interface=args.interface,
            bpf_filter=args.filter,
            packet_queue=packet_queue
        )
        sniffer.start()

        # Start packet processor thread
        processor = threading.Thread(
            target=process_packet_queue,
            args=(app, packet_queue, analyzer),
            daemon=True
        )
        processor.start()

        print(f"Packet capture active on {args.interface}")
        print(f"[FIREWALL] DDoS detection enabled - Thresholds: {analyzer.DDOS_PACKET_THRESHOLD} pkts/{analyzer.DDOS_TIME_WINDOW}s")
    else:
        print("Starting without packet capture (use --capture to enable)")

    # Start Flask web server
    print(f"Starting web server at http://{args.host}:{args.port}")
    debug_mode = args.debug and not args.no_debug
    app.run(host=args.host, port=args.port, debug=debug_mode, threaded=True, use_reloader=False)


if __name__ == '__main__':
    main()
