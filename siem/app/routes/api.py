from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from sqlalchemy import func
from app import db
from app.models import Packet, Event, Alert

api_bp = Blueprint('api', __name__)


@api_bp.route('/stats')
def get_stats():
    """Get dashboard statistics."""
    now = datetime.utcnow()
    last_hour = now - timedelta(hours=1)
    last_24h = now - timedelta(hours=24)

    return jsonify({
        'packets_1h': Packet.query.filter(Packet.timestamp >= last_hour).count(),
        'packets_24h': Packet.query.filter(Packet.timestamp >= last_24h).count(),
        'events_24h': Event.query.filter(Event.timestamp >= last_24h).count(),
        'alerts_open': Alert.query.filter(Alert.status.in_(['new', 'ack', 'investigating'])).count(),
    })


@api_bp.route('/packets')
def get_packets():
    """Get recent packets as JSON."""
    limit = request.args.get('limit', 100, type=int)
    limit = min(limit, 1000)  # Cap at 1000

    packets = Packet.query.order_by(Packet.timestamp.desc()).limit(limit).all()
    return jsonify([p.to_dict() for p in packets])


@api_bp.route('/packets/timeline')
def packets_timeline():
    """Get packet counts over time for charts."""
    hours = request.args.get('hours', 24, type=int)
    now = datetime.utcnow()

    # Group packets by hour
    timeline = []
    for i in range(hours, 0, -1):
        start = now - timedelta(hours=i)
        end = now - timedelta(hours=i-1)
        count = Packet.query.filter(
            Packet.timestamp >= start,
            Packet.timestamp < end
        ).count()
        timeline.append({
            'hour': start.strftime('%H:%M'),
            'count': count
        })

    return jsonify(timeline)


@api_bp.route('/events')
def get_events():
    """Get recent events as JSON."""
    limit = request.args.get('limit', 100, type=int)
    events = Event.query.order_by(Event.timestamp.desc()).limit(limit).all()
    return jsonify([e.to_dict() for e in events])


@api_bp.route('/alerts')
def get_alerts():
    """Get alerts as JSON."""
    status = request.args.get('status', 'open')

    query = Alert.query
    if status == 'open':
        query = query.filter(Alert.status.in_(['new', 'ack', 'investigating']))
    elif status != 'all':
        query = query.filter(Alert.status == status)

    alerts = query.order_by(Alert.created_at.desc()).limit(100).all()
    return jsonify([a.to_dict() for a in alerts])


@api_bp.route('/top-talkers')
def top_talkers():
    """Get top source IPs by packet count."""
    hours = request.args.get('hours', 1, type=int)
    limit = request.args.get('limit', 10, type=int)

    since = datetime.utcnow() - timedelta(hours=hours)

    results = db.session.query(
        Packet.src_ip,
        func.count(Packet.id).label('count')
    ).filter(
        Packet.timestamp >= since
    ).group_by(Packet.src_ip).order_by(func.count(Packet.id).desc()).limit(limit).all()

    return jsonify([{'ip': r[0], 'count': r[1]} for r in results])


@api_bp.route('/protocols')
def protocol_distribution():
    """Get protocol distribution."""
    hours = request.args.get('hours', 1, type=int)
    since = datetime.utcnow() - timedelta(hours=hours)

    results = db.session.query(
        Packet.protocol,
        func.count(Packet.id).label('count')
    ).filter(
        Packet.timestamp >= since
    ).group_by(Packet.protocol).all()

    return jsonify([{'protocol': r[0], 'count': r[1]} for r in results])


@api_bp.route('/test-alert', methods=['POST'])
def create_test_alert():
    """Create a test alert for debugging."""
    alert = Alert(
        title='Test Alert - Security Detection',
        description='This is a test alert to verify the alerting system is working correctly.',
        severity='high',
        status='new',
        source_ip='192.168.1.100',
        dest_ip='10.0.0.15',
        rule_name='test_rule',
        event_count=1,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow()
    )
    db.session.add(alert)
    db.session.commit()
    return jsonify({'status': 'ok', 'alert_id': alert.id, 'message': 'Test alert created'})


@api_bp.route('/generate-alerts-from-events', methods=['POST'])
def generate_alerts_from_events():
    """Convert existing events (severity >= 2) into alerts."""
    # Get events that don't have alerts yet
    events = Event.query.filter(Event.severity >= 2).all()
    created = 0

    for event in events:
        # Check if alert already exists for this event type and source
        existing = Alert.query.filter(
            Alert.rule_name == event.event_type,
            Alert.source_ip == event.src_ip
        ).first()

        if existing:
            # Update existing alert
            existing.event_count += 1
            existing.last_seen = event.timestamp
        else:
            # Create new alert
            severity_map = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info'}
            alert = Alert(
                title=f"{event.event_type.replace('_', ' ').title()} Detected",
                description=str(event.details) if event.details else '',
                severity=severity_map.get(event.severity, 'medium'),
                status='new',
                source_ip=event.src_ip,
                dest_ip=event.dst_ip,
                rule_name=event.event_type,
                event_count=1,
                first_seen=event.timestamp,
                last_seen=event.timestamp
            )
            db.session.add(alert)
            created += 1

    db.session.commit()
    return jsonify({'status': 'ok', 'alerts_created': created, 'events_processed': len(events)})


@api_bp.route('/events/dns')
def get_dns_events():
    """Get DNS-related events (for analysis of suspicious DNS activity)."""
    limit = request.args.get('limit', 100, type=int)
    events = Event.query.filter(
        Event.event_type.like('%dns%')
    ).order_by(Event.timestamp.desc()).limit(limit).all()
    return jsonify([e.to_dict() for e in events])


@api_bp.route('/events/ddos')
def get_ddos_events():
    """Get DDoS-related events."""
    limit = request.args.get('limit', 100, type=int)
    events = Event.query.filter(
        Event.event_type.like('%ddos%')
    ).order_by(Event.timestamp.desc()).limit(limit).all()
    return jsonify([e.to_dict() for e in events])


@api_bp.route('/events/attacks')
def get_attack_events():
    """Get attack-related events (SQL injection, XSS, etc.)."""
    limit = request.args.get('limit', 100, type=int)
    events = Event.query.filter(
        Event.event_type.like('%attack%')
    ).order_by(Event.timestamp.desc()).limit(limit).all()
    return jsonify([e.to_dict() for e in events])


@api_bp.route('/events/scans')
def get_scan_events():
    """Get port scan events."""
    limit = request.args.get('limit', 100, type=int)
    events = Event.query.filter(
        Event.event_type.like('%scan%')
    ).order_by(Event.timestamp.desc()).limit(limit).all()
    return jsonify([e.to_dict() for e in events])
