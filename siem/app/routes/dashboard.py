from flask import Blueprint, render_template
from sqlalchemy import func
from datetime import datetime, timedelta
from app import db
from app.models import Packet, Event, Alert, BannedIP

dashboard_bp = Blueprint('dashboard', __name__, template_folder='../templates')


@dashboard_bp.route('/')
def index():
    """Main dashboard view."""
    now = datetime.utcnow()
    last_hour = now - timedelta(hours=1)
    last_24h = now - timedelta(hours=24)

    # Get statistics
    stats = {
        'packets_1h': Packet.query.filter(Packet.timestamp >= last_hour).count(),
        'packets_24h': Packet.query.filter(Packet.timestamp >= last_24h).count(),
        'events_24h': Event.query.filter(Event.timestamp >= last_24h).count(),
        'alerts_open': Alert.query.filter(Alert.status.in_(['new', 'ack', 'investigating'])).count(),
        'alerts_critical': Alert.query.filter(
            Alert.severity == 'critical',
            Alert.status.in_(['new', 'ack'])
        ).count(),
        'banned_ips': BannedIP.query.filter(BannedIP.is_active == True).count(),
    }

    # Get recent alerts
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(10).all()

    # Get top source IPs (potential attackers)
    top_sources_query = db.session.query(
        Packet.src_ip,
        func.count(Packet.id).label('count')
    ).filter(
        Packet.timestamp >= last_hour
    ).group_by(Packet.src_ip).order_by(func.count(Packet.id).desc()).limit(10).all()
    top_sources = [[row[0], row[1]] for row in top_sources_query]

    # Get protocol distribution
    protocols_query = db.session.query(
        Packet.protocol,
        func.count(Packet.id).label('count')
    ).filter(
        Packet.timestamp >= last_hour
    ).group_by(Packet.protocol).all()
    protocols = [[row[0], row[1]] for row in protocols_query]

    return render_template('dashboard.html',
                           stats=stats,
                           recent_alerts=recent_alerts,
                           top_sources=top_sources,
                           protocols=protocols)


@dashboard_bp.route('/status')
def status():
    """Health check endpoint."""
    return {'status': 'ok', 'timestamp': datetime.utcnow().isoformat()}
