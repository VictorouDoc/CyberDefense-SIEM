from datetime import datetime, timedelta
from app import db


class BannedIP(db.Model):
    """Banned IP addresses (fail2ban-like functionality)"""
    __tablename__ = 'banned_ips'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, unique=True, index=True)
    reason = db.Column(db.String(255))
    ban_type = db.Column(db.String(32), default='manual')  # manual, ddos, port_scan, attack
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=True)  # NULL = permanent
    is_active = db.Column(db.Boolean, default=True, index=True)
    packet_count = db.Column(db.Integer, default=0)  # packets blocked since ban
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'ban_type': self.ban_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active,
            'packet_count': self.packet_count
        }

    @property
    def is_expired(self):
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at


class Packet(db.Model):
    """Captured network packets"""
    __tablename__ = 'packets'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45), index=True)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(16), index=True)  # TCP, UDP, ICMP, etc.
    length = db.Column(db.Integer)
    flags = db.Column(db.String(32))  # TCP flags
    payload_preview = db.Column(db.Text)  # First N bytes of payload
    raw_hex = db.Column(db.Text)  # Raw packet in hex (optional)
    analyzed = db.Column(db.Boolean, default=False)
    threat_score = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'length': self.length,
            'flags': self.flags,
            'threat_score': self.threat_score
        }


class Event(db.Model):
    """Parsed high-level events (HTTP requests, DNS queries, etc.)"""
    __tablename__ = 'events'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    event_type = db.Column(db.String(32), index=True)  # http_request, dns_query, ssh_attempt
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    details = db.Column(db.JSON)  # Event-specific data
    severity = db.Column(db.Integer, default=0)  # 0=info, 1=low, 2=medium, 3=high, 4=critical
    log_source = db.Column(db.String(32))  # packet, syslog, auth

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'event_type': self.event_type,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'details': self.details,
            'severity': self.severity,
            'log_source': self.log_source
        }


class WhitelistIP(db.Model):
    """Whitelisted IP addresses that should never be banned"""
    __tablename__ = 'whitelist_ips'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, unique=True, index=True)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(64), default='system')

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by
        }


class AttackChain(db.Model):
    """Kill chain correlation - groups related events/alerts by source IP and time window."""
    __tablename__ = 'attack_chains'

    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(16), default='medium', index=True)
    status = db.Column(db.String(32), default='active', index=True)  # active, resolved
    current_phase = db.Column(db.String(64))  # Latest kill chain phase
    kill_chain_phases = db.Column(db.JSON, default=list)  # List of observed phases
    event_types = db.Column(db.JSON, default=list)  # List of event types seen
    alert_ids = db.Column(db.JSON, default=list)  # Related alert IDs
    event_count = db.Column(db.Integer, default=1)
    first_seen = db.Column(db.DateTime, index=True)
    last_seen = db.Column(db.DateTime, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'source_ip': self.source_ip,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'current_phase': self.current_phase,
            'kill_chain_phases': self.kill_chain_phases or [],
            'event_types': self.event_types or [],
            'alert_ids': self.alert_ids or [],
            'event_count': self.event_count,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
        }


class Alert(db.Model):
    """Security alerts generated by detection rules"""
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(16), default='medium', index=True)  # critical, high, medium, low, info
    status = db.Column(db.String(32), default='new', index=True)  # new, ack, investigating, resolved, false_positive
    source_ip = db.Column(db.String(45))
    dest_ip = db.Column(db.String(45))
    rule_name = db.Column(db.String(128))
    event_count = db.Column(db.Integer, default=1)
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    packet_ids = db.Column(db.JSON)  # List of related packet IDs

    def to_dict(self):
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'rule_name': self.rule_name,
            'event_count': self.event_count
        }
