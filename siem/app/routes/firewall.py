"""
Firewall routes for IP ban management (fail2ban-like functionality).
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from datetime import datetime, timedelta
from app import db
from app.models import BannedIP, Alert, WhitelistIP
import subprocess
import re

firewall_bp = Blueprint('firewall', __name__)

# Regex for IP validation
IP_REGEX = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

# Default whitelisted IPs (always protected)
DEFAULT_WHITELIST_IPS = {
    '127.0.0.1',          # Localhost
    '10.0.0.1',         # Internal gateway
    '10.0.0.15',        # Bastion itself
    '192.168.1.1',        # Internal network
    '192.168.1.100',      # Bastion eth1
}


def validate_ip(ip):
    """Validate IP address format."""
    if not ip or not IP_REGEX.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def is_whitelisted(ip):
    """Check if IP is whitelisted (default or database)."""
    if ip in DEFAULT_WHITELIST_IPS:
        return True
    return WhitelistIP.query.filter_by(ip_address=ip).first() is not None


def get_all_whitelisted_ips():
    """Get all whitelisted IPs (default + database)."""
    db_whitelist = {w.ip_address for w in WhitelistIP.query.all()}
    return DEFAULT_WHITELIST_IPS | db_whitelist


def apply_firewall_ban(ip_address, action='ban', duration_seconds=None):
    """
    Apply or remove firewall rule for IP using nftables sets.
    Falls back to iptables if nft is not available.
    action: 'ban' or 'unban'
    duration_seconds: optional ban timeout (nftables only)
    """
    try:
        # Try nftables first (preferred)
        if action == 'ban':
            if duration_seconds:
                element = f"{{ {ip_address} timeout {duration_seconds}s }}"
            else:
                element = f"{{ {ip_address} }}"
            cmd = ['nft', 'add', 'element', 'inet', 'filter', 'banned', element]
        else:
            cmd = ['nft', 'delete', 'element', 'inet', 'filter', 'banned', f'{{ {ip_address} }}']

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, None

        # If nft failed (set doesn't exist yet, etc.), fall back to iptables
        if action == 'ban':
            cmd = ['iptables', '-I', 'INPUT', '-s', ip_address, '-j', 'DROP']
        else:
            cmd = ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.returncode == 0, result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, "Neither nft nor iptables found"
    except Exception as e:
        return False, str(e)


@firewall_bp.route('/')
def index():
    """Display firewall/ban management page."""
    # Get filter parameters
    status_filter = request.args.get('status', 'active')

    # Build query
    query = BannedIP.query

    if status_filter == 'active':
        query = query.filter(BannedIP.is_active == True)
    elif status_filter == 'expired':
        query = query.filter(
            (BannedIP.is_active == False) |
            (BannedIP.expires_at < datetime.utcnow())
        )

    banned_ips = query.order_by(BannedIP.created_at.desc()).all()

    # Get whitelist (database entries)
    whitelist_ips = WhitelistIP.query.order_by(WhitelistIP.created_at.desc()).all()

    # Get stats
    stats = {
        'total_banned': BannedIP.query.filter(BannedIP.is_active == True).count(),
        'auto_banned': BannedIP.query.filter(
            BannedIP.is_active == True,
            BannedIP.ban_type != 'manual'
        ).count(),
        'manual_banned': BannedIP.query.filter(
            BannedIP.is_active == True,
            BannedIP.ban_type == 'manual'
        ).count(),
        'total_blocked': db.session.query(db.func.sum(BannedIP.packet_count)).scalar() or 0,
        'whitelisted': len(DEFAULT_WHITELIST_IPS) + len(whitelist_ips)
    }

    return render_template('firewall.html',
                           banned_ips=banned_ips,
                           whitelist_ips=whitelist_ips,
                           default_whitelist=sorted(DEFAULT_WHITELIST_IPS),
                           status_filter=status_filter,
                           stats=stats)


@firewall_bp.route('/ban', methods=['POST'])
def ban_ip():
    """Manually ban an IP address."""
    ip_address = request.form.get('ip_address', '').strip()
    reason = request.form.get('reason', 'Manual ban')
    duration = request.form.get('duration', 'permanent')

    # Validate IP
    if not validate_ip(ip_address):
        flash(f'Invalid IP address: {ip_address}', 'danger')
        return redirect(url_for('firewall.index'))

    # Check whitelist
    if is_whitelisted(ip_address):
        flash(f'IP {ip_address} is whitelisted and cannot be banned', 'warning')
        return redirect(url_for('firewall.index'))

    # Check if already banned
    existing = BannedIP.query.filter_by(ip_address=ip_address, is_active=True).first()
    if existing:
        flash(f'IP {ip_address} is already banned', 'warning')
        return redirect(url_for('firewall.index'))

    # Calculate expiry
    expires_at = None
    if duration != 'permanent':
        duration_map = {
            '1h': timedelta(hours=1),
            '6h': timedelta(hours=6),
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7),
            '30d': timedelta(days=30)
        }
        if duration in duration_map:
            expires_at = datetime.utcnow() + duration_map[duration]

    # Create ban record
    ban = BannedIP(
        ip_address=ip_address,
        reason=reason,
        ban_type='manual',
        expires_at=expires_at,
        is_active=True
    )
    db.session.add(ban)

    # Apply firewall rule (with timeout for non-permanent bans)
    duration_secs_map = {
        '1h': 3600, '6h': 21600, '24h': 86400,
        '7d': 604800, '30d': 2592000
    }
    ban_timeout = duration_secs_map.get(duration)
    success, error = apply_firewall_ban(ip_address, 'ban', duration_seconds=ban_timeout)
    if not success:
        flash(f'IP banned in database but firewall rule failed: {error}', 'warning')
    else:
        flash(f'IP {ip_address} has been banned', 'success')

    # Create alert for manual ban
    alert = Alert(
        title=f'Manual IP Ban: {ip_address}',
        description=f'IP {ip_address} was manually banned. Reason: {reason}',
        severity='high',
        status='new',
        source_ip=ip_address,
        rule_name='manual_ban',
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow()
    )
    db.session.add(alert)
    ban.alert_id = alert.id

    db.session.commit()

    return redirect(url_for('firewall.index'))


@firewall_bp.route('/unban/<int:ban_id>', methods=['POST'])
def unban_ip(ban_id):
    """Remove IP ban."""
    ban = BannedIP.query.get_or_404(ban_id)

    # Remove firewall rule
    success, error = apply_firewall_ban(ban.ip_address, 'unban')

    # Deactivate ban
    ban.is_active = False
    db.session.commit()

    if not success:
        flash(f'Ban removed from database but firewall rule failed: {error}', 'warning')
    else:
        flash(f'IP {ban.ip_address} has been unbanned', 'success')

    return redirect(url_for('firewall.index'))


@firewall_bp.route('/api/ban', methods=['POST'])
def api_ban_ip():
    """API endpoint to ban IP (used by auto-ban system)."""
    data = request.get_json() or {}
    ip_address = data.get('ip_address')
    reason = data.get('reason', 'Auto-ban')
    ban_type = data.get('ban_type', 'auto')
    duration_seconds = data.get('duration', 3600)  # Default 1 hour

    if not validate_ip(ip_address):
        return jsonify({'error': 'Invalid IP address'}), 400

    # Check if already banned
    existing = BannedIP.query.filter_by(ip_address=ip_address, is_active=True).first()
    if existing:
        existing.packet_count += 1
        db.session.commit()
        return jsonify({'status': 'already_banned', 'id': existing.id})

    # Calculate expiry
    expires_at = datetime.utcnow() + timedelta(seconds=duration_seconds) if duration_seconds else None

    # Create ban
    ban = BannedIP(
        ip_address=ip_address,
        reason=reason,
        ban_type=ban_type,
        expires_at=expires_at,
        is_active=True
    )
    db.session.add(ban)

    # Apply firewall rule (with timeout if duration is set)
    success, error = apply_firewall_ban(ip_address, 'ban', duration_seconds=duration_seconds)

    db.session.commit()

    return jsonify({
        'status': 'banned',
        'id': ban.id,
        'ip_address': ip_address,
        'firewall_applied': success,
        'firewall_error': error if not success else None
    })


@firewall_bp.route('/api/unban/<ip_address>', methods=['POST'])
def api_unban_ip(ip_address):
    """API endpoint to unban IP."""
    ban = BannedIP.query.filter_by(ip_address=ip_address, is_active=True).first()

    if not ban:
        return jsonify({'error': 'IP not found in ban list'}), 404

    success, error = apply_firewall_ban(ip_address, 'unban')
    ban.is_active = False
    db.session.commit()

    return jsonify({
        'status': 'unbanned',
        'ip_address': ip_address,
        'firewall_removed': success
    })


@firewall_bp.route('/api/banned')
def api_list_banned():
    """API endpoint to list all banned IPs."""
    active_only = request.args.get('active', 'true').lower() == 'true'

    query = BannedIP.query
    if active_only:
        query = query.filter(BannedIP.is_active == True)

    bans = query.order_by(BannedIP.created_at.desc()).all()

    return jsonify([b.to_dict() for b in bans])


@firewall_bp.route('/api/check/<ip_address>')
def api_check_ip(ip_address):
    """Check if IP is banned."""
    ban = BannedIP.query.filter_by(ip_address=ip_address, is_active=True).first()

    return jsonify({
        'ip_address': ip_address,
        'is_banned': ban is not None,
        'ban_info': ban.to_dict() if ban else None
    })


def auto_ban_ip(ip_address, ban_type, reason, duration_seconds=3600):
    """
    Auto-ban function called by the analyzer.
    This is called from the packet processing thread.
    """
    from flask import current_app

    # NEVER ban whitelisted IPs
    if is_whitelisted(ip_address):
        print(f"[FIREWALL] Skipping ban for whitelisted IP: {ip_address}")
        return None

    # Check if already banned
    existing = BannedIP.query.filter_by(ip_address=ip_address, is_active=True).first()
    if existing:
        existing.packet_count += 1
        db.session.commit()
        return existing

    # Calculate expiry
    expires_at = datetime.utcnow() + timedelta(seconds=duration_seconds) if duration_seconds else None

    # Create ban
    ban = BannedIP(
        ip_address=ip_address,
        reason=reason,
        ban_type=ban_type,
        expires_at=expires_at,
        is_active=True
    )
    db.session.add(ban)

    # Create alert
    alert = Alert(
        title=f'Auto-Ban: {ban_type.upper()} from {ip_address}',
        description=reason,
        severity='critical',
        status='new',
        source_ip=ip_address,
        rule_name=f'auto_ban_{ban_type}',
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow()
    )
    db.session.add(alert)

    db.session.commit()

    # Apply firewall ban (with timeout for auto-bans)
    apply_firewall_ban(ip_address, 'ban', duration_seconds=duration_seconds)

    print(f"[FIREWALL] Auto-banned {ip_address} ({duration_seconds}s): {reason}")

    return ban


# ==================== WHITELIST MANAGEMENT ====================

@firewall_bp.route('/whitelist/add', methods=['POST'])
def add_whitelist():
    """Add an IP to the whitelist."""
    ip_address = request.form.get('ip_address', '').strip()
    description = request.form.get('description', '').strip()

    # Validate IP
    if not validate_ip(ip_address):
        flash(f'Invalid IP address: {ip_address}', 'danger')
        return redirect(url_for('firewall.index'))

    # Check if already whitelisted
    if ip_address in DEFAULT_WHITELIST_IPS:
        flash(f'IP {ip_address} is already in the default whitelist', 'warning')
        return redirect(url_for('firewall.index'))

    existing = WhitelistIP.query.filter_by(ip_address=ip_address).first()
    if existing:
        flash(f'IP {ip_address} is already whitelisted', 'warning')
        return redirect(url_for('firewall.index'))

    # Add to whitelist
    whitelist_entry = WhitelistIP(
        ip_address=ip_address,
        description=description or 'Manual whitelist',
        created_by='admin'
    )
    db.session.add(whitelist_entry)

    # If IP is currently banned, unban it
    banned = BannedIP.query.filter_by(ip_address=ip_address, is_active=True).first()
    if banned:
        banned.is_active = False
        apply_firewall_ban(ip_address, 'unban')
        flash(f'IP {ip_address} was unbanned and added to whitelist', 'success')
    else:
        flash(f'IP {ip_address} added to whitelist', 'success')

    db.session.commit()

    return redirect(url_for('firewall.index'))


@firewall_bp.route('/whitelist/remove/<int:whitelist_id>', methods=['POST'])
def remove_whitelist(whitelist_id):
    """Remove an IP from the whitelist."""
    entry = WhitelistIP.query.get_or_404(whitelist_id)
    ip_address = entry.ip_address

    db.session.delete(entry)
    db.session.commit()

    flash(f'IP {ip_address} removed from whitelist', 'success')

    return redirect(url_for('firewall.index'))


@firewall_bp.route('/api/whitelist', methods=['GET'])
def api_list_whitelist():
    """API endpoint to list all whitelisted IPs."""
    whitelist = WhitelistIP.query.order_by(WhitelistIP.created_at.desc()).all()

    return jsonify({
        'default': list(DEFAULT_WHITELIST_IPS),
        'custom': [w.to_dict() for w in whitelist]
    })


@firewall_bp.route('/api/whitelist/add', methods=['POST'])
def api_add_whitelist():
    """API endpoint to add IP to whitelist."""
    data = request.get_json() or {}
    ip_address = data.get('ip_address')
    description = data.get('description', 'API whitelist')

    if not validate_ip(ip_address):
        return jsonify({'error': 'Invalid IP address'}), 400

    if ip_address in DEFAULT_WHITELIST_IPS:
        return jsonify({'status': 'already_default', 'ip_address': ip_address})

    existing = WhitelistIP.query.filter_by(ip_address=ip_address).first()
    if existing:
        return jsonify({'status': 'already_whitelisted', 'id': existing.id})

    entry = WhitelistIP(
        ip_address=ip_address,
        description=description,
        created_by='api'
    )
    db.session.add(entry)
    db.session.commit()

    return jsonify({
        'status': 'whitelisted',
        'id': entry.id,
        'ip_address': ip_address
    })


@firewall_bp.route('/api/whitelist/remove/<ip_address>', methods=['POST'])
def api_remove_whitelist(ip_address):
    """API endpoint to remove IP from whitelist."""
    if ip_address in DEFAULT_WHITELIST_IPS:
        return jsonify({'error': 'Cannot remove default whitelist entries'}), 400

    entry = WhitelistIP.query.filter_by(ip_address=ip_address).first()
    if not entry:
        return jsonify({'error': 'IP not found in whitelist'}), 404

    db.session.delete(entry)
    db.session.commit()

    return jsonify({
        'status': 'removed',
        'ip_address': ip_address
    })
