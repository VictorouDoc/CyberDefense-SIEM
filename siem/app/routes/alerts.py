from flask import Blueprint, render_template, request, redirect, url_for, flash
from datetime import datetime
from app import db
from app.models import Alert

alerts_bp = Blueprint('alerts', __name__, template_folder='../templates')


@alerts_bp.route('/')
def list_alerts():
    """View all alerts."""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'open')
    severity_filter = request.args.get('severity')

    query = Alert.query

    if status_filter == 'open':
        query = query.filter(Alert.status.in_(['new', 'ack', 'investigating']))
    elif status_filter != 'all':
        query = query.filter(Alert.status == status_filter)

    if severity_filter:
        query = query.filter(Alert.severity == severity_filter)

    alerts = query.order_by(Alert.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )

    return render_template('alerts.html', alerts=alerts, status_filter=status_filter)


@alerts_bp.route('/<int:alert_id>')
def alert_detail(alert_id):
    """View single alert details."""
    alert = Alert.query.get_or_404(alert_id)
    return render_template('alert_detail.html', alert=alert)


@alerts_bp.route('/<int:alert_id>/update', methods=['POST'])
def update_alert(alert_id):
    """Update alert status."""
    alert = Alert.query.get_or_404(alert_id)

    new_status = request.form.get('status')
    if new_status in ['new', 'ack', 'investigating', 'resolved', 'false_positive']:
        alert.status = new_status
        db.session.commit()

    return redirect(url_for('alerts.alert_detail', alert_id=alert_id))
