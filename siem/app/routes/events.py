from flask import Blueprint, render_template, request
from app import db
from app.models import Event

events_bp = Blueprint('events', __name__, template_folder='../templates')


@events_bp.route('/')
def list_events():
    """View all detected events."""
    page = request.args.get('page', 1, type=int)
    event_type = request.args.get('type')
    severity = request.args.get('severity', type=int)

    query = Event.query

    if event_type:
        query = query.filter(Event.event_type == event_type)
    if severity is not None:
        query = query.filter(Event.severity >= severity)

    events = query.order_by(Event.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )

    # Get unique event types for filter dropdown
    event_types = db.session.query(Event.event_type).distinct().all()
    event_types = [e[0] for e in event_types]

    return render_template('events.html', events=events, event_types=event_types)
