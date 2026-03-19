from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
import os

db = SQLAlchemy()


def _set_sqlite_pragma(dbapi_conn, connection_record):
    """Enable WAL mode for better concurrent access."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()


def create_app():
    app = Flask(__name__)

    # Load config
    app.config.from_object('config.Config')

    # Ensure data directory exists
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    os.makedirs(data_dir, exist_ok=True)

    # Initialize extensions
    db.init_app(app)

    # Enable WAL mode for SQLite
    with app.app_context():
        event.listen(db.engine, "connect", _set_sqlite_pragma)

    # Register blueprints
    from app.routes.dashboard import dashboard_bp
    from app.routes.packets import packets_bp
    from app.routes.events import events_bp
    from app.routes.alerts import alerts_bp
    from app.routes.api import api_bp
    from app.routes.firewall import firewall_bp
    from app.routes.killchain import killchain_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(packets_bp, url_prefix='/packets')
    app.register_blueprint(events_bp, url_prefix='/events')
    app.register_blueprint(alerts_bp, url_prefix='/alerts')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(firewall_bp, url_prefix='/firewall')
    app.register_blueprint(killchain_bp, url_prefix='/killchain')

    # Create tables
    with app.app_context():
        db.create_all()

    return app
