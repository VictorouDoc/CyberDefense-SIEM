import os

class Config:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    # Database - use WAL mode for better concurrency
    DB_PATH = os.path.join(BASE_DIR, 'data', 'siem.db')
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}?timeout=30"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'connect_args': {'timeout': 30, 'check_same_thread': False},
        'pool_pre_ping': True,
    }

    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'

    # Network interfaces to monitor
    SNIFF_INTERFACE = os.environ.get('SNIFF_INTERFACE', 'eth0')
    SNIFF_FILTER = os.environ.get('SNIFF_FILTER', '')  # BPF filter

    # Log paths (for file-based collection)
    AUTH_LOG_PATH = '/var/log/auth.log'
    SYSLOG_PATH = '/var/log/syslog'

    # Capture settings
    PACKET_BATCH_SIZE = 100  # Store packets in batches
    MAX_PAYLOAD_PREVIEW = 200  # Bytes of payload to store

    # Detection settings
    RULES_DIR = os.path.join(BASE_DIR, 'detection', 'rules')

    # Web interface
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
