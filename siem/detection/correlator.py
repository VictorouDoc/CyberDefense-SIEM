"""
Kill Chain Correlation Engine
Groups related security events by source IP into attack chains,
mapping each event to a MITRE ATT&CK-inspired kill chain phase.
"""
from datetime import datetime, timedelta

# Event type -> Kill Chain phase mapping
PHASE_MAP = {
    # 1. Reconnaissance
    'port_scan': 'reconnaissance',
    'suspicious_dns': 'reconnaissance',
    'fuzzing': 'reconnaissance',

    # 2. Initial Access
    'ssh_bruteforce': 'initial_access',
    'attack_ssti': 'initial_access',
    'attack_sqli': 'initial_access',
    'attack_xss': 'initial_access',
    'attack_path_traversal': 'initial_access',
    'attack_command_injection': 'initial_access',

    # 3. Execution
    'vuln_exploit': 'execution',
    'http_exploit': 'execution',

    # 4. Lateral Movement
    'lateral_movement': 'lateral_movement',

    # 5. Command & Control
    'c2_beaconing': 'command_control',

    # 6. Exfiltration
    'dns_exfiltration': 'exfiltration',
    'http_exfiltration': 'exfiltration',

    # 7. Impact
    'ddos_packet_flood': 'impact',
    'ddos_syn_flood': 'impact',
}

# Kill chain phase order (for progression tracking)
PHASE_ORDER = [
    'reconnaissance',
    'initial_access',
    'execution',
    'lateral_movement',
    'command_control',
    'exfiltration',
    'impact',
]

PHASE_LABELS = {
    'reconnaissance': 'Reconnaissance',
    'initial_access': 'Initial Access',
    'execution': 'Execution',
    'lateral_movement': 'Lateral Movement',
    'command_control': 'Command & Control',
    'exfiltration': 'Exfiltration',
    'impact': 'Impact',
}

# Correlation time window (seconds)
CORRELATION_WINDOW = 1800  # 30 minutes


def get_phase(event_type):
    """Map an event type to its kill chain phase."""
    return PHASE_MAP.get(event_type)


def compute_chain_severity(phases):
    """Compute severity based on number and type of kill chain phases observed."""
    if not phases:
        return 'low'

    num_phases = len(phases)
    has_execution = 'execution' in phases
    has_exfil = 'exfiltration' in phases
    has_lateral = 'lateral_movement' in phases

    # 4+ phases or execution+exfil = critical
    if num_phases >= 4 or (has_execution and has_exfil):
        return 'critical'
    # 3 phases or execution+lateral = high
    if num_phases >= 3 or (has_execution and has_lateral):
        return 'high'
    # 2 phases = medium
    if num_phases >= 2:
        return 'medium'
    return 'low'


def build_chain_title(phases, source_ip):
    """Build a descriptive title from observed phases."""
    phase_names = [PHASE_LABELS.get(p, p) for p in PHASE_ORDER if p in phases]
    if len(phase_names) >= 3:
        return f"Kill Chain: {phase_names[0]} → ... → {phase_names[-1]} from {source_ip}"
    elif len(phase_names) == 2:
        return f"Attack Chain: {' → '.join(phase_names)} from {source_ip}"
    else:
        return f"Attack Activity: {phase_names[0]} from {source_ip}"


def build_chain_description(event_types, phases, event_count):
    """Build a description summarizing the attack chain."""
    phase_names = [PHASE_LABELS.get(p, p) for p in PHASE_ORDER if p in phases]
    lines = [
        f"Attack chain with {event_count} events across {len(phases)} kill chain phases.",
        f"Phases: {' → '.join(phase_names)}",
        f"Event types: {', '.join(sorted(set(event_types)))}"
    ]
    return '\n'.join(lines)


def correlate_event(db, AttackChain, event_data, alert_id=None):
    """
    Correlate an event into an attack chain.
    Returns the AttackChain object (new or updated).
    """
    src_ip = event_data.get('src_ip')
    event_type = event_data.get('event_type')
    timestamp = event_data.get('timestamp', datetime.utcnow())

    if not src_ip or not event_type:
        return None

    phase = get_phase(event_type)
    if not phase:
        return None

    # Look for existing active chain for this source IP within time window
    cutoff = timestamp - timedelta(seconds=CORRELATION_WINDOW)
    chain = AttackChain.query.filter(
        AttackChain.source_ip == src_ip,
        AttackChain.status == 'active',
        AttackChain.last_seen >= cutoff
    ).first()

    if chain:
        # Update existing chain
        current_types = chain.event_types or []
        current_phases = chain.kill_chain_phases or []
        current_alerts = chain.alert_ids or []

        if event_type not in current_types:
            current_types.append(event_type)
        if phase not in current_phases:
            current_phases.append(phase)
        if alert_id and alert_id not in current_alerts:
            current_alerts.append(alert_id)

        chain.event_types = current_types
        chain.kill_chain_phases = current_phases
        chain.alert_ids = current_alerts
        chain.event_count += 1
        chain.last_seen = timestamp
        chain.current_phase = phase
        chain.severity = compute_chain_severity(current_phases)
        chain.title = build_chain_title(current_phases, src_ip)
        chain.description = build_chain_description(current_types, current_phases, chain.event_count)
    else:
        # Create new chain
        chain = AttackChain(
            source_ip=src_ip,
            title=build_chain_title([phase], src_ip),
            description=build_chain_description([event_type], [phase], 1),
            severity=compute_chain_severity([phase]),
            status='active',
            current_phase=phase,
            kill_chain_phases=[phase],
            event_types=[event_type],
            alert_ids=[alert_id] if alert_id else [],
            event_count=1,
            first_seen=timestamp,
            last_seen=timestamp,
        )
        db.session.add(chain)

    return chain
