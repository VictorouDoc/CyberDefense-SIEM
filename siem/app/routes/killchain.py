from flask import Blueprint, render_template, request, jsonify
from datetime import datetime, timedelta
from app import db
from app.models import AttackChain

killchain_bp = Blueprint('killchain', __name__, template_folder='../templates')


@killchain_bp.route('/')
def list_chains():
    """View all attack chains."""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'active')

    query = AttackChain.query

    if status_filter != 'all':
        query = query.filter(AttackChain.status == status_filter)

    chains = query.order_by(AttackChain.last_seen.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template('killchain.html', chains=chains, status_filter=status_filter)


@killchain_bp.route('/<int:chain_id>')
def chain_detail(chain_id):
    """View single attack chain details."""
    chain = AttackChain.query.get_or_404(chain_id)
    return render_template('killchain_detail.html', chain=chain)


@killchain_bp.route('/<int:chain_id>/resolve', methods=['POST'])
def resolve_chain(chain_id):
    """Mark an attack chain as resolved."""
    chain = AttackChain.query.get_or_404(chain_id)
    chain.status = 'resolved'
    db.session.commit()
    return jsonify({'status': 'ok'})
