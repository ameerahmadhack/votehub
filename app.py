from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import secrets
import string
import os
import csv
import io
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///votehub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads/candidates'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

db = SQLAlchemy(app)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(20), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('admin.id'))

class Election(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    manual_control = db.Column(db.Boolean, default=False)
    manually_started = db.Column(db.Boolean, default=False)
    manually_stopped = db.Column(db.Boolean, default=False)
    allow_results_view = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('admin.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    party_name = db.Column(db.String(100))
    image_path = db.Column(db.String(500))
    description = db.Column(db.Text)
    manifesto = db.Column(db.Text)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    votes_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('voter.id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    voted_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    user_type = db.Column(db.String(20))
    user_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), default='info')
    created_by = db.Column(db.Integer, db.ForeignKey('admin.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_voter_id():
    while True:
        voter_id = 'VH-' + ''.join(secrets.choice(string.digits) for _ in range(6))
        if not Voter.query.filter_by(voter_id=voter_id).first():
            return voter_id

def log_action(action, user_type, user_id, details=''):
    log = AuditLog(
        action=action,
        user_type=user_type,
        user_id=user_id,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please login as admin to access this page', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def voter_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'voter_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('voter_login'))
        return f(*args, **kwargs)
    return decorated_function

def is_election_active(election):
    now = datetime.utcnow()
    if election.manually_stopped:
        return False
    if election.manual_control and election.manually_started:
        return now <= election.end_time
    return election.start_time <= now <= election.end_time

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            log_action('Admin Login', 'admin', admin.id, f'Admin {username} logged in')
            flash('Welcome back, Admin!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    total_voters = Voter.query.count()
    total_elections = Election.query.count()
    total_votes = Vote.query.count()
    active_elections = sum(1 for e in Election.query.all() if is_election_active(e))
    
    recent_elections = Election.query.order_by(Election.created_at.desc()).limit(5).all()
    recent_voters = Voter.query.order_by(Voter.created_at.desc()).limit(5).all()
    
    return render_template('admin_dashboard.html',
                         total_voters=total_voters,
                         total_elections=total_elections,
                         total_votes=total_votes,
                         active_elections=active_elections,
                         recent_elections=recent_elections,
                         recent_voters=recent_voters)

@app.route('/admin/voters')
@admin_required
def admin_voters():
    voters = Voter.query.order_by(Voter.created_at.desc()).all()
    return render_template('admin_voters.html', voters=voters)

@app.route('/admin/voters/create', methods=['GET', 'POST'])
@admin_required
def admin_create_voter():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        
        voter_id = generate_voter_id()
        default_password = secrets.token_urlsafe(8)
        
        voter = Voter(
            voter_id=voter_id,
            full_name=full_name,
            email=email,
            phone=phone,
            password_hash=generate_password_hash(default_password),
            created_by=session['admin_id']
        )
        
        db.session.add(voter)
        db.session.commit()
        
        log_action('Create Voter', 'admin', session['admin_id'], 
                  f'Created voter: {voter_id} - {full_name}')
        
        flash(f'Voter created successfully! Voter ID: {voter_id}, Password: {default_password}', 'success')
        return redirect(url_for('admin_voters'))
    
    return render_template('admin_create_voter.html')

@app.route('/admin/voters/bulk-create', methods=['GET', 'POST'])
@admin_required
def admin_bulk_create_voters():
    if request.method == 'POST':
        count = int(request.form.get('count', 1))
        voters_created = []
        
        for i in range(count):
            voter_id = generate_voter_id()
            default_password = secrets.token_urlsafe(8)
            
            voter = Voter(
                voter_id=voter_id,
                full_name=f'Voter {i+1}',
                password_hash=generate_password_hash(default_password),
                created_by=session['admin_id']
            )
            
            db.session.add(voter)
            voters_created.append({
                'voter_id': voter_id,
                'password': default_password
            })
        
        db.session.commit()
        log_action('Bulk Create Voters', 'admin', session['admin_id'], 
                  f'Created {count} voters')
        
        return render_template('admin_bulk_voters_result.html', voters=voters_created)
    
    return render_template('admin_bulk_create_voters.html')

@app.route('/admin/elections')
@admin_required
def admin_elections():
    elections = Election.query.order_by(Election.created_at.desc()).all()
    return render_template('admin_elections.html', elections=elections)

@app.route('/admin/elections/create', methods=['GET', 'POST'])
@admin_required
def admin_create_election():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        start_time = datetime.strptime(request.form.get('start_time'), '%Y-%m-%dT%H:%M')
        end_time = datetime.strptime(request.form.get('end_time'), '%Y-%m-%dT%H:%M')
        
        election = Election(
            title=title,
            description=description,
            start_time=start_time,
            end_time=end_time,
            created_by=session['admin_id']
        )
        
        db.session.add(election)
        db.session.commit()
        
        log_action('Create Election', 'admin', session['admin_id'], 
                  f'Created election: {title}')
        
        flash('Election created successfully!', 'success')
        return redirect(url_for('admin_add_candidates', election_id=election.id))
    
    return render_template('admin_create_election.html')

@app.route('/admin/elections/<int:election_id>/candidates', methods=['GET', 'POST'])
def admin_add_candidates(election_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    election = Election.query.get_or_404(election_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        party_name = request.form.get('party_name')
        description = request.form.get('description')
        manifesto = request.form.get('manifesto')
        
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image_path = f"uploads/candidates/{filename}"
        
        if name:
            candidate = Candidate(
                name=name,
                party_name=party_name,
                description=description,
                manifesto=manifesto,
                image_path=image_path,
                election_id=election_id
            )
            db.session.add(candidate)
            db.session.commit()
            flash('Candidate added successfully!', 'success')
        else:
            flash('Candidate name is required!', 'error')
        
        return redirect(url_for('admin_add_candidates', election_id=election_id))
    
    candidates = Candidate.query.filter_by(election_id=election_id).all()
    return render_template('admin_add_candidates.html', election=election, candidates=candidates)

@app.route('/admin/elections/<int:election_id>/results')
@admin_required
def admin_election_results(election_id):
    election = Election.query.get_or_404(election_id)
    candidates = Candidate.query.filter_by(election_id=election_id).order_by(Candidate.votes_count.desc()).all()
    total_votes = sum(c.votes_count for c in candidates)
    
    votes = Vote.query.filter_by(election_id=election_id).all()
    
    all_voters = Voter.query.filter_by(is_active=True).all()
    voted_voter_ids = [v.voter_id for v in votes]
    voters_who_voted = Voter.query.filter(Voter.id.in_([v.voter_id for v in votes])).all()
    voters_who_didnt_vote = [v for v in all_voters if v.id not in [vote.voter_id for vote in votes]]
    
    return render_template('admin_election_results.html', 
                         election=election, 
                         candidates=candidates,
                         total_votes=total_votes,
                         votes=votes,
                         voters_who_voted=voters_who_voted,
                         voters_who_didnt_vote=voters_who_didnt_vote,
                         total_voters=len(all_voters))

@app.route('/admin/audit-logs')
@admin_required
def admin_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('admin_audit_logs.html', logs=logs)

@app.route('/admin/logout')
def admin_logout():
    log_action('Admin Logout', 'admin', session.get('admin_id'), 
              f'Admin {session.get("admin_username")} logged out')
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin/elections/<int:election_id>/start', methods=['POST'])
@admin_required
def admin_start_election(election_id):
    election = Election.query.get_or_404(election_id)
    election.manual_control = True
    election.manually_started = True
    election.manually_stopped = False
    db.session.commit()
    
    log_action('Start Election', 'admin', session['admin_id'], 
              f'Manually started election: {election.title}')
    flash(f'Election "{election.title}" has been started!', 'success')
    return redirect(url_for('admin_elections'))

@app.route('/admin/elections/<int:election_id>/stop', methods=['POST'])
@admin_required
def admin_stop_election(election_id):
    election = Election.query.get_or_404(election_id)
    election.manually_stopped = True
    db.session.commit()
    
    log_action('Stop Election', 'admin', session['admin_id'], 
              f'Manually stopped election: {election.title}')
    flash(f'Election "{election.title}" has been stopped!', 'success')
    return redirect(url_for('admin_elections'))

@app.route('/admin/elections/<int:election_id>/export-csv')
@admin_required
def admin_export_results_csv(election_id):
    election = Election.query.get_or_404(election_id)
    candidates = Candidate.query.filter_by(election_id=election_id).order_by(Candidate.votes_count.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['Election', election.title])
    writer.writerow(['Description', election.description])
    writer.writerow(['Start Time', election.start_time.strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow(['End Time', election.end_time.strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])
    writer.writerow(['Rank', 'Candidate Name', 'Party', 'Votes', 'Percentage'])
    
    total_votes = sum(c.votes_count for c in candidates)
    for idx, candidate in enumerate(candidates, 1):
        percentage = (candidate.votes_count / total_votes * 100) if total_votes > 0 else 0
        writer.writerow([idx, candidate.name, candidate.party_name or 'Independent', 
                        candidate.votes_count, f'{percentage:.2f}%'])
    
    writer.writerow([])
    writer.writerow(['Total Votes', total_votes])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'election_results_{election.id}_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route('/admin/notifications', methods=['GET', 'POST'])
@admin_required
def admin_notifications():
    if request.method == 'POST':
        title = request.form.get('title')
        message = request.form.get('message')
        notification_type = request.form.get('notification_type', 'info')
        
        notification = Notification(
            title=title,
            message=message,
            notification_type=notification_type,
            created_by=session['admin_id']
        )
        db.session.add(notification)
        db.session.commit()
        
        log_action('Create Notification', 'admin', session['admin_id'], 
                  f'Created notification: {title}')
        flash('Notification sent to all voters!', 'success')
        return redirect(url_for('admin_notifications'))
    
    notifications = Notification.query.order_by(Notification.created_at.desc()).all()
    return render_template('admin_notifications.html', notifications=notifications)

@app.route('/admin/notifications/<int:notification_id>/delete', methods=['POST'])
@admin_required
def admin_delete_notification(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    db.session.delete(notification)
    db.session.commit()
    
    log_action('Delete Notification', 'admin', session['admin_id'], 
              f'Deleted notification: {notification.title}')
    flash('Notification deleted!', 'success')
    return redirect(url_for('admin_notifications'))

@app.route('/voter/login', methods=['GET', 'POST'])
def voter_login():
    if request.method == 'POST':
        voter_id = request.form.get('voter_id')
        password = request.form.get('password')
        
        voter = Voter.query.filter_by(voter_id=voter_id).first()
        if voter and check_password_hash(voter.password_hash, password):
            if not voter.is_active:
                flash('Your account has been deactivated. Please contact admin.', 'error')
                return redirect(url_for('voter_login'))
            
            session['voter_id'] = voter.id
            session['voter_name'] = voter.full_name
            session['voter_code'] = voter.voter_id
            
            log_action('Voter Login', 'voter', voter.id, f'Voter {voter_id} logged in')
            flash(f'Welcome, {voter.full_name}!', 'success')
            return redirect(url_for('voter_dashboard'))
        else:
            flash('Invalid Voter ID or Password', 'error')
    
    return render_template('voter_login.html')

@app.route('/voter/dashboard')
@voter_required
def voter_dashboard():
    voter = Voter.query.get(session['voter_id'])
    
    all_elections = Election.query.order_by(Election.created_at.desc()).all()
    
    elections_with_candidates = []
    for election in all_elections:
        candidates = Candidate.query.filter_by(election_id=election.id).all()
        elections_with_candidates.append({
            'election': election,
            'candidates': candidates
        })
    
    voted_election_ids = [v.election_id for v in Vote.query.filter_by(voter_id=voter.id).all()]
    
    notifications = Notification.query.filter_by(is_active=True).order_by(Notification.created_at.desc()).limit(5).all()
    
    return render_template('voter_dashboard.html',
                         voter=voter,
                         elections_with_candidates=elections_with_candidates,
                         voted_election_ids=voted_election_ids,
                         notifications=notifications)

@app.route('/voter/vote-history')
@voter_required
def voter_vote_history():
    voter = Voter.query.get(session['voter_id'])
    votes = Vote.query.filter_by(voter_id=voter.id).order_by(Vote.voted_at.desc()).all()
    
    vote_history = []
    for vote in votes:
        election = Election.query.get(vote.election_id)
        candidate = Candidate.query.get(vote.candidate_id)
        vote_history.append({
            'election': election,
            'candidate': candidate,
            'voted_at': vote.voted_at
        })
    
    return render_template('voter_vote_history.html', vote_history=vote_history, voter=voter)

@app.route('/voter/notifications')
@voter_required
def voter_notifications():
    voter = Voter.query.get(session['voter_id'])
    notifications = Notification.query.filter_by(is_active=True).order_by(Notification.created_at.desc()).all()
    return render_template('voter_notifications.html', notifications=notifications, voter=voter)

@app.route('/voter/election/<int:election_id>')
@voter_required
def voter_view_election(election_id):
    election = Election.query.get_or_404(election_id)
    candidates = Candidate.query.filter_by(election_id=election_id).all()
    
    existing_vote = Vote.query.filter_by(
        voter_id=session['voter_id'],
        election_id=election_id
    ).first()
    
    now = datetime.utcnow()
    is_active = is_election_active(election)
    
    return render_template('voter_view_election.html',
                         election=election,
                         candidates=candidates,
                         existing_vote=existing_vote,
                         is_active=is_active)

@app.route('/voter/vote/<int:election_id>/<int:candidate_id>', methods=['POST'])
@voter_required
def voter_cast_vote(election_id, candidate_id):
    election = Election.query.get_or_404(election_id)
    
    if not is_election_active(election):
        flash('This election is not currently active', 'error')
        return redirect(url_for('voter_dashboard'))
    
    existing_vote = Vote.query.filter_by(
        voter_id=session['voter_id'],
        election_id=election_id
    ).first()
    
    if existing_vote:
        flash('You have already voted in this election', 'error')
        return redirect(url_for('voter_dashboard'))
    
    vote = Vote(
        voter_id=session['voter_id'],
        election_id=election_id,
        candidate_id=candidate_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    
    candidate = Candidate.query.get(candidate_id)
    candidate.votes_count += 1
    
    db.session.add(vote)
    db.session.commit()
    
    log_action('Cast Vote', 'voter', session['voter_id'], 
              f'Voted in election {election_id}')
    
    flash('Your vote has been recorded successfully!', 'success')
    return redirect(url_for('voter_dashboard'))

@app.route('/voter/results/<int:election_id>')
@voter_required
def voter_view_results(election_id):
    election = Election.query.get_or_404(election_id)
    
    if not election.allow_results_view:
        flash('Results are not available for this election', 'error')
        return redirect(url_for('voter_dashboard'))
    
    candidates = Candidate.query.filter_by(election_id=election_id).order_by(Candidate.votes_count.desc()).all()
    total_votes = sum(c.votes_count for c in candidates)
    
    return render_template('voter_results.html',
                         election=election,
                         candidates=candidates,
                         total_votes=total_votes)

@app.route('/voter/change-password', methods=['GET', 'POST'])
@voter_required
def voter_change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        voter = Voter.query.get(session['voter_id'])
        
        if not check_password_hash(voter.password_hash, current_password):
            flash('Current password is incorrect', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'error')
        else:
            voter.password_hash = generate_password_hash(new_password)
            db.session.commit()
            
            log_action('Change Password', 'voter', voter.id, 'Password changed')
            flash('Password changed successfully!', 'success')
            return redirect(url_for('voter_dashboard'))
    
    return render_template('voter_change_password.html')

@app.route('/voter/logout')
def voter_logout():
    log_action('Voter Logout', 'voter', session.get('voter_id'), 
              f'Voter {session.get("voter_code")} logged out')
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/api/election/<int:election_id>/results')
def api_election_results(election_id):
    candidates = Candidate.query.filter_by(election_id=election_id).all()
    data = {
        'labels': [c.name for c in candidates],
        'data': [c.votes_count for c in candidates],
        'colors': ['#3B82F6', '#EF4444', '#10B981', '#F59E0B', '#8B5CF6', '#EC4899', '#14B8A6']
    }
    return jsonify(data)

with app.app_context():
    db.create_all()
    
    if not Admin.query.filter_by(username='admin').first():
        admin = Admin(
            username='admin',
            email='admin@votehub.com',
            password_hash=generate_password_hash('Admin@2024')
        )
        db.session.add(admin)
        db.session.commit()
        print('Default admin created - Username: admin, Password: Admin@2024')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
