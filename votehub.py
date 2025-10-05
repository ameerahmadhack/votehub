from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import json
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///votes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    photo_url = db.Column(db.String(500))
    party_logo = db.Column(db.String(500))
    party_name = db.Column(db.String(100))
    description = db.Column(db.Text)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    votes_count = db.Column(db.Integer, default=0)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    voted_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin access required')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    polls = Poll.query.filter(Poll.end_time > datetime.utcnow()).all()
    return render_template('index.html', polls=polls)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(
            email=email,
            phone=phone,
            password_hash=generate_password_hash(password),
            verification_code=secrets.randbelow(1000000)
        )
        db.session.add(user)
        db.session.commit()
        
        session['temp_user_id'] = user.id
        flash(f'Verification code: {user.verification_code}')  # In real app, send via email/SMS
        return redirect(url_for('verify'))
    
    return render_template('register.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        code = request.form.get('code')
        user = User.query.get(session.get('temp_user_id'))
        
        if user and user.verification_code == code:
            user.is_verified = True
            db.session.commit()
            session['user_id'] = user.id
            session.pop('temp_user_id', None)
            flash('Account verified successfully!')
            return redirect(url_for('index'))
        else:
            flash('Invalid verification code')
    
    return render_template('verify.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            if user.is_verified:
                session['user_id'] = user.id
                flash('Logged in successfully!')
                return redirect(url_for('index'))
            else:
                flash('Please verify your account first')
                return redirect(url_for('verify'))
        else:
            flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully')
    return redirect(url_for('index'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    polls = Poll.query.all()
    total_votes = Vote.query.count()
    return render_template('admin_dashboard.html', polls=polls, total_votes=total_votes)

@app.route('/admin/create-poll', methods=['GET', 'POST'])
@admin_required
def create_poll():
    if request.method == 'POST':
        poll = Poll(
            title=request.form.get('title'),
            description=request.form.get('description'),
            start_time=datetime.strptime(request.form.get('start_time'), '%Y-%m-%dT%H:%M'),
            end_time=datetime.strptime(request.form.get('end_time'), '%Y-%m-%dT%H:%M'),
            created_by=session['user_id']
        )
        db.session.add(poll)
        db.session.commit()
        
        # Add candidates
        candidates = request.form.getlist('candidate_name[]')
        for i, name in enumerate(candidates):
            candidate = Candidate(
                name=name,
                party_name=request.form.getlist('candidate_party[]')[i],
                description=request.form.getlist('candidate_description[]')[i],
                poll_id=poll.id
            )
            db.session.add(candidate)
        
        db.session.commit()
        flash('Poll created successfully!')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('create_poll.html')

@app.route('/poll/<int:poll_id>')
@login_required
def view_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    candidates = Candidate.query.filter_by(poll_id=poll_id).all()
    user_vote = Vote.query.filter_by(user_id=session['user_id'], poll_id=poll_id).first()
    
    return render_template('view_poll.html', poll=poll, candidates=candidates, user_vote=user_vote)

@app.route('/vote/<int:poll_id>/<int:candidate_id>')
@login_required
def vote(poll_id, candidate_id):
    # Check if user already voted
    existing_vote = Vote.query.filter_by(user_id=session['user_id'], poll_id=poll_id).first()
    if existing_vote:
        flash('You have already voted in this poll!')
        return redirect(url_for('view_poll', poll_id=poll_id))
    
    # Check if poll is active
    poll = Poll.query.get(poll_id)
    if not poll or poll.end_time < datetime.utcnow():
        flash('This poll is no longer active!')
        return redirect(url_for('index'))
    
    # Record vote
    vote = Vote(
        user_id=session['user_id'],
        poll_id=poll_id,
        candidate_id=candidate_id,
        ip_address=request.remote_addr
    )
    
    # Update candidate vote count
    candidate = Candidate.query.get(candidate_id)
    candidate.votes_count += 1
    
    db.session.add(vote)
    db.session.commit()
    
    flash('Your vote has been recorded successfully! 🎉')
    return redirect(url_for('view_poll', poll_id=poll_id))

@app.route('/results/<int:poll_id>')
def results(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    candidates = Candidate.query.filter_by(poll_id=poll_id).order_by(Candidate.votes_count.desc()).all()
    total_votes = sum(candidate.votes_count for candidate in candidates)
    
    return render_template('results.html', poll=poll, candidates=candidates, total_votes=total_votes)

@app.route('/api/results/<int:poll_id>')
def api_results(poll_id):
    candidates = Candidate.query.filter_by(poll_id=poll_id).all()
    data = {
        'labels': [candidate.name for candidate in candidates],
        'data': [candidate.votes_count for candidate in candidates],
        'colors': ['#3B82F6', '#EF4444', '#10B981', '#F59E0B', '#8B5CF6']
    }
    return jsonify(data)

# Template rendering functions
@app.context_processor
def utility_processor():
    def is_poll_active(poll):
        return poll.start_time <= datetime.utcnow() <= poll.end_time
    return dict(is_poll_active=is_poll_active, now=datetime.utcnow())

# HTML Templates as string (for single file deployment)
app.jinja_env.globals.update(render_template_string=render_template)

# Create database tables
with app.app_context():
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(is_admin=True).first():
        admin = User(
            email='admin@votehub.com',
            password_hash=generate_password_hash('admin123'),
            is_admin=True,
            is_verified=True
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
