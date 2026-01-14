"""
Zearom QA Management System
A comprehensive Flask application for managing QA projects, testing sessions, and findings.

Installation:
pip install flask flask-sqlalchemy flask-login authlib werkzeug pillow

Run:
python app.py
"""

import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
import secrets

# Get the absolute path of the directory containing this script
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "zearom_qa.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Google OAuth Config
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', 'your-google-client-id')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', 'your-google-client-secret')

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
oauth = OAuth(app)

# Configure Google OAuth
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200))
    name = db.Column(db.String(100))
    is_google_user = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    projects = db.relationship('Project', backref='creator', lazy=True)
    categories = db.relationship('Category', backref='creator', lazy=True)
    findings = db.relationship('Finding', backref='creator', lazy=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    sessions = db.relationship('TestingSession', backref='project', lazy=True, cascade='all, delete-orphan')
    categories = db.relationship('Category', backref='project', lazy=True, cascade='all, delete-orphan')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    color = db.Column(db.String(7), default='#3B82F6')  # Hex color
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    findings = db.relationship('Finding', backref='category', lazy=True)

class TestingSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='Active')  # Active, Completed, Archived
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    findings = db.relationship('Finding', backref='session', lazy=True, cascade='all, delete-orphan')

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(50), default='Medium')  # Critical, High, Medium, Low
    status = db.Column(db.String(50), default='Open')  # Open, In Progress, Resolved, Closed
    session_id = db.Column(db.Integer, db.ForeignKey('testing_session.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    screenshots = db.relationship('Screenshot', backref='finding', lazy=True, cascade='all, delete-orphan')

class Screenshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    filepath = db.Column(db.String(300), nullable=False)
    finding_id = db.Column(db.Integer, db.ForeignKey('finding.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        user = User.query.filter(db.func.lower(User.email) == email).first()

        if user and check_password_hash(user.password, password):
            if not user.is_active:
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
            else:
                login_user(user)
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')

        if user_info:
            user = User.query.filter(db.func.lower(User.email) == user_info['email'].lower()).first()

            if not user:
                flash('Your account is not registered. Please contact an administrator.', 'error')
                return redirect(url_for('login'))

            if not user.is_active:
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
                return redirect(url_for('login'))

            if not user.is_google_user:
                user.is_google_user = True
                user.name = user_info.get('name')
                db.session.commit()

            login_user(user)
            return redirect(url_for('dashboard'))
    except Exception as e:
        flash('Google login failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    projects = Project.query.order_by(Project.updated_at.desc()).all()
    recent_findings = Finding.query.order_by(Finding.created_at.desc()).limit(10).all()

    stats = {
        'total_projects': Project.query.count(),
        'total_sessions': TestingSession.query.count(),
        'total_findings': Finding.query.count(),
        'open_findings': Finding.query.filter_by(status='Open').count()
    }

    return render_template('dashboard.html', projects=projects, recent_findings=recent_findings, stats=stats)

@app.route('/projects')
@login_required
def projects():
    all_projects = Project.query.order_by(Project.updated_at.desc()).all()
    return render_template('projects.html', projects=all_projects)

@app.route('/project/new', methods=['GET', 'POST'])
@login_required
def new_project():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')

        project = Project(name=name, description=description, created_by=current_user.id)
        db.session.add(project)
        db.session.commit()

        flash('Project created successfully!', 'success')
        return redirect(url_for('project_detail', project_id=project.id))

    return render_template('project_form.html')

@app.route('/project/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)

    # Pagination for sessions
    page = request.args.get('page', 1, type=int)
    per_page = 10
    sessions_pagination = TestingSession.query.filter_by(project_id=project_id)\
        .order_by(TestingSession.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)

    categories = Category.query.filter_by(project_id=project_id).all()
    return render_template('project_detail.html',
                         project=project,
                         sessions_pagination=sessions_pagination,
                         categories=categories)

@app.route('/project/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)

    if request.method == 'POST':
        project.name = request.form.get('name')
        project.description = request.form.get('description')
        project.updated_at = datetime.utcnow()
        db.session.commit()

        flash('Project updated successfully!', 'success')
        return redirect(url_for('project_detail', project_id=project.id))

    return render_template('project_form.html', project=project)

@app.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted successfully!', 'success')
    return redirect(url_for('projects'))

@app.route('/project/<int:project_id>/category/new', methods=['GET', 'POST'])
@login_required
def new_category(project_id):
    project = Project.query.get_or_404(project_id)

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        color = request.form.get('color', '#3B82F6')

        category = Category(
            name=name,
            description=description,
            color=color,
            project_id=project_id,
            created_by=current_user.id
        )
        db.session.add(category)
        db.session.commit()

        flash('Category created successfully!', 'success')
        return redirect(url_for('project_detail', project_id=project_id))

    return render_template('category_form.html', project=project)

@app.route('/session/new/<int:project_id>', methods=['GET', 'POST'])
@login_required
def new_session(project_id):
    project = Project.query.get_or_404(project_id)

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')

        testing_session = TestingSession(
            name=name,
            description=description,
            project_id=project_id
        )
        db.session.add(testing_session)
        db.session.commit()

        flash('Testing session created successfully!', 'success')
        return redirect(url_for('session_detail', session_id=testing_session.id))

    return render_template('session_form.html', project=project, testing_session=None)


@app.route('/session/<int:session_id>')
@login_required
def session_detail(session_id):
    testing_session = TestingSession.query.get_or_404(session_id)
    categories = Category.query.filter_by(project_id=testing_session.project_id).all()

    # Pagination for findings
    page = request.args.get('page', 1, type=int)
    per_page = 10
    findings_pagination = Finding.query.filter_by(session_id=session_id) \
        .order_by(Finding.created_at.desc()) \
        .paginate(page=page, per_page=per_page, error_out=False)

    # Get all findings for stats (not paginated)
    all_findings = Finding.query.filter_by(session_id=session_id).all()

    return render_template('session_detail.html',
                           testing_session=testing_session,
                           findings_pagination=findings_pagination,
                           all_findings=all_findings,
                           categories=categories)


@app.route('/finding/<int:finding_id>/update-status', methods=['POST'])
@login_required
def update_finding_status(finding_id):
    finding = Finding.query.get_or_404(finding_id)
    new_status = request.form.get('status')

    if new_status in ['Open', 'In Progress', 'Resolved', 'Closed']:
        finding.status = new_status
        finding.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'message': f'Status updated to {new_status}'})

    return jsonify({'success': False, 'message': 'Invalid status'}), 400

@app.route('/session/<int:session_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_session(session_id):
    testing_session = TestingSession.query.get_or_404(session_id)

    if request.method == 'POST':
        testing_session.name = request.form.get('name')
        testing_session.description = request.form.get('description')
        testing_session.status = request.form.get('status')
        testing_session.updated_at = datetime.utcnow()
        db.session.commit()

        flash('Session updated successfully!', 'success')
        return redirect(url_for('session_detail', session_id=session_id))

    return render_template('session_form.html', testing_session=testing_session, project=testing_session.project)

@app.route('/session/<int:session_id>/update-status', methods=['POST'])
@login_required
def update_session_status(session_id):
    testing_session = TestingSession.query.get_or_404(session_id)
    new_status = request.form.get('status')

    if new_status in ['Active', 'Completed', 'Archived']:
        testing_session.status = new_status
        testing_session.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'message': f'Status updated to {new_status}'})

    return jsonify({'success': False, 'message': 'Invalid status'}), 400

@app.route('/finding/new/<int:session_id>', methods=['GET', 'POST'])
@login_required
def new_finding(session_id):
    testing_session = TestingSession.query.get_or_404(session_id)
    categories = Category.query.filter_by(project_id=testing_session.project_id).all()

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        severity = request.form.get('severity')
        category_id = request.form.get('category_id')

        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            category_id=category_id if category_id else None,
            session_id=session_id,
            created_by=current_user.id
        )
        db.session.add(finding)
        db.session.commit()

        # Handle file uploads
        if 'screenshots' in request.files:
            files = request.files.getlist('screenshots')
            for file in files:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{timestamp}_{filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)

                    screenshot = Screenshot(
                        filename=filename,
                        filepath=filepath,
                        finding_id=finding.id
                    )
                    db.session.add(screenshot)

            db.session.commit()

        flash('Finding created successfully!', 'success')
        return redirect(url_for('session_detail', session_id=session_id))

    return render_template('finding_form.html', testing_session=testing_session, categories=categories)

@app.route('/finding/<int:finding_id>')
@login_required
def finding_detail(finding_id):
    finding = Finding.query.get_or_404(finding_id)
    return render_template('finding_detail.html', finding=finding)

@app.route('/finding/<int:finding_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_finding(finding_id):
    finding = Finding.query.get_or_404(finding_id)
    categories = Category.query.filter_by(project_id=finding.session.project_id).all()

    if request.method == 'POST':
        finding.title = request.form.get('title')
        finding.description = request.form.get('description')
        finding.severity = request.form.get('severity')
        finding.status = request.form.get('status')
        category_id = request.form.get('category_id')
        finding.category_id = category_id if category_id else None
        finding.updated_at = datetime.utcnow()

        # Handle screenshot deletions
        screenshots_to_keep = request.form.getlist('keep_screenshots')
        for screenshot in finding.screenshots:
            if str(screenshot.id) not in screenshots_to_keep:
                # Delete file from filesystem
                try:
                    if os.path.exists(screenshot.filepath):
                        os.remove(screenshot.filepath)
                except:
                    pass
                db.session.delete(screenshot)

        # Handle new file uploads
        if 'screenshots' in request.files:
            files = request.files.getlist('screenshots')
            for file in files:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{timestamp}_{filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)

                    screenshot = Screenshot(
                        filename=filename,
                        filepath=filepath,
                        finding_id=finding.id
                    )
                    db.session.add(screenshot)

        db.session.commit()
        flash('Finding updated successfully!', 'success')
        return redirect(url_for('finding_detail', finding_id=finding_id))

    return render_template('finding_form.html', finding=finding, categories=categories, testing_session=finding.session)

@app.route('/finding/<int:finding_id>/delete', methods=['POST'])
@login_required
def delete_finding(finding_id):
    finding = Finding.query.get_or_404(finding_id)
    session_id = finding.session_id
    db.session.delete(finding)
    db.session.commit()
    flash('Finding deleted successfully!', 'success')
    return redirect(url_for('session_detail', session_id=session_id))

@app.route('/screenshot/<int:screenshot_id>/delete', methods=['POST'])
@login_required
def delete_screenshot(screenshot_id):
    screenshot = Screenshot.query.get_or_404(screenshot_id)
    finding_id = screenshot.finding_id

    # Delete the file from filesystem
    try:
        if os.path.exists(screenshot.filepath):
            os.remove(screenshot.filepath)
    except:
        pass

    db.session.delete(screenshot)
    db.session.commit()
    flash('Screenshot deleted successfully!', 'success')
    return redirect(url_for('edit_finding', finding_id=finding_id))

@app.route('/category/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)

    if request.method == 'POST':
        category.name = request.form.get('name')
        category.description = request.form.get('description')
        category.color = request.form.get('color', '#3B82F6')
        db.session.commit()

        flash('Category updated successfully!', 'success')
        return redirect(url_for('project_detail', project_id=category.project_id))

    return render_template('category_form.html', category=category, project=category.project)

@app.route('/category/<int:category_id>/delete', methods=['POST'])
@login_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    project_id = category.project_id
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully!', 'success')
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/users')
@login_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=all_users)


@app.route('/user/<int:user_id>/toggle-active', methods=['POST'])
@login_required
def toggle_user_active(user_id):
    user = User.query.get_or_404(user_id)

    # Prevent deactivating yourself
    if user.id == current_user.id:
        flash('You cannot deactivate your own account!', 'error')
        return redirect(url_for('users'))

    # Prevent deactivating the system admin
    if user.email.lower() == 'admin@zearom.com':
        flash('The system administrator account cannot be deactivated!', 'error')
        return redirect(url_for('users'))

    user.is_active = not user.is_active
    db.session.commit()

    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.email} has been {status}!', 'success')
    return redirect(url_for('users'))

@app.route('/user/new', methods=['GET', 'POST'])
@login_required
def new_user():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        name = request.form.get('name')
        password = request.form.get('password')

        existing_user = User.query.filter(db.func.lower(User.email) == email).first()
        if existing_user:
            flash('A user with this email already exists!', 'error')
            return render_template('user_form.html')

        user = User(
            email=email,
            name=name,
            password=generate_password_hash(password) if password else None,
            is_google_user=not password,
            is_active=True
        )
        db.session.add(user)
        db.session.commit()

        flash('User created successfully!', 'success')
        return redirect(url_for('users'))

    return render_template('user_form.html')

#initialize the database
def init_db():
    with app.app_context():
        db.create_all()

        admin = User.query.filter_by(email='Admin@Zearom.com').first()
        if not admin:
            admin = User(
                email='Admin@Zearom.com',
                password=generate_password_hash('Success@Zearom'),
                name='Admin',
                is_google_user=False
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created: Admin@Zearom.com / Success@Zearom")
            print(f"Database location: {os.path.join(BASE_DIR, 'zearom_qa.db')}")
            print(f"Upload folder: {app.config['UPLOAD_FOLDER']}")

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)